use libp2p::identity::Keypair;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

/// Domain-separator tag for direct-message signatures. Prevents a signature
/// produced under a different protocol (or a future revision of this one)
/// from being accepted here.
///
/// Kept at `v1` even though the wire payload changed from plaintext to a
/// serialized [`EncryptedPayload`] in Phase 3 — the *signed-bytes layout*
/// did not change (still to+from+payload+timestamp+ttl+msg_type). Bump
/// only if that layout changes.
const DOMAIN_SEPARATOR: &[u8] = b"zerocenter-dm-v1";

/// Phase 3 wire-form payload: a Double-Ratchet ciphertext plus the per-
/// message header. The outer [`ProtocolMessage::payload`] field carries
/// this serialized as JSON.
///
/// `x3dh_eph` is present **only on the very first message** of a new
/// session — it's the initiator's ephemeral X25519 pubkey that the
/// responder needs to derive the same shared secret via X3DH-lite. After
/// the responder has been bootstrapped it is omitted (and ignored if seen).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedPayload {
    /// Sender's current DH ratchet pubkey.
    pub dh: [u8; 32],
    /// Length of the previous sending chain (`PN` in the Signal spec).
    pub pn: u32,
    /// Sequence number in the current sending chain.
    pub n: u32,
    /// AEAD ciphertext, includes the Poly1305 tag.
    pub ct: Vec<u8>,
    /// Initiator's X3DH ephemeral pubkey. Present only on the first
    /// message of a fresh session; `None` afterwards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x3dh_eph: Option<[u8; 32]>,

    /// Responder's OTPK id that the initiator consumed during X3DH.
    /// Present only on the first message AND only if the prekey-fetch
    /// response carried an OTPK bundle. Tells the responder which row
    /// in `my_otpks` to look up for the private bytes. `None` means
    /// the 2-DH variant of X3DH was used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otpk_id: Option<i64>,
}

impl EncryptedPayload {
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Protocol-level error surface. Kept tiny on purpose — higher layers map
/// these into `anyhow::Error`.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("message is missing a signature")]
    MissingSignature,

    #[error("sender field does not parse as a PeerId: {0}")]
    InvalidSender(String),

    #[error("sender PeerId does not embed an inlinable public key — cannot verify")]
    NoInlinePublicKey,

    #[error("signature verification failed")]
    BadSignature,
}

/// Protocol message envelope.
///
/// The envelope is *authenticated* at the application layer: the sender signs
/// the canonical bytes of (`to` + `from` + `payload` + `timestamp` + `ttl` +
/// `msg_type`) with their libp2p Ed25519 identity key. Recipients MUST verify
/// this signature (see [`Self::verify`]) before trusting any field.
///
/// Transport-level security (Noise) only protects each hop; the application
/// signature is what lets us tell a forged "from Alice" message from a real
/// one, and is the foundation we build E2EE on top of.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Recipient identifier (PeerId bytes).
    pub to: Vec<u8>,

    /// Sender identifier (PeerId bytes).
    pub from: Vec<u8>,

    /// Payload. Plaintext for now — Phase 3 will replace this with a
    /// Double-Ratchet ciphertext.
    pub payload: Vec<u8>,

    /// Unix timestamp (seconds).
    pub timestamp: i64,

    /// Time to live in seconds.
    pub ttl: i64,

    /// Message type.
    pub msg_type: MessageType,

    /// Ed25519 signature over the canonical signing bytes. Empty only during
    /// construction — never on the wire.
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// Type of message
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Direct message
    Direct = 0,

    /// Group message
    Group = 1,

    /// File transfer
    File = 2,

    /// Voice message
    Voice = 3,

    /// System/control message
    Control = 4,
}

impl ProtocolMessage {
    /// Build and sign a new direct message.
    ///
    /// The sender's libp2p [`Keypair`] must correspond to the `from` PeerId,
    /// otherwise recipients will reject the message at verification time.
    pub fn new_direct_signed(
        to: Vec<u8>,
        from: Vec<u8>,
        payload: Vec<u8>,
        keypair: &Keypair,
    ) -> Result<Self, ProtocolError> {
        let mut msg = Self {
            to,
            from,
            payload,
            timestamp: current_timestamp(),
            ttl: 7 * 24 * 60 * 60, // 7 days
            msg_type: MessageType::Direct,
            signature: Vec::new(),
        };

        let signing_bytes = msg.signing_bytes();
        // libp2p's Keypair::sign returns an Err only for RSA without a private
        // key; for Ed25519 it is infallible in practice, but we still surface
        // the error rather than unwrapping.
        let sig = keypair
            .sign(&signing_bytes)
            .map_err(|e| ProtocolError::InvalidSender(e.to_string()))?;
        msg.signature = sig;
        Ok(msg)
    }

    /// Verify the embedded signature against the public key extracted from
    /// the `from` PeerId. Returns the parsed sender PeerId on success.
    ///
    /// This works only if the sender's PeerId embeds its public key inline
    /// (multihash code = 0x00, "identity"). That is the default for Ed25519
    /// keys under 42 bytes — our case. For hashed PeerIds we'd need the
    /// public key out of band; we can extend this later.
    pub fn verify(&self) -> Result<PeerId, ProtocolError> {
        if self.signature.is_empty() {
            return Err(ProtocolError::MissingSignature);
        }

        let peer_id = PeerId::from_bytes(&self.from)
            .map_err(|e| ProtocolError::InvalidSender(e.to_string()))?;

        // PeerId derefs to a multihash; when the hash code is 0x00 ("identity")
        // the digest bytes are the protobuf-encoded public key itself.
        let multihash = peer_id.as_ref();
        if multihash.code() != 0 {
            return Err(ProtocolError::NoInlinePublicKey);
        }

        let public_key = libp2p::identity::PublicKey::try_decode_protobuf(multihash.digest())
            .map_err(|e| ProtocolError::InvalidSender(e.to_string()))?;

        if public_key.verify(&self.signing_bytes(), &self.signature) {
            Ok(peer_id)
        } else {
            Err(ProtocolError::BadSignature)
        }
    }

    /// Canonical bytes fed into the signature. Deliberately excludes the
    /// `signature` field itself.
    fn signing_bytes(&self) -> Vec<u8> {
        // Fixed-order, length-prefixed concatenation. Not using JSON here on
        // purpose: we want a stable, minimal byte layout that doesn't depend
        // on field ordering or JSON whitespace.
        //
        // The leading domain-separator tag binds this signature to *this*
        // protocol and version. Without it, a signature produced for some
        // future envelope with the same field layout could be replayed here
        // (cross-protocol signature reuse). Bump the suffix if the layout or
        // semantics ever change.
        let mut out = Vec::with_capacity(
            DOMAIN_SEPARATOR.len()
                + self.to.len()
                + self.from.len()
                + self.payload.len()
                + 32,
        );
        out.extend_from_slice(DOMAIN_SEPARATOR);
        push_bytes(&mut out, &self.to);
        push_bytes(&mut out, &self.from);
        push_bytes(&mut out, &self.payload);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out.push(self.msg_type as u8);
        out
    }

    /// Check if message is expired.
    pub fn is_expired(&self) -> bool {
        current_timestamp() > self.timestamp + self.ttl
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Length-prefix a byte slice (u32 big-endian length, then payload).
fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn sign_and_verify_roundtrip() {
        let alice = Keypair::generate_ed25519();
        let bob = Keypair::generate_ed25519();

        let alice_pid = PeerId::from(alice.public()).to_bytes();
        let bob_pid = PeerId::from(bob.public()).to_bytes();

        let msg = ProtocolMessage::new_direct_signed(
            bob_pid,
            alice_pid.clone(),
            b"hello bob".to_vec(),
            &alice,
        )
        .expect("sign");

        let verified_peer = msg.verify().expect("verify");
        assert_eq!(verified_peer.to_bytes(), alice_pid);
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let alice = Keypair::generate_ed25519();
        let alice_pid = PeerId::from(alice.public()).to_bytes();

        let mut msg = ProtocolMessage::new_direct_signed(
            vec![0u8; 16],
            alice_pid,
            b"original".to_vec(),
            &alice,
        )
        .expect("sign");

        msg.payload = b"tampered".to_vec();
        assert!(matches!(msg.verify(), Err(ProtocolError::BadSignature)));
    }

    #[test]
    fn forged_sender_fails_verification() {
        // Mallory signs a message but claims it's from Alice.
        let alice = Keypair::generate_ed25519();
        let mallory = Keypair::generate_ed25519();

        let alice_pid = PeerId::from(alice.public()).to_bytes();
        let msg = ProtocolMessage::new_direct_signed(
            vec![0u8; 16],
            alice_pid, // lie: claim to be Alice
            b"you owe me 100 dollars".to_vec(),
            &mallory, // but sign with Mallory's key
        )
        .expect("sign");

        // verify() extracts Alice's pubkey from `from` and tries to verify
        // against it — the signature was produced by Mallory, so it fails.
        assert!(matches!(msg.verify(), Err(ProtocolError::BadSignature)));
    }

    #[test]
    fn missing_signature_is_rejected() {
        let mut msg = ProtocolMessage {
            to: vec![],
            from: vec![],
            payload: vec![],
            timestamp: 0,
            ttl: 0,
            msg_type: MessageType::Direct,
            signature: Vec::new(),
        };
        msg.signature.clear();
        assert!(matches!(msg.verify(), Err(ProtocolError::MissingSignature)));
    }
}
