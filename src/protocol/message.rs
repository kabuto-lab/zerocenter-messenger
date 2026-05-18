use libp2p::identity::Keypair;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;

/// Domain-separator tag for direct-message signatures. Prevents a signature
/// produced under a different protocol (or a future revision of this one)
/// from being accepted here.
///
/// Kept at `v1` even though the wire payload changed from plaintext to a
/// serialized [`EncryptedPayload`] in Phase 3 — the *signed-bytes layout*
/// did not change (still to+from+payload+timestamp+ttl+msg_type). Bump
/// only if that layout changes.
const DOMAIN_SEPARATOR: &[u8] = b"zerocenter-dm-v1";

/// Phase 5 sealed-sender signature domain separator. Distinct from
/// [`DOMAIN_SEPARATOR`] so a signature produced under the direct path
/// cannot be replayed under the sealed path or vice versa (INVARIANTS §1
/// hygiene).
const SEALED_DOMAIN_SEPARATOR: &[u8] = b"zerocenter-sealed-dm-v1";

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

    /// Sealed envelope was passed to [`ProtocolMessage::verify`] which
    /// expects the legacy direct path. Caller should route to
    /// [`ProtocolMessage::verify_sealed`] instead.
    #[error("envelope is sealed; call verify_sealed with the recipient's X25519 priv")]
    EnvelopeIsSealed,

    #[error("envelope has no sealed_sender field (direct path)")]
    EnvelopeNotSealed,

    #[error("failed to decrypt sealed envelope: {0}")]
    SealDecryptFailed(String),

    #[error("sealed sender cert is malformed: {0}")]
    MalformedSealedCert(String),
}

/// Protocol message envelope. Supports two authentication paths:
///
/// **Direct path (legacy).** `from` + `signature` carry a clear sender
/// PeerId and an Ed25519 signature over the canonical signing bytes
/// (`zerocenter-dm-v1` || to || from || payload || ts || ttl || msg_type).
/// The transport-layer source PeerId is cross-checked against `from`
/// (INVARIANTS §2). Used when the sender does NOT yet have the
/// recipient's X25519 prekey (e.g. very first contact before
/// `cached_prekey` is populated).
///
/// **Sealed path (Phase 5).** `sealed_sender` carries an ECIES-style
/// ciphertext encrypted to the recipient's long-term X25519 prekey
/// containing `(sender_pid_bytes || signature_bytes)`. The signature
/// uses a DISTINCT domain separator (`zerocenter-sealed-dm-v1`) so a
/// captured direct signature can't be replayed under sealed semantics.
/// `from` and `signature` are empty on the wire. The §2 transport-peer
/// cross-check is intentionally skipped — the entire point of sealed
/// sender is to make the transport peer orthogonal to the actual
/// sender identity.
///
/// Recipients MUST call [`Self::verify`] (direct) or
/// [`Self::verify_sealed`] (sealed) before trusting any field. The
/// caller inspects [`Self::is_sealed`] to pick the right path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Recipient identifier (PeerId bytes). Always clear — needed for
    /// libp2p routing and (for DHT-mailbox) `slot_kad_key` derivation.
    pub to: Vec<u8>,

    /// Sender identifier (PeerId bytes) — direct path only. Empty for
    /// sealed-path envelopes (the sender PeerId is inside
    /// `sealed_sender`).
    #[serde(default)]
    pub from: Vec<u8>,

    /// Phase 5 sealed-path field — ECIES-encrypted
    /// `(sender_pid || signature)`. Empty for direct-path envelopes.
    /// See [`crate::crypto::sealed`] for the wire layout.
    #[serde(default)]
    pub sealed_sender: Vec<u8>,

    /// Payload. Plaintext for now — Phase 3 will replace this with a
    /// Double-Ratchet ciphertext.
    pub payload: Vec<u8>,

    /// Unix timestamp (seconds).
    pub timestamp: i64,

    /// Time to live in seconds.
    pub ttl: i64,

    /// Message type.
    pub msg_type: MessageType,

    /// Ed25519 signature over the canonical signing bytes — direct
    /// path only. Empty for sealed-path envelopes (the inner signature
    /// is inside `sealed_sender`).
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
    /// Build and sign a new direct (legacy) message.
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
            sealed_sender: Vec::new(),
            payload,
            timestamp: current_timestamp(),
            ttl: 7 * 24 * 60 * 60, // 7 days
            msg_type: MessageType::Direct,
            signature: Vec::new(),
        };

        let signing_bytes = msg.direct_signing_bytes();
        // libp2p's Keypair::sign returns an Err only for RSA without a private
        // key; for Ed25519 it is infallible in practice, but we still surface
        // the error rather than unwrapping.
        let sig = keypair
            .sign(&signing_bytes)
            .map_err(|e| ProtocolError::InvalidSender(e.to_string()))?;
        msg.signature = sig;
        Ok(msg)
    }

    /// Build a Phase 5 sealed envelope. `sender_pid` and `keypair` go
    /// INSIDE the seal; only the recipient (who holds the private of
    /// `recipient_x25519_pub`) can recover them. The outer envelope on
    /// the wire reveals only `to` (needed for routing) and the encrypted
    /// payload. Returns an envelope with empty `from` and `signature`
    /// fields — the actual signature is inside `sealed_sender`.
    pub fn new_sealed(
        to: Vec<u8>,
        sender_pid: Vec<u8>,
        payload: Vec<u8>,
        keypair: &Keypair,
        recipient_x25519_pub: &[u8; 32],
    ) -> Result<Self, ProtocolError> {
        let mut msg = Self {
            to,
            from: Vec::new(),
            sealed_sender: Vec::new(),
            payload,
            timestamp: current_timestamp(),
            ttl: 7 * 24 * 60 * 60,
            msg_type: MessageType::Direct,
            signature: Vec::new(),
        };

        // Sign with the sealed-path domain separator. Scope includes
        // sender_pid, to, payload, ts, ttl, msg_type so a captured
        // signature can't be transplanted onto a different envelope.
        let inner_signing_bytes = msg.sealed_signing_bytes(&sender_pid);
        let sig = keypair
            .sign(&inner_signing_bytes)
            .map_err(|e| ProtocolError::InvalidSender(e.to_string()))?;

        // sender_cert layout (inside the seal): length-prefixed
        // `sender_pid || signature`. Mirror the same length-prefix
        // convention used by `direct_signing_bytes` for uniformity.
        let mut cert = Vec::with_capacity(8 + sender_pid.len() + sig.len());
        push_bytes(&mut cert, &sender_pid);
        push_bytes(&mut cert, &sig);

        let sealed = crate::crypto::sealed::seal_sender_cert(recipient_x25519_pub, &cert)
            .map_err(|e| ProtocolError::SealDecryptFailed(format!("seal failed: {}", e)))?;
        msg.sealed_sender = sealed;
        Ok(msg)
    }

    /// Returns true iff this envelope uses the Phase 5 sealed path
    /// (i.e. has a non-empty `sealed_sender` field).
    pub fn is_sealed(&self) -> bool {
        !self.sealed_sender.is_empty()
    }

    /// Direct-path verification. Returns the parsed sender PeerId on
    /// success. Caller MUST call [`Self::is_sealed`] first and route
    /// sealed envelopes to [`Self::verify_sealed`] instead.
    pub fn verify(&self) -> Result<PeerId, ProtocolError> {
        if self.is_sealed() {
            return Err(ProtocolError::EnvelopeIsSealed);
        }
        if self.signature.is_empty() {
            return Err(ProtocolError::MissingSignature);
        }

        let peer_id = PeerId::from_bytes(&self.from)
            .map_err(|e| ProtocolError::InvalidSender(e.to_string()))?;
        let public_key = extract_inline_pubkey(&peer_id)?;

        if public_key.verify(&self.direct_signing_bytes(), &self.signature) {
            Ok(peer_id)
        } else {
            Err(ProtocolError::BadSignature)
        }
    }

    /// Phase 5 sealed-path verification. Decrypts `sealed_sender` with
    /// the recipient's X25519 prekey private, recovers
    /// `(sender_pid || signature)`, and verifies the signature against
    /// the sender PeerId's embedded Ed25519 pubkey. Returns the
    /// recovered sender PeerId on success.
    pub fn verify_sealed(
        &self,
        recipient_x25519_priv: &StaticSecret,
    ) -> Result<PeerId, ProtocolError> {
        if !self.is_sealed() {
            return Err(ProtocolError::EnvelopeNotSealed);
        }
        let cert_bytes =
            crate::crypto::sealed::unseal_sender_cert(recipient_x25519_priv, &self.sealed_sender)
                .map_err(|e| ProtocolError::SealDecryptFailed(e.to_string()))?;

        let mut cur = &cert_bytes[..];
        let sender_pid_bytes = pop_bytes(&mut cur)
            .map_err(|e| ProtocolError::MalformedSealedCert(format!("sender_pid: {}", e)))?;
        let sig_bytes = pop_bytes(&mut cur)
            .map_err(|e| ProtocolError::MalformedSealedCert(format!("signature: {}", e)))?;
        if !cur.is_empty() {
            return Err(ProtocolError::MalformedSealedCert(format!(
                "trailing {} bytes in sealed cert",
                cur.len()
            )));
        }

        let peer_id = PeerId::from_bytes(&sender_pid_bytes)
            .map_err(|e| ProtocolError::InvalidSender(e.to_string()))?;
        let public_key = extract_inline_pubkey(&peer_id)?;

        let signing_bytes = self.sealed_signing_bytes(&sender_pid_bytes);
        if public_key.verify(&signing_bytes, &sig_bytes) {
            Ok(peer_id)
        } else {
            Err(ProtocolError::BadSignature)
        }
    }

    /// Canonical signing bytes for the direct path.
    /// Domain `"zerocenter-dm-v1"`. Layout has not changed since Phase 1.
    fn direct_signing_bytes(&self) -> Vec<u8> {
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

    /// Phase 5 canonical signing bytes for the sealed path. Distinct
    /// domain separator (`"zerocenter-sealed-dm-v1"`) keeps the signed-
    /// bytes namespace disjoint from the direct path so neither
    /// signature can be transplanted into the other context.
    /// `sender_pid` is passed in because the envelope's own `from`
    /// field is empty on the sealed path — the PeerId lives inside
    /// `sealed_sender` and only appears at verify time.
    fn sealed_signing_bytes(&self, sender_pid: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            SEALED_DOMAIN_SEPARATOR.len()
                + self.to.len()
                + sender_pid.len()
                + self.payload.len()
                + 32,
        );
        out.extend_from_slice(SEALED_DOMAIN_SEPARATOR);
        push_bytes(&mut out, &self.to);
        push_bytes(&mut out, sender_pid);
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

/// Inverse of `push_bytes`. Reads a u32-be length prefix from `cur`,
/// then `len` payload bytes, advancing `cur`. Returns the payload bytes.
fn pop_bytes(cur: &mut &[u8]) -> Result<Vec<u8>, String> {
    if cur.len() < 4 {
        return Err(format!("need 4 length-prefix bytes, have {}", cur.len()));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&cur[..4]);
    let len = u32::from_be_bytes(len_bytes) as usize;
    let rest = &cur[4..];
    if rest.len() < len {
        return Err(format!("need {} payload bytes, have {}", len, rest.len()));
    }
    let payload = rest[..len].to_vec();
    *cur = &rest[len..];
    Ok(payload)
}

/// Extract a libp2p `PublicKey` from an inlined-pubkey PeerId.
/// Returns `NoInlinePublicKey` for hash-coded PeerIds (multihash code
/// != 0), which require an out-of-band pubkey lookup we don't yet do.
fn extract_inline_pubkey(peer_id: &PeerId) -> Result<libp2p::identity::PublicKey, ProtocolError> {
    let multihash = peer_id.as_ref();
    if multihash.code() != 0 {
        return Err(ProtocolError::NoInlinePublicKey);
    }
    libp2p::identity::PublicKey::try_decode_protobuf(multihash.digest())
        .map_err(|e| ProtocolError::InvalidSender(e.to_string()))
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
        let msg = ProtocolMessage {
            to: vec![],
            from: vec![],
            sealed_sender: vec![],
            payload: vec![],
            timestamp: 0,
            ttl: 0,
            msg_type: MessageType::Direct,
            signature: Vec::new(),
        };
        assert!(matches!(msg.verify(), Err(ProtocolError::MissingSignature)));
    }

    // -------- Phase 5 sealed-sender tests --------

    fn random_x25519_keypair() -> (StaticSecret, [u8; 32]) {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let priv_k = StaticSecret::from(bytes);
        let pub_k = x25519_dalek::PublicKey::from(&priv_k);
        (priv_k, *pub_k.as_bytes())
    }

    #[test]
    fn sealed_envelope_roundtrips_through_recipient() {
        let alice = Keypair::generate_ed25519();
        let alice_pid = PeerId::from(alice.public()).to_bytes();
        let bob_pid = vec![0xBBu8; 32];

        let (bob_x25519_priv, bob_x25519_pub) = random_x25519_keypair();

        let msg = ProtocolMessage::new_sealed(
            bob_pid.clone(),
            alice_pid.clone(),
            b"sealed payload".to_vec(),
            &alice,
            &bob_x25519_pub,
        )
        .expect("seal");

        assert!(msg.is_sealed());
        assert!(msg.from.is_empty());
        assert!(msg.signature.is_empty());
        assert!(!msg.sealed_sender.is_empty());
        assert_eq!(msg.to, bob_pid);

        // Bob unseals and recovers Alice as the verified sender.
        let verified = msg.verify_sealed(&bob_x25519_priv).expect("unseal");
        assert_eq!(verified.to_bytes(), alice_pid);

        // verify() on a sealed envelope must return EnvelopeIsSealed.
        assert!(matches!(msg.verify(), Err(ProtocolError::EnvelopeIsSealed)));
    }

    #[test]
    fn sealed_envelope_rejected_by_wrong_recipient() {
        let alice = Keypair::generate_ed25519();
        let alice_pid = PeerId::from(alice.public()).to_bytes();

        let (_real_priv, real_pub) = random_x25519_keypair();
        let (other_priv, _) = random_x25519_keypair();

        let msg = ProtocolMessage::new_sealed(
            b"bob".to_vec(),
            alice_pid,
            b"payload".to_vec(),
            &alice,
            &real_pub,
        )
        .expect("seal");

        // A different recipient's private cannot AEAD-decrypt the seal.
        let result = msg.verify_sealed(&other_priv);
        assert!(matches!(
            result,
            Err(ProtocolError::SealDecryptFailed(_))
        ));
    }

    #[test]
    fn sealed_envelope_tampered_payload_fails_signature() {
        // Even with the right recipient key, mutating the payload
        // after sealing breaks the inner Ed25519 signature scope.
        let alice = Keypair::generate_ed25519();
        let alice_pid = PeerId::from(alice.public()).to_bytes();
        let (bob_priv, bob_pub) = random_x25519_keypair();

        let mut msg = ProtocolMessage::new_sealed(
            b"bob".to_vec(),
            alice_pid,
            b"original".to_vec(),
            &alice,
            &bob_pub,
        )
        .expect("seal");

        msg.payload = b"tampered".to_vec();
        let result = msg.verify_sealed(&bob_priv);
        assert!(matches!(result, Err(ProtocolError::BadSignature)));
    }

    #[test]
    fn sealed_signature_uses_distinct_domain() {
        // A direct-path signature must NOT verify when interpreted as a
        // sealed-path signature, and vice versa. The domain separators
        // are different (`zerocenter-dm-v1` vs `zerocenter-sealed-dm-v1`)
        // so this is true by construction; the test pins it down.
        let alice = Keypair::generate_ed25519();
        let alice_pid = PeerId::from(alice.public()).to_bytes();

        // Build a direct-path message and a sealed message with the
        // SAME inner content (to, payload, ts, ttl, msg_type).
        // Force the timestamps to match so only the signing scope
        // differs.
        let to = b"bob".to_vec();
        let payload = b"hello".to_vec();

        let direct =
            ProtocolMessage::new_direct_signed(to.clone(), alice_pid.clone(), payload.clone(), &alice)
                .expect("sign");

        // Cross-construct: fake a "sealed" envelope whose inner
        // signature is actually the DIRECT signature. If the domain
        // separators were equal, this would verify.
        let (bob_priv, bob_pub) = random_x25519_keypair();
        let mut faked_cert = Vec::new();
        push_bytes(&mut faked_cert, &alice_pid);
        push_bytes(&mut faked_cert, &direct.signature);
        let sealed_bytes =
            crate::crypto::sealed::seal_sender_cert(&bob_pub, &faked_cert).expect("seal cert");

        let mut faked = direct.clone();
        faked.from = Vec::new();
        faked.signature = Vec::new();
        faked.sealed_sender = sealed_bytes;

        let result = faked.verify_sealed(&bob_priv);
        // The seal decrypts (recipient is right) but the inner
        // signature was produced under the direct-path domain
        // separator, so it fails against the sealed-path scope.
        assert!(matches!(result, Err(ProtocolError::BadSignature)));
    }

    #[test]
    fn verify_sealed_rejects_direct_envelope() {
        let alice = Keypair::generate_ed25519();
        let alice_pid = PeerId::from(alice.public()).to_bytes();
        let msg = ProtocolMessage::new_direct_signed(
            b"bob".to_vec(),
            alice_pid,
            b"payload".to_vec(),
            &alice,
        )
        .expect("sign");

        let (bob_priv, _) = random_x25519_keypair();
        assert!(matches!(
            msg.verify_sealed(&bob_priv),
            Err(ProtocolError::EnvelopeNotSealed)
        ));
    }
}
