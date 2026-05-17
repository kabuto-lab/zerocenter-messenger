//! Double Ratchet — pure-function building blocks for forward-secret,
//! authenticated DM encryption.
//!
//! Implemented per the Signal spec:
//! https://signal.org/docs/specifications/doubleratchet/
//!
//! Scope of this module:
//! - [`RatchetState`] — the per-peer session state.
//! - [`RatchetState::encrypt`] / [`RatchetState::decrypt`] — the spec's
//!   `RatchetEncrypt` and `RatchetDecrypt` algorithms.
//! - JSON serialization for persistence.
//!
//! **Out of scope** (lives in node.rs once commit 4 wires it up):
//! - X3DH-lite handshake (see [`super::x3dh`]).
//! - First-message X3DH ephemeral plumbing.
//! - The application-layer Ed25519 signature on the outer envelope.
//!
//! Threat model assumptions:
//! - Each message key is used **exactly once**, so a zero nonce on the
//!   AEAD is safe (Signal makes the same choice).
//! - The associated data passed to `encrypt`/`decrypt` is the application-
//!   level AD (e.g. sender/recipient PeerId bytes). The header bytes are
//!   appended internally so a header swap fails AEAD verification.
//! - `MAX_SKIP = 1000` skipped message keys per session; older keys are
//!   evicted oldest-first to bound memory against a peer that withholds
//!   low-counter messages forever.

use chacha20poly1305::{
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
// `KeyInit` (re-exported from the `digest` crate via `hmac`) brings the
// `new_from_slice` constructor into scope. Without this import, calling
// `HmacSha256::new_from_slice(...)` does not resolve in some toolchain
// versions even though `Mac` is in scope, because `new_from_slice` lives
// on `KeyInit` — a supertrait, not the same trait.
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::VecDeque;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separator for the root-key KDF.
const RK_INFO: &[u8] = b"zerocenter-rk-v1";
/// Constant byte fed into KDF_CK to produce the next chain key.
const CK_CONST_CHAIN: u8 = 0x02;
/// Constant byte fed into KDF_CK to produce the message key.
const CK_CONST_MSG: u8 = 0x01;

/// Maximum number of skipped message keys retained per session.
/// Matches Signal's `MAX_SKIP`. Lower keeps memory bounded; higher
/// tolerates more out-of-order delivery.
pub const MAX_SKIP: usize = 1000;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum RatchetError {
    #[error("AEAD authentication failed (tamper or wrong key)")]
    BadAead,
    #[error("would exceed MAX_SKIP={MAX_SKIP} skipped keys in one step")]
    TooManySkipped,
    #[error("ratchet state is not yet initialized for receiving")]
    NotInitializedForRecv,
}

/// Per-message ratchet header. Travels in the clear alongside the
/// ciphertext but is bound into the AEAD's associated data so a swap
/// of header fields fails verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Sender's current DH ratchet pubkey.
    pub dh: [u8; 32],
    /// Number of messages in the previous sending chain (`PN` in the spec).
    pub pn: u32,
    /// Sequence number of this message in the current sending chain.
    pub n: u32,
}

impl Header {
    /// Canonical byte layout: 32 bytes dh || 4 bytes pn (BE) || 4 bytes n (BE).
    /// Fixed-width, no length prefix needed — every field is fixed size.
    pub fn to_aad_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..40].copy_from_slice(&self.n.to_be_bytes());
        out
    }
}

/// One produced ciphertext + its header. The caller is responsible for
/// transmitting both together; the AEAD tag is inside `ciphertext`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetMessage {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

/// A single skipped message key entry. Stored as `Vec` (not BTreeMap) so
/// it serializes cleanly to JSON; linear search through ≤1000 entries is
/// fast enough and only runs on the out-of-order path.
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
struct SkippedKey {
    /// The sender's DH ratchet pubkey at the time this key was derived.
    dh_pub: [u8; 32],
    /// The sequence number this key decrypts.
    n: u32,
    /// The 32-byte message key.
    mk: [u8; 32],
}

/// Per-peer session state. Holds all the secrets the Signal spec calls
/// out: `DHs`, `DHr`, `RK`, `CKs`, `CKr`, `Ns`, `Nr`, `PN`, `MKSKIPPED`.
///
/// Cloning is supported (needed for testing); in production you should
/// own exactly one copy per peer and persist it after every send / receive.
///
/// Intentionally NOT `Debug`: contains `StaticSecret` (which doesn't impl
/// Debug for safety reasons) plus root-key / chain-key bytes that we don't
/// want accidentally leaking into a `{:?}` log.
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetState {
    /// Our current DH ratchet keypair — private half, serialized as 32 bytes.
    #[serde(with = "serde_static_secret")]
    dhs_secret: StaticSecret,
    /// Cached public half of `dhs_secret`. Recomputed on deserialize.
    #[serde(with = "serde_pubkey")]
    dhs_public: PublicKey,
    /// Remote party's last-seen DH ratchet pubkey. `None` until the first
    /// receive on the responder side.
    #[serde(with = "serde_opt_pubkey")]
    dhr: Option<PublicKey>,
    /// 32-byte root key.
    rk: [u8; 32],
    /// Current sending chain key. `None` on the responder until the first
    /// DH ratchet step.
    cks: Option<[u8; 32]>,
    /// Current receiving chain key. `None` on the initiator until the
    /// first receive.
    ckr: Option<[u8; 32]>,
    /// Messages sent in the current sending chain.
    ns: u32,
    /// Messages received in the current receiving chain.
    nr: u32,
    /// Length of the previous sending chain (the `PN` header field for our
    /// outgoing messages).
    pn: u32,
    /// Bounded queue of skipped message keys, oldest first.
    skipped: VecDeque<SkippedKey>,
}

impl RatchetState {
    /// Initialise on the **initiator** side after X3DH has produced `sk`.
    ///
    /// `their_dh_pub` is the responder's signed X25519 prekey (which is
    /// what they used as their initial DH ratchet key).
    ///
    /// The initiator can `encrypt` immediately; the first message header
    /// carries the new DH pubkey so the responder can do a ratchet step.
    pub fn new_initiator(sk: [u8; 32], their_dh_pub: PublicKey) -> Self {
        let dhs_secret = StaticSecret::random_from_rng(OsRng);
        let dhs_public = PublicKey::from(&dhs_secret);

        // First DH ratchet step: advances rk from sk and produces cks.
        let dh_out = dhs_secret.diffie_hellman(&their_dh_pub);
        let (rk, cks) = kdf_rk(&sk, dh_out.as_bytes());

        Self {
            dhs_secret,
            dhs_public,
            dhr: Some(their_dh_pub),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: VecDeque::new(),
        }
    }

    /// Initialise on the **responder** side after X3DH has produced `sk`.
    ///
    /// `my_dh_secret` is the responder's own signed prekey secret. The
    /// responder cannot `encrypt` until they've received one message and
    /// derived `cks` via a ratchet step.
    pub fn new_responder(sk: [u8; 32], my_dh_secret: StaticSecret) -> Self {
        let dhs_public = PublicKey::from(&my_dh_secret);
        Self {
            dhs_secret: my_dh_secret,
            dhs_public,
            dhr: None,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: VecDeque::new(),
        }
    }

    /// Encrypt `plaintext`. `associated_data` is mixed into the AEAD so
    /// the recipient can pass the same bytes and detect any mismatch.
    ///
    /// Returns the wire-form [`RatchetMessage`].
    ///
    /// Errors: only the "uninitialized for send" path (responder hasn't
    /// received yet). Everything else is infallible.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<RatchetMessage, RatchetError> {
        let cks = self.cks.as_mut().ok_or(RatchetError::NotInitializedForRecv)?;
        let (next_cks, mk) = kdf_ck(cks);
        *cks = next_cks;

        let header = Header {
            dh: *self.dhs_public.as_bytes(),
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let ciphertext = aead_encrypt(&mk, plaintext, associated_data, &header);
        Ok(RatchetMessage { header, ciphertext })
    }

    /// Decrypt a [`RatchetMessage`]. Mirrors the spec's `RatchetDecrypt`:
    /// 1. Try any cached skipped message key.
    /// 2. If the header carries a new DH pubkey, do a DH ratchet step
    ///    (storing the keys we skipped in the *previous* receiving chain).
    /// 3. Skip forward in the current receiving chain if needed.
    /// 4. Derive `mk` and decrypt.
    pub fn decrypt(
        &mut self,
        msg: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        // Step 1: skipped-key fast path.
        if let Some(pt) = self.try_skipped(msg, associated_data) {
            return Ok(pt);
        }

        // Step 2: DH ratchet step if we see a new sender DH pubkey.
        let incoming_dh = PublicKey::from(msg.header.dh);
        let is_new_dh = match self.dhr {
            Some(ref current) => current.as_bytes() != incoming_dh.as_bytes(),
            None => true,
        };
        if is_new_dh {
            self.skip_message_keys(msg.header.pn)?;
            self.dh_ratchet_step(incoming_dh);
        }

        // Step 3: catch up within the current receiving chain.
        self.skip_message_keys(msg.header.n)?;

        // Step 4: derive mk and decrypt.
        let ckr = self.ckr.as_mut().ok_or(RatchetError::NotInitializedForRecv)?;
        let (next_ckr, mk) = kdf_ck(ckr);
        *ckr = next_ckr;
        self.nr += 1;

        aead_decrypt(&mk, &msg.ciphertext, associated_data, &msg.header)
    }

    /// Serialize state to JSON. Plaintext for now — encryption at rest
    /// lands in Phase 3.5 once OS-keyring integration is wired up.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize state from JSON.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    // ----- internal -----

    /// Search the skipped-key cache. On hit, decrypt with the cached `mk`
    /// and remove it from the cache (each `mk` is one-shot).
    fn try_skipped(
        &mut self,
        msg: &RatchetMessage,
        ad: &[u8],
    ) -> Option<Vec<u8>> {
        let pos = self
            .skipped
            .iter()
            .position(|s| s.dh_pub == msg.header.dh && s.n == msg.header.n)?;
        // `remove` returns Option; we just confirmed `pos` is valid.
        let entry = self.skipped.remove(pos).expect("position is valid");
        aead_decrypt(&entry.mk, &msg.ciphertext, ad, &msg.header).ok()
    }

    /// Advance the current receiving chain to `until` (exclusive),
    /// caching the message keys we skipped past so an out-of-order
    /// delivery can still decrypt them.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        let Some(ckr) = self.ckr.as_mut() else {
            // Nothing to skip yet; the caller will do a DH ratchet step.
            return Ok(());
        };

        if until.saturating_sub(self.nr) as usize + self.skipped.len() > MAX_SKIP {
            return Err(RatchetError::TooManySkipped);
        }

        let dhr_bytes = match self.dhr {
            Some(ref pk) => *pk.as_bytes(),
            None => return Ok(()),
        };

        while self.nr < until {
            let (next_ckr, mk) = kdf_ck(ckr);
            *ckr = next_ckr;
            self.skipped.push_back(SkippedKey {
                dh_pub: dhr_bytes,
                n: self.nr,
                mk,
            });
            self.nr += 1;
        }

        // Oldest-first eviction if we crept over the cap via repeated steps.
        while self.skipped.len() > MAX_SKIP {
            self.skipped.pop_front();
        }
        Ok(())
    }

    /// The spec's `DHRatchet`: rotate our keypair, derive a new receiving
    /// chain from the incoming DH, then a new sending chain from a freshly
    /// generated keypair against the same incoming DH.
    fn dh_ratchet_step(&mut self, incoming_dh: PublicKey) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(incoming_dh);

        // First half: derive the new receiving chain from the OLD dhs.
        let dh_out = self.dhs_secret.diffie_hellman(&incoming_dh);
        let (new_rk, new_ckr) = kdf_rk(&self.rk, dh_out.as_bytes());
        self.rk = new_rk;
        self.ckr = Some(new_ckr);

        // Second half: rotate our keypair, derive the new sending chain.
        let new_dhs = StaticSecret::random_from_rng(OsRng);
        let new_dhs_pub = PublicKey::from(&new_dhs);
        let dh_out2 = new_dhs.diffie_hellman(&incoming_dh);
        let (new_rk2, new_cks) = kdf_rk(&self.rk, dh_out2.as_bytes());

        // Replace and zero the old keypair on drop (StaticSecret implements
        // ZeroizeOnDrop in x25519-dalek 2.x).
        self.dhs_secret = new_dhs;
        self.dhs_public = new_dhs_pub;
        self.rk = new_rk2;
        self.cks = Some(new_cks);
    }
}

// ----- key derivation -----

/// KDF_RK(rk, dh_out) → (new_rk, ck). HKDF-SHA256 with salt = rk,
/// ikm = dh_out, info = domain. Splits the 64-byte output into two
/// 32-byte halves.
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Explicit `.as_slice()` because `Some(&[u8; 32])` does not coerce to
    // `Option<&[u8]>` inside a function argument — the coercion only fires
    // for the bare reference, not through the Option wrapper.
    let hk = Hkdf::<Sha256>::new(Some(rk.as_slice()), dh_out.as_slice());
    let mut okm = [0u8; 64];
    hk.expand(RK_INFO, &mut okm)
        .expect("64 bytes is within HKDF-SHA256's output limit");

    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (new_rk, ck)
}

/// KDF_CK(ck) → (new_ck, mk). Per Signal spec: HMAC-SHA256 with
/// `ck` as key, the message-key constant for `mk`, and the chain-key
/// constant for `new_ck`.
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // `.as_slice()` to avoid relying on `&[u8; 32]` → `&[u8]` coercion at
    // the call site.
    // Disambiguate `new_from_slice`: both `Mac` and the `digest::KeyInit`
    // supertrait expose a method by that name in scope. Pick the `KeyInit`
    // one explicitly — that's the supertrait that actually defines it.
    let mut mac_mk = <HmacSha256 as HmacKeyInit>::new_from_slice(ck.as_slice())
        .expect("HMAC accepts any key length");
    mac_mk.update(&[CK_CONST_MSG]);
    let mk_bytes = mac_mk.finalize().into_bytes();

    let mut mac_ck = <HmacSha256 as HmacKeyInit>::new_from_slice(ck.as_slice())
        .expect("HMAC accepts any key length");
    mac_ck.update(&[CK_CONST_CHAIN]);
    let ck_bytes = mac_ck.finalize().into_bytes();

    let mut mk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    mk.copy_from_slice(&mk_bytes);
    new_ck.copy_from_slice(&ck_bytes);
    (new_ck, mk)
}

// ----- AEAD -----

/// AEAD encrypt with a one-shot key. Zero nonce is safe because `mk`
/// is derived per-message and never reused.
fn aead_encrypt(mk: &[u8; 32], plaintext: &[u8], ad: &[u8], header: &Header) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&mk[..]));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let header_bytes = header.to_aad_bytes();
    // Combine the application AD with the header bytes so a header swap
    // fails AEAD verification.
    let mut combined_ad = Vec::with_capacity(ad.len() + header_bytes.len());
    combined_ad.extend_from_slice(ad);
    combined_ad.extend_from_slice(&header_bytes);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &combined_ad,
            },
        )
        .expect("ChaCha20-Poly1305 encryption is infallible for valid keys")
}

fn aead_decrypt(
    mk: &[u8; 32],
    ciphertext: &[u8],
    ad: &[u8],
    header: &Header,
) -> Result<Vec<u8>, RatchetError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&mk[..]));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let header_bytes = header.to_aad_bytes();
    let mut combined_ad = Vec::with_capacity(ad.len() + header_bytes.len());
    combined_ad.extend_from_slice(ad);
    combined_ad.extend_from_slice(&header_bytes);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &combined_ad,
            },
        )
        .map_err(|_| RatchetError::BadAead)
}

// ----- serde helpers for non-serde-native crypto types -----

mod serde_static_secret {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use x25519_dalek::StaticSecret;

    pub fn serialize<S: Serializer>(s: &StaticSecret, ser: S) -> Result<S::Ok, S::Error> {
        s.to_bytes().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<StaticSecret, D::Error> {
        let bytes: [u8; 32] = Deserialize::deserialize(de)?;
        Ok(StaticSecret::from(bytes))
    }
}

mod serde_pubkey {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use x25519_dalek::PublicKey;

    pub fn serialize<S: Serializer>(p: &PublicKey, ser: S) -> Result<S::Ok, S::Error> {
        p.as_bytes().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<PublicKey, D::Error> {
        let bytes: [u8; 32] = Deserialize::deserialize(de)?;
        Ok(PublicKey::from(bytes))
    }
}

mod serde_opt_pubkey {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use x25519_dalek::PublicKey;

    pub fn serialize<S: Serializer>(
        p: &Option<PublicKey>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        p.as_ref().map(|k| *k.as_bytes()).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<PublicKey>, D::Error> {
        let opt: Option<[u8; 32]> = Deserialize::deserialize(de)?;
        Ok(opt.map(PublicKey::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::x3dh;

    /// Helper: stand up a fresh initiator/responder pair via X3DH + ratchet init.
    /// Returns `(alice, bob)` where Alice is the initiator.
    fn pair() -> (RatchetState, RatchetState) {
        // Bob has a signed prekey he'll use as his initial DH ratchet key.
        let bob_spk = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub = PublicKey::from(&bob_spk);

        // Alice has a long-term X25519 identity (her own prekey).
        let alice_id = StaticSecret::random_from_rng(OsRng);
        let alice_id_pub = PublicKey::from(&alice_id);

        let (eph_pub, sk_alice) = x3dh::initiator_derive(&alice_id, &bob_spk_pub);
        let sk_bob = x3dh::responder_derive(&bob_spk, &eph_pub, &alice_id_pub);
        assert_eq!(sk_alice, sk_bob);

        let alice = RatchetState::new_initiator(sk_alice, bob_spk_pub);
        let bob = RatchetState::new_responder(sk_bob, bob_spk);
        (alice, bob)
    }

    const AD: &[u8] = b"alice->bob";

    #[test]
    fn one_message_alice_to_bob() {
        let (mut alice, mut bob) = pair();
        let ct = alice.encrypt(b"hi bob", AD).unwrap();
        let pt = bob.decrypt(&ct, AD).unwrap();
        assert_eq!(pt, b"hi bob");
    }

    #[test]
    fn ping_pong_100_messages() {
        let (mut alice, mut bob) = pair();
        for i in 0..100 {
            let msg_a = format!("alice msg {}", i).into_bytes();
            let ct = alice.encrypt(&msg_a, AD).unwrap();
            let pt = bob.decrypt(&ct, AD).unwrap();
            assert_eq!(pt, msg_a);

            let msg_b = format!("bob msg {}", i).into_bytes();
            let ct = bob.encrypt(&msg_b, AD).unwrap();
            let pt = alice.decrypt(&ct, AD).unwrap();
            assert_eq!(pt, msg_b);
        }
    }

    #[test]
    fn out_of_order_within_chain() {
        let (mut alice, mut bob) = pair();
        let c1 = alice.encrypt(b"1", AD).unwrap();
        let c2 = alice.encrypt(b"2", AD).unwrap();
        let c3 = alice.encrypt(b"3", AD).unwrap();
        let c4 = alice.encrypt(b"4", AD).unwrap();
        let c5 = alice.encrypt(b"5", AD).unwrap();

        // Deliver 1, 3, 2, 5, 4.
        assert_eq!(bob.decrypt(&c1, AD).unwrap(), b"1");
        assert_eq!(bob.decrypt(&c3, AD).unwrap(), b"3"); // 2 gets skipped + cached
        assert_eq!(bob.decrypt(&c2, AD).unwrap(), b"2"); // recovered from cache
        assert_eq!(bob.decrypt(&c5, AD).unwrap(), b"5"); // 4 skipped + cached
        assert_eq!(bob.decrypt(&c4, AD).unwrap(), b"4");
    }

    #[test]
    fn out_of_order_across_ratchet_step() {
        let (mut alice, mut bob) = pair();
        // Alice sends A1, A2. Bob hasn't received yet.
        let a1 = alice.encrypt(b"a1", AD).unwrap();
        let a2 = alice.encrypt(b"a2", AD).unwrap();
        // Bob receives only A2 first — this forces a DH ratchet step at Bob
        // with pn=0 and skips A1's key in the new receiving chain.
        assert_eq!(bob.decrypt(&a2, AD).unwrap(), b"a2");
        // A1 still decryptable from the skipped cache.
        assert_eq!(bob.decrypt(&a1, AD).unwrap(), b"a1");

        // Now Bob → Alice triggers another ratchet at Alice.
        let b1 = bob.encrypt(b"b1", AD).unwrap();
        assert_eq!(alice.decrypt(&b1, AD).unwrap(), b"b1");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut alice, mut bob) = pair();
        let mut ct = alice.encrypt(b"secret", AD).unwrap();
        ct.ciphertext[0] ^= 0x01;
        assert!(matches!(bob.decrypt(&ct, AD), Err(RatchetError::BadAead)));
    }

    #[test]
    fn tampered_header_dh_fails() {
        let (mut alice, mut bob) = pair();
        let mut ct = alice.encrypt(b"secret", AD).unwrap();
        ct.header.dh[0] ^= 0x01;
        // Wrong DH means Bob runs a ratchet step with a bogus key →
        // the derived chain key is wrong → AEAD fails.
        assert!(bob.decrypt(&ct, AD).is_err());
    }

    #[test]
    fn wrong_associated_data_fails() {
        let (mut alice, mut bob) = pair();
        let ct = alice.encrypt(b"secret", AD).unwrap();
        assert!(matches!(
            bob.decrypt(&ct, b"different-ad"),
            Err(RatchetError::BadAead)
        ));
    }

    #[test]
    fn cross_session_isolation() {
        // Alice has two parallel sessions (with Bob and with Carol).
        // A message from session A must not decrypt in session B.
        let (mut alice_with_bob, _) = pair();
        let (_, mut carol) = pair();
        let ct = alice_with_bob.encrypt(b"for bob", AD).unwrap();
        assert!(carol.decrypt(&ct, AD).is_err());
    }

    #[test]
    fn responder_cannot_send_before_first_receive() {
        let (_, mut bob) = pair();
        let r = bob.encrypt(b"premature", AD);
        assert!(matches!(r, Err(RatchetError::NotInitializedForRecv)));
    }

    #[test]
    fn too_many_skipped_returns_error() {
        let (mut alice, mut bob) = pair();
        // Send one to bootstrap Bob's receiving chain.
        let first = alice.encrypt(b"bootstrap", AD).unwrap();
        bob.decrypt(&first, AD).unwrap();

        // Now Alice rolls forward MAX_SKIP + 2 messages without delivery.
        for _ in 0..(MAX_SKIP + 2) {
            let _ = alice.encrypt(b".", AD).unwrap();
        }
        // The (MAX_SKIP+3)rd message arrives at Bob; he can't skip that
        // many keys in one step → TooManySkipped.
        let huge_n = alice.encrypt(b"way ahead", AD).unwrap();
        assert!(matches!(
            bob.decrypt(&huge_n, AD),
            Err(RatchetError::TooManySkipped)
        ));
    }

    #[test]
    fn state_survives_json_roundtrip() {
        let (mut alice, mut bob) = pair();
        // Exchange a few messages so both states are non-trivial.
        for i in 0..3 {
            let c = alice.encrypt(format!("a{}", i).as_bytes(), AD).unwrap();
            bob.decrypt(&c, AD).unwrap();
            let c = bob.encrypt(format!("b{}", i).as_bytes(), AD).unwrap();
            alice.decrypt(&c, AD).unwrap();
        }

        // Persist and restore Alice.
        let saved = alice.to_json().unwrap();
        let mut alice2 = RatchetState::from_json(&saved).unwrap();

        // alice2 should be functionally identical to alice — next
        // message encrypts and Bob decrypts it.
        let c = alice2.encrypt(b"after restart", AD).unwrap();
        let pt = bob.decrypt(&c, AD).unwrap();
        assert_eq!(pt, b"after restart");
    }

    #[test]
    fn header_aad_bytes_layout_is_stable() {
        let h = Header { dh: [7u8; 32], pn: 0x01020304, n: 0xAABBCCDD };
        let bytes = h.to_aad_bytes();
        assert_eq!(&bytes[..32], &[7u8; 32]);
        assert_eq!(&bytes[32..36], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&bytes[36..40], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
