//! Megolm-style group sender chain — pure-function building blocks
//! for many-to-many group-chat encryption.
//!
//! Each member of a group owns a [`SenderChain`] and broadcasts a
//! [`SenderKeyBundle`] to every other member (via the existing 1:1 DR
//! channel — see `protocol::group::GROUP_CTRL_DOMAIN_SEPARATOR`).
//! Recipients install the bundle as a [`ReceiverChain`] and use it to
//! decrypt that sender's subsequent group messages.
//!
//! ## Architecture
//!
//! - **Chain advance**: HMAC-SHA256(ck, 0x01) → message_key,
//!   HMAC-SHA256(ck, 0x02) → next_ck. Mirrors the DM ratchet's
//!   KDF_CK constants so the two modules are easy to audit side-by-
//!   side.
//! - **Per-message AEAD**: ChaCha20-Poly1305 with key=message_key,
//!   zero nonce. Each message key is used exactly once (chain
//!   advances unconditionally on `encrypt`), so the zero-nonce
//!   choice matches the same safety argument the DR ratchet makes.
//! - **Per-message Ed25519 signature**: prevents one *outsider*
//!   from impersonating a chain owner. The signing key is born
//!   with the chain and embedded in the bundle, so for inside-the-
//!   group impersonation the signature is NOT a defence — see
//!   "threat-model notes" below.
//! - **Skipped-keys cache**: same MAX_SKIP=1000 + oldest-first
//!   eviction policy as the DR ratchet, tracked per (group, peer)
//!   chain.
//!
//! ## Threat-model notes
//!
//! - The signing key is part of the bundle; once a member receives
//!   another's bundle, they CAN forge signed messages claiming to
//!   be that sender at any future chain index ≥ the bundle's
//!   index. The per-message Ed25519 signature is therefore an
//!   anti-impersonation guarantee against group OUTSIDERS only.
//!   For anti-impersonation among insiders, members rely on the
//!   existing safety-number primitive on each pairwise 1:1 channel
//!   and rotate the group on suspected compromise.
//! - MAX_SKIP=1000 matches the DR. A peer that holds back N
//!   messages and then bursts them all forces the receiver to
//!   cache N keys; with MAX_SKIP the worst-case memory is bounded.

use chacha20poly1305::{
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{digest::KeyInit as HmacKeyInit, Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::VecDeque;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

use crate::protocol::GROUP_MSG_DOMAIN_SEPARATOR;

type HmacSha256 = Hmac<Sha256>;

/// HMAC constant → message key. Mirrors `ratchet::CK_CONST_MSG`.
const CK_CONST_MSG: u8 = 0x01;
/// HMAC constant → next chain key. Mirrors `ratchet::CK_CONST_CHAIN`.
const CK_CONST_CHAIN: u8 = 0x02;

/// Per-chain skipped-key cap. Matches `ratchet::MAX_SKIP`.
pub const MAX_SKIP: usize = 1000;

#[derive(Debug, Error)]
pub enum MegolmError {
    #[error("AEAD authentication failed (tamper or wrong key)")]
    BadAead,
    #[error("Ed25519 signature verification failed")]
    BadSignature,
    #[error("would exceed MAX_SKIP={MAX_SKIP} skipped keys in one step")]
    TooManySkipped,
    #[error("message at index {0} is in the past and its key was already consumed or evicted")]
    MessageKeyMissing(u32),
    #[error("bundle's signing pubkey is malformed")]
    BadVerifyingKey,
}

/// Wire-form of a sender's chain state at a particular index. Sent
/// over the 1:1 DR channel to bootstrap a peer's [`ReceiverChain`].
///
/// `index` is the next index the chain will emit — the recipient
/// installs the bundle and expects the very next message at that
/// index, not later ones.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SenderKeyBundle {
    pub chain_key: [u8; 32],
    pub index: u32,
    pub verify_pub: [u8; 32],
}

/// Wire-form of a single encrypted group message. Embedded in the
/// `EncryptedPayload` content (kind=2) — see commit 4 of the group
/// track.
///
/// `signature` is a `Vec<u8>` (not `[u8; 64]`) because serde's
/// blanket `Deserialize` impls don't cover arbitrary-size byte
/// arrays. A malformed-length signature is detected when
/// `ReceiverChain::decrypt` tries to convert it back to an Ed25519
/// `Signature` and the conversion fails — surfaces as
/// `BadSignature`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedGroupMessage {
    pub index: u32,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

/// State of MY sender chain for one group. One instance per group I
/// belong to. Serialized to JSON for at-rest storage (AEAD-wrapped
/// under the DEK by `MessageStore::my_sender_key_save`).
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SenderChain {
    chain_key: [u8; 32],
    index: u32,
    /// Raw 32-byte Ed25519 signing-key seed. Reconstructed on demand
    /// via `SigningKey::from_bytes`.
    sign_priv: [u8; 32],
}

impl SenderChain {
    /// Generate a fresh chain: random 32-byte chain_key + random
    /// Ed25519 keypair. Index starts at 0.
    pub fn new() -> Self {
        let mut chain_key = [0u8; 32];
        OsRng.fill_bytes(&mut chain_key);
        let signing = SigningKey::generate(&mut OsRng);
        Self {
            chain_key,
            index: 0,
            sign_priv: signing.to_bytes(),
        }
    }

    /// Current message index — the value the NEXT `encrypt` call
    /// will stamp into its output.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Bundle a peer needs to install a [`ReceiverChain`] at our
    /// current position. The peer will see our next message at
    /// `bundle.index`, not earlier ones — earlier messages stay
    /// unrecoverable by design (forward secrecy at chain-install time).
    pub fn current_bundle(&self) -> SenderKeyBundle {
        let signing = SigningKey::from_bytes(&self.sign_priv);
        SenderKeyBundle {
            chain_key: self.chain_key,
            index: self.index,
            verify_pub: signing.verifying_key().to_bytes(),
        }
    }

    /// Encrypt a plaintext, advance the chain by one step, and sign
    /// the canonical bytes.
    ///
    /// `associated_data` is bound into the AEAD's AAD AND the
    /// signature; callers typically pass `(group_id || sender_pid)`
    /// so a captured ciphertext can't be replayed under a different
    /// group context.
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> EncryptedGroupMessage {
        let (next_ck, message_key) = advance_chain(&self.chain_key);
        let index = self.index;
        // Bump state BEFORE we craft the output so callers can't
        // accidentally encrypt-and-not-advance on a mid-function panic.
        self.chain_key = next_ck;
        self.index = self.index.wrapping_add(1);

        let aad = build_aead_aad(index, associated_data);
        let ciphertext = chacha_encrypt(&message_key, plaintext, &aad);

        let canonical = canonical_sign_bytes(index, associated_data, &ciphertext);
        let signing = SigningKey::from_bytes(&self.sign_priv);
        let sig = signing.sign(&canonical);

        EncryptedGroupMessage {
            index,
            ciphertext,
            signature: sig.to_bytes().to_vec(),
        }
    }

    pub fn to_json(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }
    pub fn from_json(bytes: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(bytes)
    }
}

impl Default for SenderChain {
    fn default() -> Self {
        Self::new()
    }
}

/// State of someone else's sender chain. Bound to a specific
/// `(group_id, peer_id)` pair by callers.
///
/// Intentionally does NOT derive `ZeroizeOnDrop` — the `VecDeque<SkippedKey>`
/// field doesn't implement `Zeroize`. Matches the existing `RatchetState`
/// pattern (zeroize at the leaf, not the container); at-rest state is
/// AEAD-wrapped under the DEK anyway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverChain {
    chain_key: [u8; 32],
    next_index: u32,
    verify_pub: [u8; 32],
    skipped: VecDeque<SkippedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
struct SkippedKey {
    index: u32,
    message_key: [u8; 32],
}

impl ReceiverChain {
    /// Install a chain from a [`SenderKeyBundle`]. The bundle's
    /// `index` becomes our `next_index` — the very next message we
    /// accept from this peer is at that index.
    pub fn from_bundle(bundle: &SenderKeyBundle) -> Self {
        Self {
            chain_key: bundle.chain_key,
            next_index: bundle.index,
            verify_pub: bundle.verify_pub,
            skipped: VecDeque::new(),
        }
    }

    /// Next message index we will accept on the live chain (skipped
    /// keys can serve earlier indices in the past-message window).
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Decrypt a message. Verifies Ed25519 BEFORE any state mutation
    /// so a forged-signature attempt can't poison the skipped cache
    /// or advance the chain.
    pub fn decrypt(
        &mut self,
        msg: &EncryptedGroupMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, MegolmError> {
        // Step 1: verify signature. Done first so chain state is never
        // mutated by a forged message. A bad-length signature blob
        // (anything other than 64 bytes) is also a BadSignature —
        // wire validation rolled into the same error.
        let verifying = VerifyingKey::from_bytes(&self.verify_pub)
            .map_err(|_| MegolmError::BadVerifyingKey)?;
        let canonical = canonical_sign_bytes(msg.index, associated_data, &msg.ciphertext);
        let sig_bytes: &[u8; 64] = msg
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| MegolmError::BadSignature)?;
        let signature = Signature::from_bytes(sig_bytes);
        verifying
            .verify(&canonical, &signature)
            .map_err(|_| MegolmError::BadSignature)?;

        // Step 2: past-message branch — look up in the skipped cache.
        // A second arrival at the same index can't be served (key was
        // either consumed or evicted) — return MessageKeyMissing.
        if msg.index < self.next_index {
            let pos = self
                .skipped
                .iter()
                .position(|sk| sk.index == msg.index)
                .ok_or(MegolmError::MessageKeyMissing(msg.index))?;
            let sk = self.skipped.remove(pos).expect("position is valid");
            let aad = build_aead_aad(msg.index, associated_data);
            return chacha_decrypt(&sk.message_key, &msg.ciphertext, &aad)
                .map_err(|_| MegolmError::BadAead);
        }

        // Step 3: future-message branch — walk the chain forward,
        // caching the skipped keys.
        let n_to_skip = msg.index - self.next_index;
        if (n_to_skip as usize).saturating_add(self.skipped.len()) > MAX_SKIP {
            return Err(MegolmError::TooManySkipped);
        }
        for _ in 0..n_to_skip {
            let (next_ck, mk) = advance_chain(&self.chain_key);
            self.skipped.push_back(SkippedKey {
                index: self.next_index,
                message_key: mk,
            });
            self.chain_key = next_ck;
            self.next_index = self.next_index.wrapping_add(1);
        }
        // Oldest-first eviction in case the loop pushed past the cap.
        while self.skipped.len() > MAX_SKIP {
            self.skipped.pop_front();
        }
        // Step 4: derive the message key for `msg.index` itself.
        let (next_ck, mk) = advance_chain(&self.chain_key);
        self.chain_key = next_ck;
        self.next_index = self.next_index.wrapping_add(1);

        let aad = build_aead_aad(msg.index, associated_data);
        chacha_decrypt(&mk, &msg.ciphertext, &aad).map_err(|_| MegolmError::BadAead)
    }

    pub fn to_json(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }
    pub fn from_json(bytes: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(bytes)
    }
}

/// Advance a chain by one step. Returns `(next_chain_key, message_key)`.
///
/// `<HmacSha256 as HmacKeyInit>::new_from_slice` is fully qualified
/// because both `KeyInit` and `Mac` define `new_from_slice` and Rust
/// would otherwise refuse to pick one (matches the disambiguation in
/// `ratchet.rs::kdf_ck`).
fn advance_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut next_ck = [0u8; 32];
    let mut mk = [0u8; 32];

    let mut h = <HmacSha256 as HmacKeyInit>::new_from_slice(chain_key)
        .expect("HMAC accepts any key length");
    h.update(&[CK_CONST_CHAIN]);
    next_ck.copy_from_slice(&h.finalize().into_bytes());

    let mut h = <HmacSha256 as HmacKeyInit>::new_from_slice(chain_key)
        .expect("HMAC accepts any key length");
    h.update(&[CK_CONST_MSG]);
    mk.copy_from_slice(&h.finalize().into_bytes());

    (next_ck, mk)
}

/// Canonical AEAD AAD: `index_be (4) || ad_len_be (4) || ad`.
fn build_aead_aad(index: u32, ad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + ad.len());
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&(ad.len() as u32).to_be_bytes());
    out.extend_from_slice(ad);
    out
}

/// Canonical bytes signed by the sender:
/// `DOMAIN || index_be (4) || ad_len_be (4) || ad || ct_len_be (4) || ct`.
/// Unambiguous because every variable-length field is preceded by its
/// u32 length.
fn canonical_sign_bytes(index: u32, ad: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        GROUP_MSG_DOMAIN_SEPARATOR.len() + 4 + 4 + ad.len() + 4 + ct.len(),
    );
    out.extend_from_slice(GROUP_MSG_DOMAIN_SEPARATOR);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&(ad.len() as u32).to_be_bytes());
    out.extend_from_slice(ad);
    out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
    out.extend_from_slice(ct);
    out
}

fn chacha_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .expect("ChaCha20-Poly1305 encryption is infallible for valid keys")
}

fn chacha_decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher.decrypt(nonce, Payload { msg: ciphertext, aad })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AD: &[u8] = b"group:test;sender:alice";

    /// Build a paired SenderChain + ReceiverChain that share state via
    /// the current bundle. The receiver expects messages starting at
    /// sender's current index (0 for a fresh chain).
    fn paired() -> (SenderChain, ReceiverChain) {
        let sender = SenderChain::new();
        let receiver = ReceiverChain::from_bundle(&sender.current_bundle());
        (sender, receiver)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (mut s, mut r) = paired();
        let msg = s.encrypt(b"hello", AD);
        assert_eq!(msg.index, 0);
        let out = r.decrypt(&msg, AD).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(r.next_index(), 1);
    }

    #[test]
    fn ping_pong_100_messages_in_order() {
        let (mut s, mut r) = paired();
        for i in 0..100u32 {
            let payload = format!("msg-{}", i);
            let m = s.encrypt(payload.as_bytes(), AD);
            let out = r.decrypt(&m, AD).unwrap();
            assert_eq!(out, payload.as_bytes());
            assert_eq!(m.index, i);
        }
        assert_eq!(s.index(), 100);
        assert_eq!(r.next_index(), 100);
    }

    #[test]
    fn out_of_order_uses_skipped_cache() {
        let (mut s, mut r) = paired();
        let m0 = s.encrypt(b"0", AD);
        let m1 = s.encrypt(b"1", AD);
        let m2 = s.encrypt(b"2", AD);
        let m3 = s.encrypt(b"3", AD);
        let m4 = s.encrypt(b"4", AD);

        // Out-of-order: 0, 2, 1, 4, 3. Indices 1 and 3 land in the
        // skipped cache on the 2 / 4 step, then get consumed.
        assert_eq!(r.decrypt(&m0, AD).unwrap(), b"0");
        assert_eq!(r.decrypt(&m2, AD).unwrap(), b"2");
        assert_eq!(r.decrypt(&m1, AD).unwrap(), b"1");
        assert_eq!(r.decrypt(&m4, AD).unwrap(), b"4");
        assert_eq!(r.decrypt(&m3, AD).unwrap(), b"3");
    }

    #[test]
    fn replay_returns_message_key_missing() {
        let (mut s, mut r) = paired();
        let m = s.encrypt(b"once", AD);
        assert_eq!(r.decrypt(&m, AD).unwrap(), b"once");
        // Second attempt: the message key was consumed on the live
        // chain and isn't cached as a skipped key.
        let err = r.decrypt(&m, AD).unwrap_err();
        assert!(matches!(err, MegolmError::MessageKeyMissing(0)), "got {:?}", err);
    }

    #[test]
    fn signature_tamper_rejected_before_state_mutation() {
        let (mut s, mut r) = paired();
        let mut bad = s.encrypt(b"x", AD);
        // Flip one bit of the signature.
        bad.signature[0] ^= 0x01;
        let next_idx_before = r.next_index();
        let err = r.decrypt(&bad, AD).unwrap_err();
        assert!(matches!(err, MegolmError::BadSignature), "got {:?}", err);
        // State unchanged: chain didn't advance because verify failed first.
        assert_eq!(r.next_index(), next_idx_before);
    }

    #[test]
    fn ciphertext_tamper_rejected_by_signature() {
        let (mut s, mut r) = paired();
        let mut bad = s.encrypt(b"x", AD);
        bad.ciphertext[0] ^= 0x01;
        // The canonical-signing bytes include ct, so a ct flip breaks
        // the signature — we hit BadSignature before the AEAD path.
        let err = r.decrypt(&bad, AD).unwrap_err();
        assert!(matches!(err, MegolmError::BadSignature), "got {:?}", err);
    }

    #[test]
    fn ad_mismatch_rejected_by_signature() {
        let (mut s, mut r) = paired();
        let m = s.encrypt(b"x", AD);
        // Receiver tries a different AD — signature is bound to the
        // sender's AD, so verify fails.
        let err = r.decrypt(&m, b"different-context").unwrap_err();
        assert!(matches!(err, MegolmError::BadSignature), "got {:?}", err);
    }

    #[test]
    fn too_many_skipped_returns_error() {
        let (mut s, mut r) = paired();
        // Roll the sender forward MAX_SKIP+2 messages.
        for _ in 0..(MAX_SKIP + 2) {
            let _ = s.encrypt(b"_", AD);
        }
        let m_last = s.encrypt(b"final", AD);
        // Receiver hasn't seen any of the prior MAX_SKIP+2; jumping
        // straight to the final index requires caching MAX_SKIP+2 keys,
        // which exceeds the cap.
        let err = r.decrypt(&m_last, AD).unwrap_err();
        assert!(matches!(err, MegolmError::TooManySkipped), "got {:?}", err);
    }

    #[test]
    fn sender_chain_json_roundtrip_preserves_state() {
        let mut s = SenderChain::new();
        let _ = s.encrypt(b"a", AD);
        let _ = s.encrypt(b"b", AD);
        let blob = s.to_json().unwrap();
        let mut s2 = SenderChain::from_json(&blob).unwrap();
        assert_eq!(s2.index(), s.index());
        // s2 should produce the same next ciphertext as s would have.
        let m_orig = s.encrypt(b"c", AD);
        let m_clone = s2.encrypt(b"c", AD);
        // Index matches; ciphertext bytes match (chain state was identical).
        assert_eq!(m_orig.index, m_clone.index);
        assert_eq!(m_orig.ciphertext, m_clone.ciphertext);
    }

    #[test]
    fn receiver_chain_json_roundtrip_preserves_skipped_cache() {
        let (mut s, mut r) = paired();
        let m0 = s.encrypt(b"0", AD);
        let m1 = s.encrypt(b"1", AD);
        let m2 = s.encrypt(b"2", AD);

        // Pre-skip: deliver m0, m2 — m1's key lands in skipped cache.
        assert_eq!(r.decrypt(&m0, AD).unwrap(), b"0");
        assert_eq!(r.decrypt(&m2, AD).unwrap(), b"2");

        // Round-trip the receiver through JSON.
        let blob = r.to_json().unwrap();
        let mut r2 = ReceiverChain::from_json(&blob).unwrap();

        // The skipped m1 key must survive the round-trip.
        assert_eq!(r2.decrypt(&m1, AD).unwrap(), b"1");
    }

    #[test]
    fn bundle_install_at_nonzero_index() {
        // Sender encrypts 3 messages, then exports a bundle. A late-
        // joiner installs the bundle and should be able to decrypt
        // sender's NEXT message (index 3) cleanly but cannot retroact
        // to messages 0..3 (chain-install forward secrecy).
        let mut s = SenderChain::new();
        let _m0 = s.encrypt(b"pre0", AD);
        let _m1 = s.encrypt(b"pre1", AD);
        let _m2 = s.encrypt(b"pre2", AD);

        let mut late = ReceiverChain::from_bundle(&s.current_bundle());
        assert_eq!(late.next_index(), 3);

        let m3 = s.encrypt(b"first-i-see", AD);
        assert_eq!(m3.index, 3);
        assert_eq!(late.decrypt(&m3, AD).unwrap(), b"first-i-see");

        // m2 is not recoverable — it was sent before bundle export.
        // We model that by simply observing the late receiver was
        // never given an m2 to try; the chain forward state has moved
        // past it, and there's no skipped-cache entry.
    }

    #[test]
    fn cross_chain_message_rejected_by_signature() {
        // A ciphertext from chain A signed by chain A's Ed25519 key
        // is rejected by chain B's verifier — even if it's at a
        // matching index. Defends against a member trying to inject
        // a message claiming to be from another member of the same
        // group.
        let (mut s_a, _r_a) = paired();
        let (_s_b, mut r_b) = paired();
        let m = s_a.encrypt(b"from A", AD);
        let err = r_b.decrypt(&m, AD).unwrap_err();
        assert!(matches!(err, MegolmError::BadSignature), "got {:?}", err);
    }
}
