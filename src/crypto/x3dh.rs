//! X3DH-lite: simplified two-DH initial key agreement.
//!
//! Full X3DH (https://signal.org/docs/specifications/x3dh/) uses four DH
//! operations: identity, signed prekey, ephemeral, and a one-time prekey
//! fetched from a server. We currently have no server and no one-time
//! prekey infrastructure, so we run a two-DH variant:
//!
//! ```text
//!   DH1 = DH(initiator_ephemeral, responder_signed_prekey)
//!   DH2 = DH(initiator_identity_x25519, responder_signed_prekey)
//!   SK  = HKDF-SHA256(salt = 0..0, ikm = DH1 || DH2, info = DOMAIN, L = 32)
//! ```
//!
//! Properties we keep:
//! - **Mutual authentication of the responder**: the responder's signed
//!   prekey is signed by their Ed25519 identity key, verified by the caller
//!   before invoking these functions.
//! - **Forward secrecy via the ephemeral**: if the initiator's identity key
//!   is later compromised, past session keys can't be derived without the
//!   responder's prekey *and* the initiator's ephemeral (which is discarded
//!   after use).
//!
//! Properties we **don't** yet have:
//! - **Initiator authentication is implicit**: we authenticate the initiator
//!   via the application-layer Ed25519 signature on each `ProtocolMessage`,
//!   not via X3DH itself. (Full X3DH includes DH3 = DH(initiator_identity,
//!   responder_identity) for this.)
//! - **Asynchronous first message**: requires one-time prekeys.
//! - **Deniability**: the per-message signature undoes the X3DH-only
//!   deniability property; this is an intentional trade-off for simpler
//!   verification.

use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use ml_kem::{kem::Decapsulate, kem::Encapsulate, EncodedSizeUser, KemCore, MlKem768};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Domain-separator tag for the X3DH HKDF, 2-DH variant.
const X3DH_INFO: &[u8] = b"ME55-x3dh-v1";

/// Domain-separator tag for the 3-DH variant (with one-time prekey).
/// Distinct from the 2-DH variant so the two derivations are NEVER
/// confusable: a session built with OTPK uses one secret, without uses
/// another, even if the rest of the inputs happen to collide.
const X3DH_INFO_OTPK: &[u8] = b"ME55-x3dh-otpk-v1";

/// Phase 2 PQ-X3DH domain separators. Distinct from the classical
/// variants so a downgrade attack (peer drops the PQ ciphertext from a
/// captured first-message envelope) cannot recover a classical-X3DH
/// secret matching a hybrid initiator — the HKDF info tag differs and
/// the resulting SKs never collide.
const X3DH_INFO_PQ: &[u8] = b"ME55-x3dh-pq-v1";
const X3DH_INFO_OTPK_PQ: &[u8] = b"ME55-x3dh-otpk-pq-v1";

/// Length of the derived shared secret in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

/// Length of an ML-KEM-768 shared secret (FIPS 203).
pub const ML_KEM_SS_LEN: usize = 32;

/// Length of an ML-KEM-768 ciphertext (FIPS 203).
pub const ML_KEM_CT_LEN: usize = 1088;

/// What the initiator runs when starting a new session with `responder`.
///
/// Inputs:
/// - `my_identity_x25519`: the initiator's long-term X25519 prekey secret
///   (from [`crate::core::Identity::x25519_secret`]).
/// - `responder_signed_prekey`: the responder's X25519 prekey **after**
///   its Ed25519 signature has been verified by the caller.
///
/// Returns:
/// - `ephemeral_pub`: the initiator's ephemeral X25519 pubkey. Must be
///   sent to the responder in the first message header so they can derive
///   the same shared secret.
/// - `sk`: the 32-byte shared secret to seed the Double Ratchet root key.
///
/// The ephemeral private key is consumed and zeroized inside this call —
/// it never crosses an API boundary.
pub fn initiator_derive(
    my_identity_x25519: &StaticSecret,
    responder_signed_prekey: &PublicKey,
) -> (PublicKey, [u8; SHARED_SECRET_LEN]) {
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // DH1 = DH(initiator_ephemeral, responder_signed_prekey)
    let dh1 = ephemeral_secret.diffie_hellman(responder_signed_prekey);
    // DH2 = DH(initiator_identity, responder_signed_prekey)
    let dh2 = my_identity_x25519.diffie_hellman(responder_signed_prekey);

    let sk = derive_shared_secret(dh1.as_bytes(), dh2.as_bytes());

    (ephemeral_public, sk)
}

/// What the responder runs when an initial message arrives bearing the
/// initiator's ephemeral pubkey.
///
/// Inputs:
/// - `my_signed_prekey`: the responder's own X25519 prekey secret.
/// - `initiator_ephemeral`: the X25519 pubkey from the first message header.
/// - `initiator_identity_x25519`: the initiator's long-term X25519 prekey
///   pubkey (fetched via the prekey protocol and signature-verified).
///
/// Returns the same 32-byte shared secret the initiator derived.
pub fn responder_derive(
    my_signed_prekey: &StaticSecret,
    initiator_ephemeral: &PublicKey,
    initiator_identity_x25519: &PublicKey,
) -> [u8; SHARED_SECRET_LEN] {
    // DH1 = DH(responder_signed_prekey, initiator_ephemeral)
    let dh1 = my_signed_prekey.diffie_hellman(initiator_ephemeral);
    // DH2 = DH(responder_signed_prekey, initiator_identity)
    let dh2 = my_signed_prekey.diffie_hellman(initiator_identity_x25519);

    derive_shared_secret(dh1.as_bytes(), dh2.as_bytes())
}

/// HKDF-SHA256(salt = zero[32], ikm = dh1 || dh2, info = X3DH_INFO).
///
/// Using a zero salt is conventional for X3DH-style initial KDF (Signal
/// does the same). The domain separator in `info` is what binds it to
/// our protocol.
fn derive_shared_secret(dh1: &[u8; 32], dh2: &[u8; 32]) -> [u8; SHARED_SECRET_LEN] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(dh1);
    ikm[32..].copy_from_slice(dh2);

    let zero_salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&zero_salt[..]), &ikm[..]);
    let mut sk = [0u8; SHARED_SECRET_LEN];
    hk.expand(X3DH_INFO, &mut sk)
        .expect("32 bytes is well within HKDF-SHA256's output budget");

    ikm.zeroize();
    sk
}

/// HKDF-SHA256 over dh1 || dh2 || dh3 with the OTPK-variant info tag.
fn derive_shared_secret_3(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
) -> [u8; SHARED_SECRET_LEN] {
    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(dh1);
    ikm[32..64].copy_from_slice(dh2);
    ikm[64..].copy_from_slice(dh3);

    let zero_salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&zero_salt[..]), &ikm[..]);
    let mut sk = [0u8; SHARED_SECRET_LEN];
    hk.expand(X3DH_INFO_OTPK, &mut sk)
        .expect("32 bytes is well within HKDF-SHA256's output budget");

    ikm.zeroize();
    sk
}

/// Initiator side of X3DH **with** a one-time prekey (3-DH variant).
///
/// Inputs same as [`initiator_derive`] plus `responder_otpk` — the
/// peer's freshly-popped OTPK pubkey (its signature must be verified
/// out of band before this is called).
///
/// The third DH is `DH(initiator_ephemeral, responder_otpk)`. Forward
/// secrecy improves: even if both long-term keys (initiator identity
/// + responder signed prekey) are later compromised, this session's SK
/// still requires the *ephemeral* secret and the *one-time* secret —
/// both of which are deleted after one use.
pub fn initiator_derive_with_otpk(
    my_identity_x25519: &StaticSecret,
    responder_signed_prekey: &PublicKey,
    responder_otpk: &PublicKey,
) -> (PublicKey, [u8; SHARED_SECRET_LEN]) {
    // Use `StaticSecret` (not `EphemeralSecret`) because we need TWO DH
    // operations from the same private key, and `EphemeralSecret::diffie_hellman`
    // consumes `self`. StaticSecret is `ZeroizeOnDrop` (with the
    // `static_secrets` feature) — same forward-secrecy property as
    // EphemeralSecret as long as we don't persist or leak its bytes.
    let eph_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_public = PublicKey::from(&eph_secret);

    let dh1 = eph_secret.diffie_hellman(responder_signed_prekey);
    let dh2 = my_identity_x25519.diffie_hellman(responder_signed_prekey);
    let dh3 = eph_secret.diffie_hellman(responder_otpk);

    let sk = derive_shared_secret_3(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes());
    // eph_secret drops at end of scope → ZeroizeOnDrop.
    (eph_public, sk)
}

/// Responder side of X3DH **with** a one-time prekey (3-DH variant).
pub fn responder_derive_with_otpk(
    my_signed_prekey: &StaticSecret,
    my_otpk: &StaticSecret,
    initiator_ephemeral: &PublicKey,
    initiator_identity_x25519: &PublicKey,
) -> [u8; SHARED_SECRET_LEN] {
    let dh1 = my_signed_prekey.diffie_hellman(initiator_ephemeral);
    let dh2 = my_signed_prekey.diffie_hellman(initiator_identity_x25519);
    let dh3 = my_otpk.diffie_hellman(initiator_ephemeral);

    derive_shared_secret_3(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes())
}

// ============================================================
// Phase 2 PQ-X3DH (hybrid ML-KEM-768)
// ============================================================
//
// Hybrid construction: classical X25519 X3DH PLUS an ML-KEM-768
// shared secret, mixed into the same HKDF. The session SK stays
// secure as long as EITHER the X25519 problem OR the ML-KEM
// problem remains hard. Matches Signal's PQXDH (2023).
//
// The PQ key material lives on the long-term identity (see
// `core::identity::Identity::ml_kem_*`). The initiator encapsulates
// against the responder's published ML-KEM encapsulation key,
// producing a (ciphertext, shared_secret) pair. Ciphertext travels in
// the first message; shared_secret feeds the HKDF here. The responder
// decapsulates with its long-term ML-KEM decapsulation key to
// recover the same shared_secret.

/// Encapsulate a shared secret against the responder's long-term
/// ML-KEM-768 encapsulation key. Used by the initiator at session
/// start. Returns `(ciphertext, shared_secret)`:
/// - `ciphertext` (1088 bytes) is transmitted to the responder in the
///   first message's `EncryptedPayload::ml_kem_ct`.
/// - `shared_secret` (32 bytes) is fed into the hybrid HKDF here and
///   never crosses the API boundary.
///
/// The caller MUST have already verified `responder_ek_bytes` against
/// the responder's identity Ed25519 key (signature over
/// `ML_KEM_PREKEY_SIG_DOMAIN || ek`).
pub fn pq_encapsulate(responder_ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; ML_KEM_SS_LEN])> {
    use ml_kem::array::Array;
    let ek_arr = Array::try_from(responder_ek_bytes)
        .map_err(|_| anyhow!("ml-kem ek wrong length: got {}", responder_ek_bytes.len()))?;
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);
    let (ct, ss) = ek
        .encapsulate(&mut rand::rngs::OsRng)
        .map_err(|e| anyhow!("ml-kem encapsulate failed: {:?}", e))?;
    let ct_vec = ct.as_slice().to_vec();
    let mut ss_arr = [0u8; ML_KEM_SS_LEN];
    ss_arr.copy_from_slice(ss.as_slice());
    Ok((ct_vec, ss_arr))
}

/// Decapsulate the initiator's ciphertext with our long-term ML-KEM
/// decapsulation key. Returns the same 32-byte shared secret the
/// initiator obtained from [`pq_encapsulate`]. Used by the responder
/// when processing a first message that carried `ml_kem_ct`.
pub fn pq_decapsulate(my_dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<[u8; ML_KEM_SS_LEN]> {
    use ml_kem::array::Array;
    let dk_arr = Array::try_from(my_dk_bytes)
        .map_err(|_| anyhow!("ml-kem dk wrong length: got {}", my_dk_bytes.len()))?;
    let ct_arr = Array::try_from(ct_bytes)
        .map_err(|_| anyhow!("ml-kem ct wrong length: got {}", ct_bytes.len()))?;
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_arr);
    let ss = dk
        .decapsulate(&ct_arr)
        .map_err(|e| anyhow!("ml-kem decapsulate failed: {:?}", e))?;
    let mut ss_arr = [0u8; ML_KEM_SS_LEN];
    ss_arr.copy_from_slice(ss.as_slice());
    Ok(ss_arr)
}

/// Hybrid 2-DH X3DH (initiator side). Same as [`initiator_derive`]
/// but additionally takes a PQ shared secret from [`pq_encapsulate`]
/// and feeds it into HKDF under the PQ-domain-separated info tag.
pub fn initiator_derive_hybrid(
    my_identity_x25519: &StaticSecret,
    responder_signed_prekey: &PublicKey,
    pq_ss: &[u8; ML_KEM_SS_LEN],
) -> (PublicKey, [u8; SHARED_SECRET_LEN]) {
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let dh1 = ephemeral_secret.diffie_hellman(responder_signed_prekey);
    let dh2 = my_identity_x25519.diffie_hellman(responder_signed_prekey);

    let sk = derive_shared_secret_pq(dh1.as_bytes(), dh2.as_bytes(), pq_ss);

    (ephemeral_public, sk)
}

/// Hybrid 2-DH X3DH (responder side). Mirror of
/// [`initiator_derive_hybrid`]. The PQ shared secret comes from
/// [`pq_decapsulate`] applied to the ciphertext carried in the
/// first message's `EncryptedPayload::ml_kem_ct`.
pub fn responder_derive_hybrid(
    my_signed_prekey: &StaticSecret,
    initiator_ephemeral: &PublicKey,
    initiator_identity_x25519: &PublicKey,
    pq_ss: &[u8; ML_KEM_SS_LEN],
) -> [u8; SHARED_SECRET_LEN] {
    let dh1 = my_signed_prekey.diffie_hellman(initiator_ephemeral);
    let dh2 = my_signed_prekey.diffie_hellman(initiator_identity_x25519);
    derive_shared_secret_pq(dh1.as_bytes(), dh2.as_bytes(), pq_ss)
}

/// Hybrid 3-DH X3DH (initiator side, with OTPK).
pub fn initiator_derive_with_otpk_hybrid(
    my_identity_x25519: &StaticSecret,
    responder_signed_prekey: &PublicKey,
    responder_otpk: &PublicKey,
    pq_ss: &[u8; ML_KEM_SS_LEN],
) -> (PublicKey, [u8; SHARED_SECRET_LEN]) {
    let eph_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_public = PublicKey::from(&eph_secret);

    let dh1 = eph_secret.diffie_hellman(responder_signed_prekey);
    let dh2 = my_identity_x25519.diffie_hellman(responder_signed_prekey);
    let dh3 = eph_secret.diffie_hellman(responder_otpk);

    let sk = derive_shared_secret_3_pq(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        pq_ss,
    );
    (eph_public, sk)
}

/// Hybrid 3-DH X3DH (responder side, with OTPK).
pub fn responder_derive_with_otpk_hybrid(
    my_signed_prekey: &StaticSecret,
    my_otpk: &StaticSecret,
    initiator_ephemeral: &PublicKey,
    initiator_identity_x25519: &PublicKey,
    pq_ss: &[u8; ML_KEM_SS_LEN],
) -> [u8; SHARED_SECRET_LEN] {
    let dh1 = my_signed_prekey.diffie_hellman(initiator_ephemeral);
    let dh2 = my_signed_prekey.diffie_hellman(initiator_identity_x25519);
    let dh3 = my_otpk.diffie_hellman(initiator_ephemeral);
    derive_shared_secret_3_pq(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        pq_ss,
    )
}

/// HKDF-SHA256(salt = zero[32], ikm = dh1 || dh2 || pq_ss, info = X3DH_INFO_PQ).
fn derive_shared_secret_pq(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    pq_ss: &[u8; ML_KEM_SS_LEN],
) -> [u8; SHARED_SECRET_LEN] {
    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(dh1);
    ikm[32..64].copy_from_slice(dh2);
    ikm[64..].copy_from_slice(pq_ss);

    let zero_salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&zero_salt[..]), &ikm[..]);
    let mut sk = [0u8; SHARED_SECRET_LEN];
    hk.expand(X3DH_INFO_PQ, &mut sk)
        .expect("32 bytes is well within HKDF-SHA256's output budget");

    ikm.zeroize();
    sk
}

/// HKDF-SHA256 over dh1 || dh2 || dh3 || pq_ss with OTPK+PQ info tag.
fn derive_shared_secret_3_pq(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    pq_ss: &[u8; ML_KEM_SS_LEN],
) -> [u8; SHARED_SECRET_LEN] {
    let mut ikm = [0u8; 128];
    ikm[..32].copy_from_slice(dh1);
    ikm[32..64].copy_from_slice(dh2);
    ikm[64..96].copy_from_slice(dh3);
    ikm[96..].copy_from_slice(pq_ss);

    let zero_salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&zero_salt[..]), &ikm[..]);
    let mut sk = [0u8; SHARED_SECRET_LEN];
    hk.expand(X3DH_INFO_OTPK_PQ, &mut sk)
        .expect("32 bytes is well within HKDF-SHA256's output budget");

    ikm.zeroize();
    sk
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn both_sides_derive_the_same_secret() {
        let initiator_id = StaticSecret::random_from_rng(OsRng);
        let initiator_id_pub = PublicKey::from(&initiator_id);

        let responder_spk = StaticSecret::random_from_rng(OsRng);
        let responder_spk_pub = PublicKey::from(&responder_spk);

        let (eph_pub, sk_initiator) = initiator_derive(&initiator_id, &responder_spk_pub);
        let sk_responder = responder_derive(&responder_spk, &eph_pub, &initiator_id_pub);

        assert_eq!(sk_initiator, sk_responder);
    }

    #[test]
    fn different_responders_yield_different_secrets() {
        // Same initiator, two different responders → two different SKs.
        let initiator_id = StaticSecret::random_from_rng(OsRng);

        let alice_spk = StaticSecret::random_from_rng(OsRng);
        let bob_spk = StaticSecret::random_from_rng(OsRng);

        let (_, sk_alice) = initiator_derive(&initiator_id, &PublicKey::from(&alice_spk));
        let (_, sk_bob) = initiator_derive(&initiator_id, &PublicKey::from(&bob_spk));

        assert_ne!(sk_alice, sk_bob);
    }

    #[test]
    fn wrong_initiator_identity_at_responder_yields_different_secret() {
        // The responder is told initiator's identity but is given the wrong
        // one. Both sides "succeed" cryptographically but derive different
        // secrets — the very next ratchet message will fail AEAD, which is
        // exactly the desired authentication property.
        let real_initiator_id = StaticSecret::random_from_rng(OsRng);
        let fake_initiator_id = StaticSecret::random_from_rng(OsRng);

        let responder_spk = StaticSecret::random_from_rng(OsRng);
        let responder_spk_pub = PublicKey::from(&responder_spk);

        let (eph_pub, sk_real) =
            initiator_derive(&real_initiator_id, &responder_spk_pub);

        let sk_fake = responder_derive(
            &responder_spk,
            &eph_pub,
            &PublicKey::from(&fake_initiator_id),
        );

        assert_ne!(sk_real, sk_fake);
    }

    #[test]
    fn ephemeral_is_used_only_once() {
        // Two invocations with the same identities must produce different
        // shared secrets, because each call generates a fresh ephemeral.
        let initiator_id = StaticSecret::random_from_rng(OsRng);
        let responder_spk = StaticSecret::random_from_rng(OsRng);
        let responder_spk_pub = PublicKey::from(&responder_spk);

        let (_, sk1) = initiator_derive(&initiator_id, &responder_spk_pub);
        let (_, sk2) = initiator_derive(&initiator_id, &responder_spk_pub);

        assert_ne!(sk1, sk2);
    }

    // ---- 3-DH variant (with OTPK) ----

    #[test]
    fn otpk_both_sides_derive_the_same_secret() {
        let initiator_id = StaticSecret::random_from_rng(OsRng);
        let initiator_id_pub = PublicKey::from(&initiator_id);

        let responder_spk = StaticSecret::random_from_rng(OsRng);
        let responder_spk_pub = PublicKey::from(&responder_spk);

        let responder_otpk = StaticSecret::random_from_rng(OsRng);
        let responder_otpk_pub = PublicKey::from(&responder_otpk);

        let (eph_pub, sk_i) = initiator_derive_with_otpk(
            &initiator_id,
            &responder_spk_pub,
            &responder_otpk_pub,
        );
        let sk_r = responder_derive_with_otpk(
            &responder_spk,
            &responder_otpk,
            &eph_pub,
            &initiator_id_pub,
        );
        assert_eq!(sk_i, sk_r);
    }

    #[test]
    fn otpk_variant_and_plain_variant_differ() {
        // Same inputs through 2-DH vs 3-DH must yield different secrets
        // — the domain-separator tags guarantee this.
        let initiator_id = StaticSecret::random_from_rng(OsRng);
        let responder_spk = StaticSecret::random_from_rng(OsRng);
        let responder_spk_pub = PublicKey::from(&responder_spk);
        let responder_otpk = StaticSecret::random_from_rng(OsRng);
        let responder_otpk_pub = PublicKey::from(&responder_otpk);

        let (_, sk_2dh) = initiator_derive(&initiator_id, &responder_spk_pub);
        let (_, sk_3dh) = initiator_derive_with_otpk(
            &initiator_id,
            &responder_spk_pub,
            &responder_otpk_pub,
        );
        assert_ne!(sk_2dh, sk_3dh);
    }

    // ---- Phase 2 PQ-X3DH hybrid ----

    #[test]
    fn pq_encap_decap_roundtrip() {
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
        let (dk, ek) = MlKem768::generate(&mut rand::rngs::OsRng);
        let ek_bytes = ek.as_bytes().to_vec();
        let dk_bytes = dk.as_bytes().to_vec();

        let (ct, ss_send) = pq_encapsulate(&ek_bytes).expect("encap ok");
        assert_eq!(ct.len(), ML_KEM_CT_LEN);
        let ss_recv = pq_decapsulate(&dk_bytes, &ct).expect("decap ok");
        assert_eq!(ss_send, ss_recv);
    }

    #[test]
    fn pq_decap_with_wrong_dk_yields_different_secret() {
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
        let (_dk_real, ek) = MlKem768::generate(&mut rand::rngs::OsRng);
        let (dk_wrong, _ek_wrong) = MlKem768::generate(&mut rand::rngs::OsRng);
        let ek_bytes = ek.as_bytes().to_vec();
        let dk_wrong_bytes = dk_wrong.as_bytes().to_vec();

        let (ct, ss_send) = pq_encapsulate(&ek_bytes).unwrap();
        // ML-KEM is IND-CCA-secure: a wrong dk implicitly returns a
        // pseudorandom ss (not an error). So decap "succeeds" but
        // yields a different secret. Same property Signal/iMessage rely
        // on for downgrade safety.
        let ss_other = pq_decapsulate(&dk_wrong_bytes, &ct).unwrap();
        assert_ne!(ss_send, ss_other);
    }

    #[test]
    fn hybrid_2dh_both_sides_match() {
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
        let initiator_id = StaticSecret::random_from_rng(OsRng);
        let initiator_id_pub = PublicKey::from(&initiator_id);
        let responder_spk = StaticSecret::random_from_rng(OsRng);
        let responder_spk_pub = PublicKey::from(&responder_spk);

        let (dk, ek) = MlKem768::generate(&mut rand::rngs::OsRng);
        let (ct, ss_i) = pq_encapsulate(&ek.as_bytes().to_vec()).unwrap();
        let ss_r = pq_decapsulate(&dk.as_bytes().to_vec(), &ct).unwrap();

        let (eph_pub, sk_i) = initiator_derive_hybrid(&initiator_id, &responder_spk_pub, &ss_i);
        let sk_r = responder_derive_hybrid(
            &responder_spk,
            &eph_pub,
            &initiator_id_pub,
            &ss_r,
        );
        assert_eq!(sk_i, sk_r);
    }

    #[test]
    fn hybrid_differs_from_classical_with_same_x25519_inputs() {
        // The PQ-info-tag must produce a different SK from the
        // classical X3DH with the same X25519 inputs. If they were
        // equal, a downgrade attacker could derive the hybrid SK
        // without knowing the PQ material.
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
        let initiator_id = StaticSecret::random_from_rng(OsRng);
        let responder_spk = StaticSecret::random_from_rng(OsRng);
        let responder_spk_pub = PublicKey::from(&responder_spk);

        let (_, sk_classical) = initiator_derive(&initiator_id, &responder_spk_pub);

        let (dk, ek) = MlKem768::generate(&mut rand::rngs::OsRng);
        let (_, ss) = pq_encapsulate(&ek.as_bytes().to_vec()).unwrap();
        let _ = dk; // ensure dk holds (unused; we only need the ss)
        let (_, sk_hybrid) = initiator_derive_hybrid(&initiator_id, &responder_spk_pub, &ss);

        assert_ne!(sk_classical, sk_hybrid);
    }

    #[test]
    fn hybrid_3dh_with_otpk_both_sides_match() {
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
        let initiator_id = StaticSecret::random_from_rng(OsRng);
        let initiator_id_pub = PublicKey::from(&initiator_id);
        let responder_spk = StaticSecret::random_from_rng(OsRng);
        let responder_spk_pub = PublicKey::from(&responder_spk);
        let responder_otpk = StaticSecret::random_from_rng(OsRng);
        let responder_otpk_pub = PublicKey::from(&responder_otpk);

        let (dk, ek) = MlKem768::generate(&mut rand::rngs::OsRng);
        let (ct, ss_i) = pq_encapsulate(&ek.as_bytes().to_vec()).unwrap();
        let ss_r = pq_decapsulate(&dk.as_bytes().to_vec(), &ct).unwrap();

        let (eph_pub, sk_i) = initiator_derive_with_otpk_hybrid(
            &initiator_id,
            &responder_spk_pub,
            &responder_otpk_pub,
            &ss_i,
        );
        let sk_r = responder_derive_with_otpk_hybrid(
            &responder_spk,
            &responder_otpk,
            &eph_pub,
            &initiator_id_pub,
            &ss_r,
        );
        assert_eq!(sk_i, sk_r);
    }

    #[test]
    fn hybrid_2dh_and_3dh_pq_differ() {
        // Same classical inputs, same PQ secret, but 2-DH vs 3-DH PQ
        // domain separators differ → different SK.
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
        let initiator_id = StaticSecret::random_from_rng(OsRng);
        let responder_spk = StaticSecret::random_from_rng(OsRng);
        let responder_spk_pub = PublicKey::from(&responder_spk);
        let responder_otpk = StaticSecret::random_from_rng(OsRng);
        let responder_otpk_pub = PublicKey::from(&responder_otpk);

        let (_dk, ek) = MlKem768::generate(&mut rand::rngs::OsRng);
        let (_ct, ss) = pq_encapsulate(&ek.as_bytes().to_vec()).unwrap();

        let (_, sk_2dh) = initiator_derive_hybrid(&initiator_id, &responder_spk_pub, &ss);
        let (_, sk_3dh) = initiator_derive_with_otpk_hybrid(
            &initiator_id,
            &responder_spk_pub,
            &responder_otpk_pub,
            &ss,
        );
        assert_ne!(sk_2dh, sk_3dh);
    }

    #[test]
    fn otpk_wrong_otpk_at_responder_yields_different_secret() {
        let initiator_id = StaticSecret::random_from_rng(OsRng);
        let initiator_id_pub = PublicKey::from(&initiator_id);

        let responder_spk = StaticSecret::random_from_rng(OsRng);
        let responder_spk_pub = PublicKey::from(&responder_spk);

        let real_otpk = StaticSecret::random_from_rng(OsRng);
        let real_otpk_pub = PublicKey::from(&real_otpk);
        let other_otpk = StaticSecret::random_from_rng(OsRng);

        let (eph_pub, sk_i) = initiator_derive_with_otpk(
            &initiator_id,
            &responder_spk_pub,
            &real_otpk_pub,
        );
        // Responder mixes up which OTPK was consumed.
        let sk_r = responder_derive_with_otpk(
            &responder_spk,
            &other_otpk,
            &eph_pub,
            &initiator_id_pub,
        );
        assert_ne!(sk_i, sk_r);
    }
}
