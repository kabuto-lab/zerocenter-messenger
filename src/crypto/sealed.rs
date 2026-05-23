//! Phase 5 sealed-sender envelope.
//!
//! Encrypts a "sender certificate" (sender PeerId + signature) to the
//! recipient's long-term X25519 prekey using a per-message ephemeral.
//! The recipient is the only party who can recover the sender's
//! identity; transport-level observers (relays, DHT-mailbox providers,
//! intermediate libp2p nodes) see only the recipient PeerId and the
//! (encrypted) payload, not the sender's PeerId.
//!
//! ## Wire layout
//!
//! ```text
//!   [ephemeral_x25519_pub: 32 bytes] [aead_ciphertext: variable]
//! ```
//!
//! ## Crypto details
//!
//! - Sender picks ephemeral X25519 `(e_priv, e_pub)`.
//! - `shared = X25519(e_priv, recipient_x25519_pub)`. Refused if zero
//!   (low-order pubkey defence; audit F2 hygiene).
//! - `(key, nonce) = HKDF-SHA256(salt="ME55-sealed-sender-v1",
//!                                ikm=shared, info="chacha-key-nonce")`,
//!   44-byte expansion split into 32-byte key + 12-byte nonce.
//! - Encrypt `sender_cert` with ChaCha20-Poly1305 under `(key, nonce)`,
//!   empty AAD.
//!
//! The HKDF binds `(key, nonce)` to the ephemeral, so the per-message
//! AEAD nonce is fresh even though we don't carry an explicit nonce on
//! the wire. As long as the OS RNG produces unique ephemerals (which it
//! does under any reasonable failure model), there is no nonce reuse.
//!
//! ## Forward secrecy
//!
//! The ephemeral private key is generated at send time, used once for
//! the X25519 DH, and dropped before the function returns. A later
//! compromise of the recipient's X25519 prekey does NOT let an attacker
//! decrypt past sealed envelopes — they would also need the ephemeral
//! private, which is gone.
//!
//! ## What the seal does NOT do
//!
//! - Authenticate the sender. That's the responsibility of the
//!   Ed25519 signature carried INSIDE the cert plaintext; this module
//!   only carries the cert bytes through encryption transparently.
//! - Hide the recipient. The outer `to` field of the `ProtocolMessage`
//!   stays clear because it's needed for libp2p routing. Hiding the
//!   recipient requires onion routing (out of scope).
//! - Hide the fact that ME55 traffic is happening. That's
//!   `ScrambleStream`'s job (`--obfs-key` flag).

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key as ChaChaKey, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const HKDF_SALT: &[u8] = b"ME55-sealed-sender-v1";
const HKDF_INFO: &[u8] = b"chacha-key-nonce";

/// Encrypt `sender_cert` to `recipient_x25519_pub`. See the module
/// docstring for the wire layout. `sender_cert` is opaque to this
/// function — the caller is responsible for its structure (typically
/// `sender_pid_bytes || signature_bytes`, length-prefixed).
pub fn seal_sender_cert(
    recipient_x25519_pub: &[u8; 32],
    sender_cert: &[u8],
) -> Result<Vec<u8>> {
    let mut eph_priv_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut eph_priv_bytes);
    let eph_priv = StaticSecret::from(eph_priv_bytes);
    let eph_pub = PublicKey::from(&eph_priv);

    let recipient_pub = PublicKey::from(*recipient_x25519_pub);
    let shared = eph_priv.diffie_hellman(&recipient_pub);

    if shared.as_bytes() == &[0u8; 32] {
        return Err(anyhow!(
            "sealed-sender X25519 shared secret collapsed to zero — recipient pubkey may be low-order"
        ));
    }

    let (key, nonce) = hkdf_derive(shared.as_bytes())?;
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: sender_cert,
                aad: &[],
            },
        )
        .map_err(|e| anyhow!("sealed AEAD encrypt failed: {}", e))?;

    let mut out = Vec::with_capacity(32 + ct.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a sealed envelope using the recipient's X25519 prekey
/// private. Returns the opaque `sender_cert` bytes; the caller must
/// parse and verify its inner signature.
pub fn unseal_sender_cert(
    recipient_x25519_priv: &StaticSecret,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    if sealed.len() < 32 + 16 {
        return Err(anyhow!(
            "sealed envelope too short ({} bytes; minimum 32 + 16)",
            sealed.len()
        ));
    }
    let mut eph_pub_bytes = [0u8; 32];
    eph_pub_bytes.copy_from_slice(&sealed[..32]);
    let eph_pub = PublicKey::from(eph_pub_bytes);
    let ct = &sealed[32..];

    let shared = recipient_x25519_priv.diffie_hellman(&eph_pub);
    if shared.as_bytes() == &[0u8; 32] {
        return Err(anyhow!(
            "sealed-sender X25519 shared secret collapsed to zero — peer ephemeral may be low-order"
        ));
    }

    let (key, nonce) = hkdf_derive(shared.as_bytes())?;
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&key));
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ct,
                aad: &[],
            },
        )
        .map_err(|e| anyhow!("sealed AEAD decrypt failed: {}", e))?;
    Ok(pt)
}

fn hkdf_derive(shared: &[u8]) -> Result<([u8; 32], [u8; 12])> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared);
    let mut okm = [0u8; 44];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|e| anyhow!("HKDF expand: {}", e))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&okm[32..]);
    Ok((key, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_keypair() -> (StaticSecret, [u8; 32]) {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let priv_k = StaticSecret::from(bytes);
        let pub_k = PublicKey::from(&priv_k);
        (priv_k, *pub_k.as_bytes())
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let (recipient_priv, recipient_pub) = random_keypair();
        let cert = b"sender-pid-bytes-and-signature-bytes-go-here-opaquely";

        let sealed = seal_sender_cert(&recipient_pub, cert).unwrap();
        // 32 ephemeral + 16 tag minimum; cert.len() of plaintext.
        assert!(sealed.len() >= 32 + 16 + cert.len());

        let recovered = unseal_sender_cert(&recipient_priv, &sealed).unwrap();
        assert_eq!(recovered, cert);
    }

    #[test]
    fn unseal_with_wrong_key_fails() {
        let (_correct_priv, recipient_pub) = random_keypair();
        let (wrong_priv, _) = random_keypair();
        let cert = b"do not leak";

        let sealed = seal_sender_cert(&recipient_pub, cert).unwrap();
        let result = unseal_sender_cert(&wrong_priv, &sealed);
        assert!(result.is_err(), "wrong key must fail AEAD verify");
    }

    #[test]
    fn tampered_ciphertext_fails_aead() {
        let (recipient_priv, recipient_pub) = random_keypair();
        let cert = b"original cert content";

        let mut sealed = seal_sender_cert(&recipient_pub, cert).unwrap();
        // Flip a bit in the AEAD ciphertext (skip past the 32-byte
        // ephemeral pubkey).
        let i = 35;
        sealed[i] ^= 0x01;
        let result = unseal_sender_cert(&recipient_priv, &sealed);
        assert!(result.is_err(), "tampered ciphertext must fail AEAD verify");
    }

    #[test]
    fn tampered_ephemeral_pubkey_fails() {
        let (recipient_priv, recipient_pub) = random_keypair();
        let cert = b"original";

        let mut sealed = seal_sender_cert(&recipient_pub, cert).unwrap();
        // Flip a bit in the ephemeral pubkey.
        sealed[5] ^= 0x01;
        let result = unseal_sender_cert(&recipient_priv, &sealed);
        assert!(result.is_err(), "tampered ephemeral must yield wrong shared secret → AEAD fail");
    }

    #[test]
    fn too_short_input_returns_error() {
        let (recipient_priv, _) = random_keypair();
        let result = unseal_sender_cert(&recipient_priv, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn two_seals_of_same_cert_produce_different_wire_bytes() {
        // Different ephemerals → different ciphertexts. Confirms the
        // RNG actually varies between calls and the wire is not
        // deterministic for the same input.
        let (_, recipient_pub) = random_keypair();
        let cert = b"same plaintext, twice";
        let s1 = seal_sender_cert(&recipient_pub, cert).unwrap();
        let s2 = seal_sender_cert(&recipient_pub, cert).unwrap();
        assert_ne!(s1, s2, "two seals must differ — fresh ephemerals");
    }
}
