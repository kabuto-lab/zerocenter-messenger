use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use libp2p::identity::Keypair;
use libp2p::PeerId;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Domain-separator tag used when Ed25519-signing the X25519 prekey. Binds
/// the signature to this purpose so it can't be replayed against another
/// payload that happens to look like a 32-byte X25519 pubkey.
const PREKEY_SIG_DOMAIN: &[u8] = b"ME55-prekey-v1";

/// Long-term identity for a peer.
///
/// Holds:
/// - the Ed25519 *identity* key (long-term, signs everything),
/// - an X25519 *signed prekey* used by the Phase 3 ratchet for ECDH,
/// - the Ed25519 signature over the X25519 pubkey (so anyone holding the
///   PeerId can verify the prekey is authentic without an out-of-band step).
#[derive(Clone)]
pub struct Identity {
    /// Ed25519 signing key (never transmitted)
    signing_key: SigningKey,
    /// Corresponding verifying key (shared with others)
    verifying_key: VerifyingKey,
    /// X25519 long-term prekey secret (never transmitted)
    x25519_secret: X25519Secret,
    /// X25519 prekey pubkey (shared on request)
    x25519_public: X25519Public,
    /// Ed25519 signature over `DOMAIN || x25519_public`
    x25519_signature: Signature,
    /// Cached peer ID
    peer_id: PeerId,
    /// libp2p keypair
    keypair: Keypair,
}

/// On-disk format. The X25519 fields are `Option` so old (pre-Phase-3)
/// `identity.json` files load successfully — `load_or_create` then generates
/// the missing prekey and re-saves with all fields populated.
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    private_key: [u8; 32],
    public_key: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x25519_private: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x25519_public: Option<[u8; 32]>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_helpers::serde_opt_arr64"
    )]
    x25519_signature: Option<[u8; 64]>,
}

impl Identity {
    /// Generate a new random identity (Ed25519 + signed X25519 prekey).
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let keypair = Keypair::ed25519_from_bytes(signing_key.to_bytes())
            .expect("Valid ed25519 key");
        let peer_id = PeerId::from(keypair.public());

        let (x25519_secret, x25519_public, x25519_signature) =
            generate_signed_prekey(&signing_key);

        info!("Generated new identity: {}", peer_id);

        Self {
            signing_key,
            verifying_key,
            x25519_secret,
            x25519_public,
            x25519_signature,
            peer_id,
            keypair,
        }
    }

    /// Load identity from disk, or create new if not exists.
    ///
    /// If an old identity.json without the X25519 prekey is loaded, a fresh
    /// prekey is generated, signed, and written back — preserving the
    /// existing PeerId. Logged as a migration so it's visible.
    pub fn load_or_create<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let key_path = data_dir.as_ref().join("identity.json");

        if !key_path.exists() {
            let identity = Self::generate();
            identity.save(&data_dir)?;
            return Ok(identity);
        }

        let data = std::fs::read_to_string(&key_path)?;
        let file: IdentityFile = serde_json::from_str(&data)?;

        let signing_key = SigningKey::from_bytes(&file.private_key);
        let verifying_key = signing_key.verifying_key();
        let keypair = Keypair::ed25519_from_bytes(signing_key.to_bytes())
            .expect("Valid ed25519 key");
        let peer_id = PeerId::from(keypair.public());

        // Migrate: generate the prekey if any of the three X25519 fields are
        // missing. We require all three to consider the prekey valid; a
        // partial file (e.g. someone hand-edited it) gets regenerated.
        let (x25519_secret, x25519_public, x25519_signature) = match (
            file.x25519_private,
            file.x25519_public,
            file.x25519_signature,
        ) {
            (Some(priv_bytes), Some(pub_bytes), Some(sig_bytes)) => {
                let secret = X25519Secret::from(priv_bytes);
                let public = X25519Public::from(pub_bytes);
                // Cross-check: derived pub must equal stored pub. Catches a
                // file where someone copied a different private key in.
                if X25519Public::from(&secret).as_bytes() != public.as_bytes() {
                    warn!("identity.json X25519 pub/priv mismatch — regenerating prekey");
                    generate_signed_prekey(&signing_key)
                } else {
                    let sig = Signature::from_bytes(&sig_bytes);
                    // Verify the signature against our own Ed25519 key — if
                    // this fails the file is corrupt or tampered. Regenerate
                    // rather than fail loudly; the PeerId is preserved.
                    if verifying_key
                        .verify_strict(&prekey_signing_bytes(public.as_bytes()), &sig)
                        .is_err()
                    {
                        warn!("identity.json X25519 signature invalid — regenerating prekey");
                        generate_signed_prekey(&signing_key)
                    } else {
                        (secret, public, sig)
                    }
                }
            }
            _ => {
                info!("Migrating identity.json: generating X25519 prekey");
                generate_signed_prekey(&signing_key)
            }
        };

        let identity = Self {
            signing_key,
            verifying_key,
            x25519_secret,
            x25519_public,
            x25519_signature,
            peer_id,
            keypair,
        };

        // Persist any migration result. Cheap if nothing changed (we always
        // write the same bytes in that case).
        identity.save(&data_dir)?;

        info!("Loaded identity: {}", peer_id);
        Ok(identity)
    }

    /// Save identity to disk.
    pub fn save<P: AsRef<Path>>(&self, data_dir: P) -> Result<()> {
        let key_path = data_dir.as_ref().join("identity.json");

        let file = IdentityFile {
            private_key: self.signing_key.to_bytes(),
            public_key: self.verifying_key.to_bytes(),
            x25519_private: Some(self.x25519_secret.to_bytes()),
            x25519_public: Some(*self.x25519_public.as_bytes()),
            x25519_signature: Some(self.x25519_signature.to_bytes()),
        };

        let data = serde_json::to_string_pretty(&file)?;
        std::fs::write(&key_path, data)?;

        // Restrict to owner read/write where the platform supports it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&key_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&key_path, perms)?;
        }

        Ok(())
    }

    /// Get the peer ID.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Sign arbitrary data with the long-term Ed25519 identity key.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }

    /// Get the Ed25519 verifying key (for sharing).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// Get the Ed25519 signing key reference.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get libp2p keypair.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Our X25519 prekey secret (for ECDH during ratchet handshake).
    pub fn x25519_secret(&self) -> &X25519Secret {
        &self.x25519_secret
    }

    /// Our X25519 prekey pubkey (shared via the prekey protocol).
    pub fn x25519_public(&self) -> &X25519Public {
        &self.x25519_public
    }

    /// Ed25519 signature over our X25519 prekey pubkey. Recipients verify
    /// this with the Ed25519 verifying key embedded in our PeerId before
    /// trusting the prekey.
    pub fn x25519_signature(&self) -> &Signature {
        &self.x25519_signature
    }
}

/// Build the canonical bytes that the Ed25519 key signs to attest the prekey.
/// Includes a domain separator so the signature isn't valid for any other
/// 32-byte payload.
pub fn prekey_signing_bytes(x25519_pub: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREKEY_SIG_DOMAIN.len() + 32);
    out.extend_from_slice(PREKEY_SIG_DOMAIN);
    out.extend_from_slice(x25519_pub);
    out
}

fn generate_signed_prekey(
    signing_key: &SigningKey,
) -> (X25519Secret, X25519Public, Signature) {
    let secret = X25519Secret::random_from_rng(OsRng);
    let public = X25519Public::from(&secret);
    let signature = signing_key.sign(&prekey_signing_bytes(public.as_bytes()));
    (secret, public, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_produces_valid_signed_prekey() {
        let id = Identity::generate();
        // Signature verifies against our own Ed25519 key.
        id.verifying_key()
            .verify_strict(
                &prekey_signing_bytes(id.x25519_public().as_bytes()),
                id.x25519_signature(),
            )
            .expect("self-signature must verify");
    }

    #[test]
    fn save_and_load_roundtrip_preserves_all_fields() {
        let dir = tempdir().unwrap();
        let original = Identity::generate();
        original.save(dir.path()).unwrap();

        let loaded = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(loaded.peer_id(), original.peer_id());
        assert_eq!(
            loaded.x25519_public().as_bytes(),
            original.x25519_public().as_bytes()
        );
        assert_eq!(
            loaded.x25519_signature().to_bytes(),
            original.x25519_signature().to_bytes()
        );
    }

    #[test]
    fn migrates_old_identity_file_without_prekey() {
        let dir = tempdir().unwrap();
        // Write an "old" identity.json (only the Ed25519 fields).
        let signing_key = SigningKey::generate(&mut OsRng);
        let old = serde_json::json!({
            "private_key": signing_key.to_bytes().to_vec(),
            "public_key": signing_key.verifying_key().to_bytes().to_vec(),
        });
        std::fs::write(
            dir.path().join("identity.json"),
            serde_json::to_string_pretty(&old).unwrap(),
        )
        .unwrap();

        // Load — should succeed AND fill in the prekey.
        let loaded = Identity::load_or_create(dir.path()).unwrap();
        loaded
            .verifying_key()
            .verify_strict(
                &prekey_signing_bytes(loaded.x25519_public().as_bytes()),
                loaded.x25519_signature(),
            )
            .expect("migrated prekey must verify");

        // PeerId is preserved across migration (only the Ed25519 key determines it).
        let expected_pid = PeerId::from(
            Keypair::ed25519_from_bytes(signing_key.to_bytes())
                .unwrap()
                .public(),
        );
        assert_eq!(loaded.peer_id(), expected_pid);

        // Re-loading hits the all-fields-present path and stays stable.
        let reloaded = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(
            reloaded.x25519_public().as_bytes(),
            loaded.x25519_public().as_bytes()
        );
    }

    #[test]
    fn corrupt_prekey_signature_is_regenerated() {
        let dir = tempdir().unwrap();
        let original = Identity::generate();
        original.save(dir.path()).unwrap();

        // Tamper: flip a bit in the saved x25519_signature.
        let path = dir.path().join("identity.json");
        let mut file: IdentityFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mut sig = file.x25519_signature.unwrap();
        sig[0] ^= 0x01;
        file.x25519_signature = Some(sig);
        std::fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();

        let loaded = Identity::load_or_create(dir.path()).unwrap();
        // Same PeerId (we kept the Ed25519 key) but the prekey is new.
        assert_eq!(loaded.peer_id(), original.peer_id());
        assert_ne!(
            loaded.x25519_signature().to_bytes(),
            original.x25519_signature().to_bytes()
        );
        // And the regenerated signature verifies.
        loaded
            .verifying_key()
            .verify_strict(
                &prekey_signing_bytes(loaded.x25519_public().as_bytes()),
                loaded.x25519_signature(),
            )
            .expect("regenerated signature must verify");
    }
}
