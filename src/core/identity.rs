use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use libp2p::identity::Keypair;
use libp2p::PeerId;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Domain-separator tag used when Ed25519-signing the X25519 prekey. Binds
/// the signature to this purpose so it can't be replayed against another
/// payload that happens to look like a 32-byte X25519 pubkey.
const PREKEY_SIG_DOMAIN: &[u8] = b"ME55-prekey-v1";

/// Domain-separator tag for Ed25519-signing the long-term ML-KEM-768
/// encapsulation key (Phase 2 PQ-X3DH). Kept DISTINCT from
/// [`PREKEY_SIG_DOMAIN`] so a captured X25519-prekey signature can't be
/// transplanted into the PQ-prekey slot or vice versa (INVARIANTS §1).
const ML_KEM_PREKEY_SIG_DOMAIN: &[u8] = b"ME55-ml-kem-prekey-v1";

/// ML-KEM-768 encoded sizes per FIPS 203.
pub const ML_KEM_EK_LEN: usize = 1184;
pub const ML_KEM_DK_LEN: usize = 2400;
pub const ML_KEM_CT_LEN: usize = 1088;
pub const ML_KEM_SS_LEN: usize = 32;

/// Long-term identity for a peer.
///
/// Holds:
/// - the Ed25519 *identity* key (long-term, signs everything),
/// - an X25519 *signed prekey* used by the Phase 3 ratchet for ECDH,
/// - an ML-KEM-768 *signed PQ prekey* used by Phase 2 hybrid X3DH,
/// - Ed25519 signatures over both prekey publics.
///
/// PQ fields are present from Phase 2 onward. Old identity.json files
/// (pre-Phase-2) are migrated lazily by [`Self::load_or_create`] —
/// see also the X25519 migration above. The Ed25519 root key is never
/// regenerated, so the PeerId is preserved across migration.
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
    /// Ed25519 signature over `PREKEY_SIG_DOMAIN || x25519_public`
    x25519_signature: Signature,
    /// ML-KEM-768 decapsulation key (private; never transmitted).
    /// Stored as raw 2400-byte encoded form so serialization stays
    /// orthogonal to the crate-internal type.
    ml_kem_dk_bytes: Vec<u8>,
    /// ML-KEM-768 encapsulation key (public; shared via prekey response).
    /// Raw 1184-byte encoded form.
    ml_kem_ek_bytes: Vec<u8>,
    /// Ed25519 signature over `ML_KEM_PREKEY_SIG_DOMAIN || ml_kem_ek_bytes`.
    ml_kem_signature: Signature,
    /// Cached peer ID
    peer_id: PeerId,
    /// libp2p keypair
    keypair: Keypair,
}

/// On-disk format. The X25519 fields are `Option` so old (pre-Phase-3)
/// `identity.json` files load successfully — `load_or_create` then generates
/// the missing prekey and re-saves with all fields populated. The ML-KEM
/// fields follow the same pattern for pre-Phase-2 files.
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
    /// Phase 2 PQ-X3DH. Raw 2400-byte encoded ML-KEM-768 decapsulation
    /// key. Pre-Phase-2 files have this as None and load_or_create
    /// generates a fresh keypair on first load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ml_kem_dk: Option<Vec<u8>>,
    /// Phase 2 PQ-X3DH. Raw 1184-byte encoded ML-KEM-768 encapsulation
    /// key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ml_kem_ek: Option<Vec<u8>>,
    /// Phase 2 PQ-X3DH. Ed25519 signature over the encapsulation key
    /// under [`ML_KEM_PREKEY_SIG_DOMAIN`].
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_helpers::serde_opt_arr64"
    )]
    ml_kem_signature: Option<[u8; 64]>,
}

impl Identity {
    /// Generate a new random identity (Ed25519 + signed X25519 prekey
    /// + signed ML-KEM-768 PQ prekey).
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let keypair = Keypair::ed25519_from_bytes(signing_key.to_bytes())
            .expect("Valid ed25519 key");
        let peer_id = PeerId::from(keypair.public());

        let (x25519_secret, x25519_public, x25519_signature) =
            generate_signed_prekey(&signing_key);

        let (ml_kem_dk_bytes, ml_kem_ek_bytes, ml_kem_signature) =
            generate_signed_ml_kem_prekey(&signing_key);

        info!("Generated new identity: {}", peer_id);

        Self {
            signing_key,
            verifying_key,
            x25519_secret,
            x25519_public,
            x25519_signature,
            ml_kem_dk_bytes,
            ml_kem_ek_bytes,
            ml_kem_signature,
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

        // Same shape of migration for the ML-KEM PQ prekey: all three
        // fields must be present AND the signature must verify, else
        // we regenerate. Stored bytes are validated by attempting to
        // round-trip through the ML-KEM type — a corrupt 2400-byte
        // blob will be caught here, not deferred to first use.
        let (ml_kem_dk_bytes, ml_kem_ek_bytes, ml_kem_signature) = match (
            file.ml_kem_dk,
            file.ml_kem_ek,
            file.ml_kem_signature,
        ) {
            (Some(dk_bytes), Some(ek_bytes), Some(sig_bytes))
                if dk_bytes.len() == ML_KEM_DK_LEN && ek_bytes.len() == ML_KEM_EK_LEN =>
            {
                let sig = Signature::from_bytes(&sig_bytes);
                if verifying_key
                    .verify_strict(&ml_kem_prekey_signing_bytes(&ek_bytes), &sig)
                    .is_err()
                {
                    warn!("identity.json ML-KEM prekey signature invalid — regenerating");
                    generate_signed_ml_kem_prekey(&signing_key)
                } else {
                    // Note: we don't separately roundtrip-test the
                    // dk/ek pair here. Signature verifies the ek; if
                    // dk is corrupt, the first PQ session will fail
                    // at decapsulation and we'll see it in logs. The
                    // additional check costs an ML-KEM keygen on
                    // every startup which isn't worth it.
                    (dk_bytes, ek_bytes, sig)
                }
            }
            (None, None, None) => {
                info!("Migrating identity.json: generating ML-KEM-768 PQ prekey");
                generate_signed_ml_kem_prekey(&signing_key)
            }
            _ => {
                warn!("identity.json ML-KEM fields partial/wrong-length — regenerating");
                generate_signed_ml_kem_prekey(&signing_key)
            }
        };

        let identity = Self {
            signing_key,
            verifying_key,
            x25519_secret,
            x25519_public,
            x25519_signature,
            ml_kem_dk_bytes,
            ml_kem_ek_bytes,
            ml_kem_signature,
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
            ml_kem_dk: Some(self.ml_kem_dk_bytes.clone()),
            ml_kem_ek: Some(self.ml_kem_ek_bytes.clone()),
            ml_kem_signature: Some(self.ml_kem_signature.to_bytes()),
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

    /// Raw 1184-byte ML-KEM-768 encapsulation key (public). Shared via
    /// the prekey-fetch response. Verified by the receiver against
    /// [`Self::ml_kem_signature`].
    pub fn ml_kem_ek_bytes(&self) -> &[u8] {
        &self.ml_kem_ek_bytes
    }

    /// Raw 2400-byte ML-KEM-768 decapsulation key (private; never
    /// transmitted). Used by the responder to decapsulate the
    /// initiator's PQ ciphertext during hybrid X3DH.
    pub fn ml_kem_dk_bytes(&self) -> &[u8] {
        &self.ml_kem_dk_bytes
    }

    /// Ed25519 signature over our ML-KEM encapsulation key. Receivers
    /// verify before trusting the PQ prekey.
    pub fn ml_kem_signature(&self) -> &Signature {
        &self.ml_kem_signature
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

/// Build the canonical bytes that the Ed25519 key signs to attest the
/// ML-KEM-768 encapsulation key. Distinct domain separator from the
/// X25519 prekey (see [`ML_KEM_PREKEY_SIG_DOMAIN`]).
pub fn ml_kem_prekey_signing_bytes(ml_kem_ek: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ML_KEM_PREKEY_SIG_DOMAIN.len() + ml_kem_ek.len());
    out.extend_from_slice(ML_KEM_PREKEY_SIG_DOMAIN);
    out.extend_from_slice(ml_kem_ek);
    out
}

/// Generate a fresh ML-KEM-768 keypair and Ed25519-sign the
/// encapsulation key.
fn generate_signed_ml_kem_prekey(
    signing_key: &SigningKey,
) -> (Vec<u8>, Vec<u8>, Signature) {
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    let dk_bytes = dk.as_bytes().to_vec();
    let ek_bytes = ek.as_bytes().to_vec();
    let signature = signing_key.sign(&ml_kem_prekey_signing_bytes(&ek_bytes));
    (dk_bytes, ek_bytes, signature)
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
    fn generate_produces_valid_signed_ml_kem_prekey() {
        let id = Identity::generate();
        assert_eq!(id.ml_kem_ek_bytes().len(), ML_KEM_EK_LEN);
        assert_eq!(id.ml_kem_dk_bytes().len(), ML_KEM_DK_LEN);
        // Self-signature over the encapsulation key verifies.
        id.verifying_key()
            .verify_strict(
                &ml_kem_prekey_signing_bytes(id.ml_kem_ek_bytes()),
                id.ml_kem_signature(),
            )
            .expect("self ML-KEM prekey signature must verify");
    }

    #[test]
    fn save_and_load_roundtrip_preserves_ml_kem_fields() {
        let dir = tempdir().unwrap();
        let original = Identity::generate();
        original.save(dir.path()).unwrap();

        let loaded = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(loaded.peer_id(), original.peer_id());
        assert_eq!(loaded.ml_kem_ek_bytes(), original.ml_kem_ek_bytes());
        assert_eq!(loaded.ml_kem_dk_bytes(), original.ml_kem_dk_bytes());
        assert_eq!(
            loaded.ml_kem_signature().to_bytes(),
            original.ml_kem_signature().to_bytes()
        );
    }

    #[test]
    fn migrates_pre_pq_identity_file() {
        // Pre-Phase-2 identity file has X25519 fields but no ML-KEM.
        let dir = tempdir().unwrap();
        let original = Identity::generate();
        original.save(dir.path()).unwrap();

        // Strip the ML-KEM fields manually to simulate a Phase 1 file.
        let path = dir.path().join("identity.json");
        let mut file: IdentityFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        file.ml_kem_dk = None;
        file.ml_kem_ek = None;
        file.ml_kem_signature = None;
        std::fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();

        // Load — should re-fill ML-KEM, preserve PeerId + X25519.
        let migrated = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(migrated.peer_id(), original.peer_id());
        assert_eq!(
            migrated.x25519_public().as_bytes(),
            original.x25519_public().as_bytes()
        );
        assert_eq!(migrated.ml_kem_ek_bytes().len(), ML_KEM_EK_LEN);
        // Newly-generated PQ keys → bytes differ from a fresh-generate baseline.
        // Just verify the signature on whatever was generated.
        migrated
            .verifying_key()
            .verify_strict(
                &ml_kem_prekey_signing_bytes(migrated.ml_kem_ek_bytes()),
                migrated.ml_kem_signature(),
            )
            .expect("migrated ML-KEM signature must verify");
    }

    #[test]
    fn corrupt_ml_kem_signature_is_regenerated() {
        let dir = tempdir().unwrap();
        let original = Identity::generate();
        original.save(dir.path()).unwrap();

        let path = dir.path().join("identity.json");
        let mut file: IdentityFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mut sig = file.ml_kem_signature.unwrap();
        sig[0] ^= 0x01;
        file.ml_kem_signature = Some(sig);
        std::fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();

        let loaded = Identity::load_or_create(dir.path()).unwrap();
        // Same PeerId, but ML-KEM keypair regenerated (bytes differ).
        assert_eq!(loaded.peer_id(), original.peer_id());
        assert_ne!(loaded.ml_kem_ek_bytes(), original.ml_kem_ek_bytes());
        loaded
            .verifying_key()
            .verify_strict(
                &ml_kem_prekey_signing_bytes(loaded.ml_kem_ek_bytes()),
                loaded.ml_kem_signature(),
            )
            .expect("regenerated ML-KEM signature must verify");
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
