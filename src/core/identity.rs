use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};
use libp2p::PeerId;
use libp2p::identity::Keypair;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

/// Long-term identity for a peer
#[derive(Clone)]
pub struct Identity {
    /// Ed25519 signing key (never transmitted)
    signing_key: SigningKey,
    /// Corresponding verifying key (shared with others)
    verifying_key: VerifyingKey,
    /// Cached peer ID
    peer_id: PeerId,
    /// libp2p keypair
    keypair: Keypair,
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    private_key: [u8; 32],
    public_key: [u8; 32],
}

impl Identity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let keypair = Keypair::ed25519_from_bytes(signing_key.to_bytes())
            .expect("Valid ed25519 key");
        let peer_id = PeerId::from(keypair.public());
        
        info!("Generated new identity: {}", peer_id);
        
        Self {
            signing_key,
            verifying_key,
            peer_id,
            keypair,
        }
    }

    /// Load identity from disk, or create new if not exists
    pub fn load_or_create<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let key_path = data_dir.as_ref().join("identity.json");
        
        if key_path.exists() {
            // Load existing identity
            let data = std::fs::read_to_string(&key_path)?;
            let identity_file: IdentityFile = serde_json::from_str(&data)?;
            
            let signing_key = SigningKey::from_bytes(&identity_file.private_key);
            let verifying_key = signing_key.verifying_key();
            let keypair = Keypair::ed25519_from_bytes(signing_key.to_bytes())
                .expect("Valid ed25519 key");
            let peer_id = PeerId::from(keypair.public());
            
            info!("Loaded identity: {}", peer_id);
            
            Ok(Self {
                signing_key,
                verifying_key,
                peer_id,
                keypair,
            })
        } else {
            // Create new identity
            let identity = Self::generate();
            identity.save(&data_dir)?;
            Ok(identity)
        }
    }

    /// Save identity to disk
    pub fn save<P: AsRef<Path>>(&self, data_dir: P) -> Result<()> {
        let key_path = data_dir.as_ref().join("identity.json");
        
        let identity_file = IdentityFile {
            private_key: self.signing_key.to_bytes(),
            public_key: self.verifying_key.to_bytes(),
        };
        
        let data = serde_json::to_string_pretty(&identity_file)?;
        std::fs::write(key_path, data)?;
        
        // Set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(key_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(key_path, perms)?;
        }
        
        Ok(())
    }

    /// Get the peer ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Sign data with identity key
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }

    /// Get the verifying key (for sharing)
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// Get the signing key reference
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get libp2p keypair
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}
