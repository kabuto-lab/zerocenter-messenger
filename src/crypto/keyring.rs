//! Per-profile data-encryption-key (DEK) management.
//!
//! The DEK is a 32-byte random symmetric key used to AEAD-encrypt all
//! at-rest blobs (ratchet sessions today; more later). It is **stored in
//! the OS-native secret store** so the bytes never touch disk in our
//! data directory:
//!
//! - **Windows:** Credential Manager (DPAPI-backed).
//! - **macOS:** Keychain.
//! - **Linux:** Secret Service via dbus (gnome-keyring, kwallet, ...).
//!
//! Service / account convention:
//! - service = `"ME55-messenger"` (constant)
//! - account = the profile name (e.g. `"alice"`)
//!
//! The DEK is encoded as lowercase hex (64 chars) inside the keyring.

use anyhow::{anyhow, Result};
use rand::RngCore;
use tracing::{info, warn};

const KEYRING_SERVICE: &str = "ME55-messenger";
const DEK_LEN: usize = 32;

/// Look up the DEK for `profile`. If none is stored yet, generate a fresh
/// 32-byte random DEK and persist it under the OS keyring.
///
/// On a system where the OS keyring is unreachable (e.g. headless Linux
/// with no secret-service daemon), this returns the same fresh DEK but
/// **without persisting it** and emits a loud warning. The implication:
/// every restart will produce a different DEK, so any encrypted-at-rest
/// blobs become unreadable. That's a deliberate "fail loud" — silently
/// falling back to plaintext-at-rest would be worse.
pub fn load_or_create_dek(profile: &str) -> Result<[u8; DEK_LEN]> {
    let entry = match keyring::Entry::new(KEYRING_SERVICE, profile) {
        Ok(e) => e,
        Err(e) => {
            warn!(
                "OS keyring unavailable ({}). At-rest encryption will use \
                 an ephemeral DEK — any persisted ratchet sessions will be \
                 unrecoverable after restart.",
                e
            );
            return Ok(random_dek());
        }
    };

    match entry.get_password() {
        Ok(hex_str) => {
            let bytes = hex::decode(hex_str.trim())
                .map_err(|e| anyhow!("DEK in keyring is not valid hex: {}", e))?;
            if bytes.len() != DEK_LEN {
                return Err(anyhow!(
                    "DEK in keyring has wrong length {} (expected {})",
                    bytes.len(),
                    DEK_LEN
                ));
            }
            let mut dek = [0u8; DEK_LEN];
            dek.copy_from_slice(&bytes);
            info!("Loaded DEK from OS keyring for profile '{}'", profile);
            Ok(dek)
        }
        Err(keyring::Error::NoEntry) => {
            let dek = random_dek();
            let encoded = hex::encode(dek);
            entry
                .set_password(&encoded)
                .map_err(|e| anyhow!("Failed to store DEK in OS keyring: {}", e))?;
            info!(
                "Generated new DEK and stored in OS keyring for profile '{}'",
                profile
            );
            Ok(dek)
        }
        Err(e) => {
            warn!(
                "OS keyring read failed ({}); using ephemeral DEK. Persisted \
                 ratchet sessions will not survive restart.",
                e
            );
            Ok(random_dek())
        }
    }
}

fn random_dek() -> [u8; DEK_LEN] {
    let mut dek = [0u8; DEK_LEN];
    rand::rngs::OsRng.fill_bytes(&mut dek);
    dek
}
