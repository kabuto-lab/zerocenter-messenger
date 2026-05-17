use libp2p::identity::Keypair;
use crate::core::Identity;

pub mod keyring;
pub mod ratchet;
pub mod x3dh;

/// Convert our identity to a libp2p keypair (already stored in Identity)
pub fn to_libp2p_keypair(identity: &Identity) -> Keypair {
    identity.keypair().clone()
}
