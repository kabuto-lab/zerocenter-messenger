use libp2p::identity::Keypair;
use crate::core::Identity;

/// Convert our identity to a libp2p keypair (already stored in Identity)
pub fn to_libp2p_keypair(identity: &Identity) -> Keypair {
    identity.keypair().clone()
}
