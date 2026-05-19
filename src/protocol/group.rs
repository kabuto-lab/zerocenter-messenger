//! Group-chat protocol surface. Phase 5, Megolm-style.
//!
//! This file holds only the foundational types that the storage and
//! crypto modules share. The wire-form control envelopes
//! (MembershipUpdate, SenderKeyDistribution, GroupMessage) are layered
//! in subsequent commits and intentionally not present here yet.

use serde::{Deserialize, Serialize};

/// Group identifier. 32 random bytes generated at create time. Renders
/// as a 64-char hex string when surfaced to a UI; opaque otherwise.
///
/// Why a random id rather than a hash of founder+timestamp: a hash
/// would leak the founder's identity to any observer who guessed the
/// preimage. Pure random gives an unlinkable identifier.
pub type GroupId = [u8; 32];

/// Domain separator for founder Ed25519 signatures on group-control
/// messages. Distinct from the per-message DM separator so a signature
/// produced under the DM path cannot be replayed as a membership-
/// update authorisation, and vice versa (INVARIANTS §1 hygiene).
pub const GROUP_CTRL_DOMAIN_SEPARATOR: &[u8] = b"zerocenter-group-ctrl-v1";

/// Domain separator for per-message Ed25519 signatures inside the
/// Megolm sender-chain. Distinct from the founder-control separator
/// (above) AND from the DM separator: a per-message group signature
/// cannot be replayed as a control-message authorisation, and a
/// founder-issued control signature cannot be replayed as a member's
/// per-message signature even when the signer happens to be the same
/// principal.
pub const GROUP_MSG_DOMAIN_SEPARATOR: &[u8] = b"zerocenter-group-msg-v1";

/// In-memory representation of a `groups` table row. Returned by
/// `MessageStore::group_get` and `group_list`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupRow {
    pub group_id: GroupId,
    pub name: String,
    /// PeerId bytes of the founding member. The founder is the sole
    /// authority for `MembershipUpdate` control messages (Phase 5 v0
    /// trust model — see INVARIANTS §25 once that lands).
    pub founder_pid: Vec<u8>,
    /// Monotonic counter bumped on every accepted membership update.
    /// Replay-protects out-of-order updates: a `MembershipUpdate` with
    /// `epoch <= our_epoch` is rejected.
    pub epoch: u64,
    pub created_at: i64,
}

/// In-memory representation of a `group_messages` table row.
#[derive(Debug, Clone)]
pub struct GroupStoredMessage {
    pub id: i64,
    pub group_id: GroupId,
    /// PeerId bytes of the sender.
    pub sender: Vec<u8>,
    /// Decrypted plaintext. The `ciphertext` column on disk is
    /// AEAD-wrapped under the DEK and unwrapped by the loader; this
    /// field already holds the cleartext.
    pub plaintext: Vec<u8>,
    pub timestamp: i64,
    pub ttl: i64,
}
