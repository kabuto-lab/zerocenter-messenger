//! Group-chat protocol surface. Phase 5, Megolm-style.
//!
//! This file holds:
//! - foundational types shared by storage and crypto (`GroupId`,
//!   `GroupRow`, `GroupStoredMessage`, domain separators)
//! - the wire-form `GroupControl` enum + canonical-bytes helpers +
//!   builders + verifiers used to bootstrap and mutate groups.
//!
//! `GroupMessageEnvelope` (kind=2 wire body for actual group chat
//! messages) lives in commit 4 of the group-chats track.

use libp2p::identity::Keypair;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::crypto::megolm::{EncryptedGroupMessage, SenderKeyBundle};
use crate::protocol::message::extract_inline_pubkey;
use crate::protocol::ProtocolError;

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

// ──────────────────── GroupMessage envelope (kind=2) ──────────────────────

/// Wire-form of a single group message: a `(group_id, encrypted_message)`
/// pair. Serialized as the kind=2 plaintext of the outer
/// `EncryptedPayload`. The inner `EncryptedGroupMessage` is the Megolm
/// sender-chain output (index + AEAD ciphertext + Ed25519 signature).
///
/// Each recipient receives one of these per group message — N-1
/// unicasts via the existing 1:1 DR channel — and decrypts
/// independently against their cached `ReceiverChain` for the sending
/// peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessageEnvelope {
    pub group_id: GroupId,
    pub msg: EncryptedGroupMessage,
}

impl GroupMessageEnvelope {
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Build the associated-data bytes bound into the Megolm AEAD and
/// signature for a group message. Layout: `group_id (32) ||
/// sender_pid_len_be (4) || sender_pid`. Binding the AD to both
/// fields means a captured ciphertext can't be replayed under a
/// different group context or attributed to a different sender.
pub fn build_group_ad(group_id: &GroupId, sender_pid: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 4 + sender_pid.len());
    out.extend_from_slice(group_id);
    out.extend_from_slice(&(sender_pid.len() as u32).to_be_bytes());
    out.extend_from_slice(sender_pid);
    out
}

// ─────────────────────── GroupControl wire types ────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum GroupControlError {
    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("founder/leaver PeerId is malformed: {0}")]
    BadPeerId(String),
    #[error("founder/leaver PeerId has no inline pubkey")]
    NoInlinePubkey,
    #[error("Ed25519 signature verification failed")]
    BadSignature,
    #[error("could not sign with the supplied keypair: {0}")]
    SignFailed(String),
}

impl From<ProtocolError> for GroupControlError {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::InvalidSender(s) => Self::BadPeerId(s),
            ProtocolError::NoInlinePublicKey => Self::NoInlinePubkey,
            other => Self::BadPeerId(format!("{}", other)),
        }
    }
}

/// Wire-form group control message. Travels as the decrypted plaintext
/// of an `EncryptedPayload` whose `kind = 1`, ferried over the existing
/// 1:1 Double Ratchet DM channel. Each recipient peer thus receives one
/// copy per control event (no broadcast — N-1 unicasts).
///
/// Signature semantics:
/// - `CreateGroup` / `MembershipUpdate` carry a **founder** signature.
///   Only the founder can legitimately produce these.
/// - `SenderKeyDistribution` is unsigned at this layer because the
///   outer 1:1 DR channel already authenticates the sender (only the
///   real chain owner can encrypt under the DR session). The recipient
///   trusts the bundle as "sent by `verified_sender`".
/// - `Leave` carries a **leaver** signature so other members can
///   verify the announcement even when the leaver isn't currently a
///   peer of theirs at the moment they see the message (e.g. via
///   forward of someone else's relay).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum GroupControl {
    /// Founder-issued group creation. Includes the initial member list.
    /// Recipients drop the message if they aren't in `members`.
    CreateGroup {
        group_id: GroupId,
        name: String,
        founder_pid: Vec<u8>,
        members: Vec<Vec<u8>>,
        epoch: u64,
        founder_sig: Vec<u8>,
    },
    /// Founder-issued membership change. `epoch` must be strictly
    /// greater than the recipient's stored epoch.
    MembershipUpdate {
        group_id: GroupId,
        added: Vec<Vec<u8>>,
        removed: Vec<Vec<u8>>,
        epoch: u64,
        founder_sig: Vec<u8>,
    },
    /// Sender hands the recipient their current Megolm chain bundle.
    /// Authenticated by the outer DR session (no inner signature).
    SenderKeyDistribution {
        group_id: GroupId,
        bundle: SenderKeyBundle,
        /// Membership epoch the sender was at when they generated this
        /// bundle. Recipients use this to spot a stale distribution from
        /// a member who hasn't yet seen the latest MembershipUpdate.
        epoch: u64,
    },
    /// Member announces they're leaving the group. Self-signed by the
    /// leaver's Ed25519 identity (PeerId-embedded).
    Leave {
        group_id: GroupId,
        leaver_pid: Vec<u8>,
        epoch: u64,
        leaver_sig: Vec<u8>,
    },
}

impl GroupControl {
    /// Serialize for placement into `EncryptedPayload.ct` plaintext
    /// (after ratchet-encrypt). Uses serde_json to mirror the convention
    /// already established by `EncryptedPayload::to_bytes`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GroupControlError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserialize from the decrypted `EncryptedPayload.ct` plaintext.
    pub fn from_bytes(data: &[u8]) -> Result<Self, GroupControlError> {
        Ok(serde_json::from_slice(data)?)
    }

    /// Build and sign a CreateGroup control message. `founder_keypair`
    /// must correspond to `founder_pid`.
    pub fn new_create_group(
        group_id: GroupId,
        name: String,
        founder_pid: Vec<u8>,
        members: Vec<Vec<u8>>,
        epoch: u64,
        founder_keypair: &Keypair,
    ) -> Result<Self, GroupControlError> {
        let signing_bytes = canonical_create_bytes(&group_id, &name, &founder_pid, &members, epoch);
        let founder_sig = founder_keypair
            .sign(&signing_bytes)
            .map_err(|e| GroupControlError::SignFailed(e.to_string()))?;
        Ok(Self::CreateGroup {
            group_id,
            name,
            founder_pid,
            members,
            epoch,
            founder_sig,
        })
    }

    /// Build and sign a MembershipUpdate control message.
    pub fn new_membership_update(
        group_id: GroupId,
        added: Vec<Vec<u8>>,
        removed: Vec<Vec<u8>>,
        epoch: u64,
        founder_keypair: &Keypair,
    ) -> Result<Self, GroupControlError> {
        let signing_bytes = canonical_update_bytes(&group_id, &added, &removed, epoch);
        let founder_sig = founder_keypair
            .sign(&signing_bytes)
            .map_err(|e| GroupControlError::SignFailed(e.to_string()))?;
        Ok(Self::MembershipUpdate {
            group_id,
            added,
            removed,
            epoch,
            founder_sig,
        })
    }

    /// Build (unsigned) SenderKeyDistribution. Authentication is
    /// inherited from the outer DR session.
    pub fn new_sender_key_distribution(
        group_id: GroupId,
        bundle: SenderKeyBundle,
        epoch: u64,
    ) -> Self {
        Self::SenderKeyDistribution {
            group_id,
            bundle,
            epoch,
        }
    }

    /// Build and sign a Leave control message. `leaver_keypair` must
    /// correspond to `leaver_pid`.
    pub fn new_leave(
        group_id: GroupId,
        leaver_pid: Vec<u8>,
        epoch: u64,
        leaver_keypair: &Keypair,
    ) -> Result<Self, GroupControlError> {
        let signing_bytes = canonical_leave_bytes(&group_id, &leaver_pid, epoch);
        let leaver_sig = leaver_keypair
            .sign(&signing_bytes)
            .map_err(|e| GroupControlError::SignFailed(e.to_string()))?;
        Ok(Self::Leave {
            group_id,
            leaver_pid,
            epoch,
            leaver_sig,
        })
    }

    /// Verify the inner signature on a signed variant. `SenderKeyDistribution`
    /// is always Ok — it has no inner signature to verify (the outer DR
    /// session authenticates it).
    ///
    /// Verifies that the `founder_sig` / `leaver_sig` was produced by
    /// the Ed25519 key embedded in `founder_pid` / `leaver_pid` (only
    /// works for inline-pubkey PeerIds — hash-coded PeerIds would need
    /// an out-of-band lookup we don't yet do).
    pub fn verify_signature(&self) -> Result<(), GroupControlError> {
        match self {
            Self::CreateGroup {
                group_id,
                name,
                founder_pid,
                members,
                epoch,
                founder_sig,
            } => {
                let signing_bytes =
                    canonical_create_bytes(group_id, name, founder_pid, members, *epoch);
                verify_pid_sig(founder_pid, &signing_bytes, founder_sig)
            }
            Self::MembershipUpdate { .. } => {
                // Founder PID is NOT carried inside this variant — the
                // caller (node.rs) MUST look it up from the local
                // `groups` row and re-attach via `verify_membership_update`
                // below. Returning Ok here would let a stranger spoof
                // updates; explicitly fail so the call site is forced
                // to use the founder-pid-attaching helper.
                Err(GroupControlError::BadSignature)
            }
            Self::SenderKeyDistribution { .. } => Ok(()),
            Self::Leave {
                group_id,
                leaver_pid,
                epoch,
                leaver_sig,
            } => {
                let signing_bytes = canonical_leave_bytes(group_id, leaver_pid, *epoch);
                verify_pid_sig(leaver_pid, &signing_bytes, leaver_sig)
            }
        }
    }

    /// Verify a `MembershipUpdate` against the founder PID looked up
    /// from local state. Returns the verified founder PeerId on success.
    pub fn verify_membership_update(
        &self,
        expected_founder_pid: &[u8],
    ) -> Result<PeerId, GroupControlError> {
        match self {
            Self::MembershipUpdate {
                group_id,
                added,
                removed,
                epoch,
                founder_sig,
            } => {
                let signing_bytes = canonical_update_bytes(group_id, added, removed, *epoch);
                verify_pid_sig(expected_founder_pid, &signing_bytes, founder_sig)?;
                PeerId::from_bytes(expected_founder_pid)
                    .map_err(|e| GroupControlError::BadPeerId(e.to_string()))
            }
            _ => Err(GroupControlError::BadSignature),
        }
    }
}

/// Verify that `sig` was produced over `bytes` by the Ed25519 key
/// embedded in `pid`. Used for CreateGroup, MembershipUpdate, and
/// Leave inner signatures.
fn verify_pid_sig(pid: &[u8], bytes: &[u8], sig: &[u8]) -> Result<(), GroupControlError> {
    let peer_id =
        PeerId::from_bytes(pid).map_err(|e| GroupControlError::BadPeerId(e.to_string()))?;
    let pubkey = extract_inline_pubkey(&peer_id)?;
    if pubkey.verify(bytes, sig) {
        Ok(())
    } else {
        Err(GroupControlError::BadSignature)
    }
}

/// Canonical signing bytes for `CreateGroup`. Layout (all u32-be
/// length-prefixed where variable):
///
/// `DOMAIN || "create" || group_id (32) || name_lp || founder_pid_lp ||
///  epoch_be (8) || count_be (4) || sorted_member_lp*`
///
/// Members are sorted by byte value so semantically-equal member sets
/// produce the same signature regardless of insert order.
fn canonical_create_bytes(
    group_id: &GroupId,
    name: &str,
    founder_pid: &[u8],
    members: &[Vec<u8>],
    epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(GROUP_CTRL_DOMAIN_SEPARATOR);
    out.extend_from_slice(b"create");
    out.extend_from_slice(&group_id[..]);
    push_lp(&mut out, name.as_bytes());
    push_lp(&mut out, founder_pid);
    out.extend_from_slice(&epoch.to_be_bytes());
    let mut sorted: Vec<&[u8]> = members.iter().map(|v| v.as_slice()).collect();
    sorted.sort();
    out.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for m in sorted {
        push_lp(&mut out, m);
    }
    out
}

/// Canonical signing bytes for `MembershipUpdate`. Adds and removes
/// are independently sorted so two semantically-equal diffs produce
/// the same signature regardless of insert order. Founder PID is NOT
/// included in the signature scope — recipients verify against the
/// founder PID they already have stored, which is the security-
/// critical bind.
fn canonical_update_bytes(
    group_id: &GroupId,
    added: &[Vec<u8>],
    removed: &[Vec<u8>],
    epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(GROUP_CTRL_DOMAIN_SEPARATOR);
    out.extend_from_slice(b"update");
    out.extend_from_slice(&group_id[..]);
    out.extend_from_slice(&epoch.to_be_bytes());
    let mut a: Vec<&[u8]> = added.iter().map(|v| v.as_slice()).collect();
    a.sort();
    out.extend_from_slice(&(a.len() as u32).to_be_bytes());
    for m in a {
        push_lp(&mut out, m);
    }
    let mut r: Vec<&[u8]> = removed.iter().map(|v| v.as_slice()).collect();
    r.sort();
    out.extend_from_slice(&(r.len() as u32).to_be_bytes());
    for m in r {
        push_lp(&mut out, m);
    }
    out
}

/// Canonical signing bytes for `Leave`. Layout: `DOMAIN || "leave" ||
/// group_id (32) || leaver_pid_lp || epoch_be (8)`.
fn canonical_leave_bytes(group_id: &GroupId, leaver_pid: &[u8], epoch: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(GROUP_CTRL_DOMAIN_SEPARATOR);
    out.extend_from_slice(b"leave");
    out.extend_from_slice(&group_id[..]);
    push_lp(&mut out, leaver_pid);
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

/// u32-be length prefix + bytes. Same convention as `message::push_bytes`
/// but local to group canonical-bytes builders.
fn push_lp(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gid() -> GroupId {
        [0xAB; 32]
    }

    fn pair_keypair_and_pid() -> (Keypair, Vec<u8>) {
        let kp = Keypair::generate_ed25519();
        let pid = PeerId::from_public_key(&kp.public()).to_bytes();
        (kp, pid)
    }

    #[test]
    fn create_group_signs_and_verifies() {
        let (kp, founder_pid) = pair_keypair_and_pid();
        let (_, alice) = pair_keypair_and_pid();
        let members = vec![founder_pid.clone(), alice];
        let ctrl =
            GroupControl::new_create_group(gid(), "test".into(), founder_pid, members, 0, &kp)
                .unwrap();
        ctrl.verify_signature().unwrap();
    }

    #[test]
    fn create_group_tampered_member_list_fails() {
        let (kp, founder_pid) = pair_keypair_and_pid();
        let (_, alice) = pair_keypair_and_pid();
        let members = vec![founder_pid.clone(), alice];
        let mut ctrl =
            GroupControl::new_create_group(gid(), "t".into(), founder_pid, members, 0, &kp)
                .unwrap();
        if let GroupControl::CreateGroup {
            ref mut members, ..
        } = ctrl
        {
            // Drop alice — should invalidate the signature.
            members.pop();
        }
        assert!(matches!(
            ctrl.verify_signature(),
            Err(GroupControlError::BadSignature)
        ));
    }

    #[test]
    fn create_group_member_order_does_not_affect_sig() {
        let (kp, founder_pid) = pair_keypair_and_pid();
        let (_, alice) = pair_keypair_and_pid();
        let (_, bob) = pair_keypair_and_pid();

        let ctrl1 = GroupControl::new_create_group(
            gid(),
            "t".into(),
            founder_pid.clone(),
            vec![alice.clone(), bob.clone()],
            0,
            &kp,
        )
        .unwrap();
        let ctrl2 = GroupControl::new_create_group(
            gid(),
            "t".into(),
            founder_pid,
            vec![bob, alice],
            0,
            &kp,
        )
        .unwrap();
        let s1 = match &ctrl1 {
            GroupControl::CreateGroup { founder_sig, .. } => founder_sig.clone(),
            _ => unreachable!(),
        };
        let s2 = match &ctrl2 {
            GroupControl::CreateGroup { founder_sig, .. } => founder_sig.clone(),
            _ => unreachable!(),
        };
        // Ed25519 is deterministic; sorted-canonical bytes are identical
        // → signatures byte-identical too.
        assert_eq!(s1, s2);
    }

    #[test]
    fn membership_update_verifies_against_founder_pid() {
        let (kp, founder_pid) = pair_keypair_and_pid();
        let (_, alice) = pair_keypair_and_pid();
        let ctrl = GroupControl::new_membership_update(
            gid(),
            vec![alice.clone()],
            vec![],
            1,
            &kp,
        )
        .unwrap();
        // Plain verify_signature returns BadSignature for MembershipUpdate
        // (founder PID isn't inside it; caller MUST use the helper).
        assert!(matches!(
            ctrl.verify_signature(),
            Err(GroupControlError::BadSignature)
        ));
        // The founder-attaching helper succeeds.
        let _ = ctrl.verify_membership_update(&founder_pid).unwrap();
    }

    #[test]
    fn membership_update_wrong_founder_fails() {
        let (kp, _founder_pid) = pair_keypair_and_pid();
        let (_kp_other, other_pid) = pair_keypair_and_pid();
        let ctrl =
            GroupControl::new_membership_update(gid(), vec![], vec![], 1, &kp).unwrap();
        // Re-attaching the wrong founder PID fails.
        assert!(matches!(
            ctrl.verify_membership_update(&other_pid),
            Err(GroupControlError::BadSignature)
        ));
    }

    #[test]
    fn leave_signs_and_verifies() {
        let (kp, leaver_pid) = pair_keypair_and_pid();
        let ctrl = GroupControl::new_leave(gid(), leaver_pid.clone(), 5, &kp).unwrap();
        ctrl.verify_signature().unwrap();
    }

    #[test]
    fn leave_with_wrong_keypair_fails_verify() {
        let (_, leaver_pid) = pair_keypair_and_pid();
        let (kp_other, _) = pair_keypair_and_pid();
        // Signed with the wrong keypair (not leaver_pid's keypair).
        let ctrl = GroupControl::new_leave(gid(), leaver_pid, 5, &kp_other).unwrap();
        assert!(matches!(
            ctrl.verify_signature(),
            Err(GroupControlError::BadSignature)
        ));
    }

    #[test]
    fn sender_key_distribution_verifies_trivially() {
        // No inner signature; outer DR session authenticates.
        let bundle = SenderKeyBundle {
            chain_key: [0u8; 32],
            index: 0,
            verify_pub: [1u8; 32],
        };
        let ctrl = GroupControl::new_sender_key_distribution(gid(), bundle, 0);
        ctrl.verify_signature().unwrap();
    }

    #[test]
    fn wire_roundtrip_serde_json() {
        let (kp, founder_pid) = pair_keypair_and_pid();
        let ctrl = GroupControl::new_create_group(
            gid(),
            "test".into(),
            founder_pid,
            vec![vec![1u8; 38]],
            0,
            &kp,
        )
        .unwrap();
        let bytes = ctrl.to_bytes().unwrap();
        let back = GroupControl::from_bytes(&bytes).unwrap();
        back.verify_signature().unwrap();
    }

    #[test]
    fn group_message_envelope_wire_roundtrip_and_decrypt() {
        use crate::crypto::megolm::{ReceiverChain, SenderChain};
        let group_id = gid();
        let (_kp, sender_pid) = pair_keypair_and_pid();
        let ad = build_group_ad(&group_id, &sender_pid);

        let mut sender_chain = SenderChain::new();
        let mut receiver_chain = ReceiverChain::from_bundle(&sender_chain.current_bundle());

        let encrypted = sender_chain.encrypt(b"hello group", &ad);
        let envelope = GroupMessageEnvelope {
            group_id,
            msg: encrypted,
        };

        let wire = envelope.to_bytes().unwrap();
        let back = GroupMessageEnvelope::from_bytes(&wire).unwrap();
        assert_eq!(back.group_id, group_id);
        // After wire round-trip, recipient can still decrypt cleanly.
        let pt = receiver_chain.decrypt(&back.msg, &ad).unwrap();
        assert_eq!(pt, b"hello group");
    }

    #[test]
    fn build_group_ad_binds_both_fields() {
        let g1 = [1u8; 32];
        let g2 = [2u8; 32];
        let pid_a = vec![0xAAu8; 38];
        let pid_b = vec![0xBBu8; 38];
        assert_ne!(build_group_ad(&g1, &pid_a), build_group_ad(&g2, &pid_a));
        assert_ne!(build_group_ad(&g1, &pid_a), build_group_ad(&g1, &pid_b));
    }

    #[test]
    fn group_ad_mismatch_breaks_megolm_decrypt() {
        use crate::crypto::megolm::{ReceiverChain, SenderChain};
        let group_id = gid();
        let (_kp, sender_pid) = pair_keypair_and_pid();
        let (_kp2, other_pid) = pair_keypair_and_pid();
        let send_ad = build_group_ad(&group_id, &sender_pid);
        let wrong_ad = build_group_ad(&group_id, &other_pid);

        let mut sender_chain = SenderChain::new();
        let mut receiver_chain = ReceiverChain::from_bundle(&sender_chain.current_bundle());
        let encrypted = sender_chain.encrypt(b"x", &send_ad);
        // Sender signature covers (DOMAIN || index || ad || ct); an AD
        // swap on the receive side breaks the signature first.
        assert!(receiver_chain.decrypt(&encrypted, &wrong_ad).is_err());
    }
}
