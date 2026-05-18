//! DHT mailbox — Kademlia store-and-forward layer.
//!
//! When a peer is offline and unreachable via the direct DM path, the
//! sender can drop their already-Double-Ratchet-encrypted `ProtocolMessage`
//! bytes into the Kademlia DHT. The recipient later polls the DHT and
//! reconstructs the message stream.
//!
//! ## Wire shape
//!
//! ```text
//!   slot_id  = floor(unix_seconds / SLOT_SECONDS)
//!
//!   slot_kad_key(recipient, slot)        = SHA-256(
//!       "zerocenter-mailbox-v1" || recipient_pid_bytes || slot_id_be8
//!   )
//!
//!   drop_kad_key(recipient, sender, slot) = SHA-256(
//!       "zerocenter-mailbox-drop-v1" || recipient_pid_bytes
//!       || sender_pid_bytes || slot_id_be8
//!   )
//! ```
//!
//! Sender flow: `start_providing(slot_kad_key)` and
//! `put_record(drop_kad_key → ProtocolMessage_bytes)`. Recipient flow:
//! `get_providers(slot_kad_key)` then `get_record(drop_kad_key)` for each
//! provider. Providers DHT-side handles fan-out — many senders can drop
//! into the same `(recipient, slot)` without collisions because each
//! sender's record lives at a distinct key.
//!
//! ## What this layer can and cannot do
//!
//! - **Can:** deliver an encrypted message to a recipient even when the
//!   sender and recipient are never online simultaneously, as long as
//!   both are eventually online in the same DHT.
//! - **Cannot:** hide which peer dropped what for whom. The providers
//!   DHT records `(sender_pid, slot_kad_key=H(recipient_pid|slot))` —
//!   anyone querying the DHT sees the same metadata leak as the direct
//!   DM path (where `from` and `to` are in clear in the envelope).
//!   A future sealed-sender design (Phase 5) is the right place to fix
//!   this; documented in `audit/INVARIANTS.md` §21 and `audit/README.md`
//!   caveat #3.
//! - **Cannot:** encrypt the FIRST message to a peer for whom we hold
//!   no session and no cached prekey — bootstrapping X3DH still needs
//!   the responder's prekey, which we currently fetch only via the
//!   live request-response channel. If the recipient has never been
//!   directly contacted, only the outbox path applies; mailbox publish
//!   is skipped with a debug log.
//!
//! ## Test coverage
//!
//! Pure-function tests in this module cover the key-derivation
//! determinism / uniqueness invariants. End-to-end multi-peer Kad
//! integration is exercised by the manual two-peer smoke; see
//! `plans/ROADMAP.md`.

use libp2p::kad::RecordKey;
use sha2::{Digest, Sha256};

/// One-hour slots. Picked to balance freshness (recipient polls every
/// `POLL_TICK_SECS`, so worst-case delivery latency is roughly
/// `SLOT_SECONDS + POLL_TICK_SECS`) against Kad load (each slot the
/// recipient enters becomes a new provider lookup).
pub const SLOT_SECONDS: i64 = 3600;

/// How long a drop survives in the DHT before we stop republishing it
/// and let the row be GC'd. 7 days matches the local-message TTL.
pub const DEFAULT_DROP_TTL_SECS: i64 = 7 * 24 * 3600;

/// Republish loop cadence. Every `REPUBLISH_TICK_SECS` we walk the local
/// `mailbox_drops` rows and re-`put_record` anything older than
/// `REPUBLISH_AFTER_SECS`. Tuned so Kad's default record TTL (1 hour
/// in libp2p 0.53) doesn't expire between republishes.
pub const REPUBLISH_TICK_SECS: u64 = 600;
pub const REPUBLISH_AFTER_SECS: i64 = 1800;

/// Recipient-side poll cadence. Every `POLL_TICK_SECS` we walk the
/// `last_polled_slot..now_slot` range and issue `get_providers` for
/// each slot we haven't yet covered.
pub const POLL_TICK_SECS: u64 = 600;

const SLOT_KEY_DOMAIN: &[u8] = b"zerocenter-mailbox-v1";
const DROP_KEY_DOMAIN: &[u8] = b"zerocenter-mailbox-drop-v1";
const ACK_KEY_DOMAIN: &[u8] = b"zerocenter-mailbox-ack-v1";

/// Compute the slot id for a given unix timestamp (seconds). `slot_id`
/// is shared by every drop targeted at any recipient during this hour.
pub fn slot_id_for(unix_seconds: i64) -> i64 {
    unix_seconds.div_euclid(SLOT_SECONDS)
}

/// Kad key under which a recipient `start_providing`-finds the set of
/// peers who have dropped something for them during `slot_id`. Each
/// such provider then leads the recipient to a `drop_kad_key` lookup.
pub fn slot_kad_key(recipient_pid: &[u8], slot_id: i64) -> RecordKey {
    let mut h = Sha256::new();
    h.update(SLOT_KEY_DOMAIN);
    h.update(recipient_pid);
    h.update(slot_id.to_be_bytes());
    RecordKey::new(&h.finalize().as_slice())
}

/// Kad key that holds the encrypted `ProtocolMessage` bytes of a single
/// drop from `sender_pid` for `recipient_pid` at `slot_id`. Distinct
/// senders never collide because their PIDs are mixed into the digest.
pub fn drop_kad_key(recipient_pid: &[u8], sender_pid: &[u8], slot_id: i64) -> RecordKey {
    let mut h = Sha256::new();
    h.update(DROP_KEY_DOMAIN);
    h.update(recipient_pid);
    h.update(sender_pid);
    h.update(slot_id.to_be_bytes());
    RecordKey::new(&h.finalize().as_slice())
}

/// Phase 5 ACK key. After the recipient successfully fetches and
/// decrypts a drop at `drop_kad_key(recipient, sender, slot)`, they
/// publish an empty record at this matching ACK key. The sender's
/// republish loop checks for the ACK before each `put_record` and
/// stops republishing once it lands. Distinct domain separator
/// (`"zerocenter-mailbox-ack-v1"`) keeps it disjoint from the drop /
/// slot namespaces.
pub fn ack_kad_key(recipient_pid: &[u8], sender_pid: &[u8], slot_id: i64) -> RecordKey {
    let mut h = Sha256::new();
    h.update(ACK_KEY_DOMAIN);
    h.update(recipient_pid);
    h.update(sender_pid);
    h.update(slot_id.to_be_bytes());
    RecordKey::new(&h.finalize().as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_id_buckets_by_hour() {
        // Anchor at a slot boundary (1.7B + 800s offset to land on one)
        // — `t` was not slot-aligned which made the `+SLOT_SECONDS - 1`
        // assertion off by one. Realign by subtracting the remainder
        // and then the boundary invariants hold cleanly.
        let raw = 1_700_000_000i64;
        let t = raw - raw.rem_euclid(SLOT_SECONDS);
        let s = slot_id_for(t);
        assert_eq!(slot_id_for(t + 1), s);
        assert_eq!(slot_id_for(t + SLOT_SECONDS - 1), s);
        assert_eq!(slot_id_for(t + SLOT_SECONDS), s + 1);
    }

    #[test]
    fn slot_id_handles_negative_timestamps() {
        // `i64::div_euclid` rounds toward negative infinity — a
        // pre-epoch second still has a well-defined slot. Defensive
        // check; real clocks won't hit this but `div_euclid` semantics
        // are worth pinning.
        assert_eq!(slot_id_for(0), 0);
        assert_eq!(slot_id_for(-1), -1);
        assert_eq!(slot_id_for(-SLOT_SECONDS), -1);
        assert_eq!(slot_id_for(-SLOT_SECONDS - 1), -2);
    }

    #[test]
    fn slot_key_deterministic_per_input_tuple() {
        let recip = b"recipient-pid-bytes-go-here-12345";
        let k1 = slot_kad_key(recip, 42);
        let k2 = slot_kad_key(recip, 42);
        assert_eq!(k1, k2, "same inputs → same key");
    }

    #[test]
    fn slot_key_changes_with_inputs() {
        let recip_a = b"recipient-a-pid";
        let recip_b = b"recipient-b-pid";
        assert_ne!(slot_kad_key(recip_a, 1), slot_kad_key(recip_b, 1));
        assert_ne!(slot_kad_key(recip_a, 1), slot_kad_key(recip_a, 2));
    }

    #[test]
    fn drop_key_distinguishes_each_sender_recipient_slot_tuple() {
        let recip = b"recipient-pid";
        let sender_a = b"sender-a-pid";
        let sender_b = b"sender-b-pid";
        let slot = 99;

        let k_a = drop_kad_key(recip, sender_a, slot);
        let k_b = drop_kad_key(recip, sender_b, slot);
        let k_a_other_slot = drop_kad_key(recip, sender_a, slot + 1);

        assert_ne!(k_a, k_b, "different senders → different drop keys");
        assert_ne!(k_a, k_a_other_slot, "different slots → different drop keys");
    }

    #[test]
    fn slot_key_and_drop_key_use_distinct_domains() {
        // A slot key and a drop key for the SAME (recipient, slot) and
        // sender = recipient must NOT collide — the domain-separator
        // bytes guarantee it.
        let pid = b"some-32-byte-peer-id-bytes-aa-bb";
        let slot = 7;
        assert_ne!(
            slot_kad_key(pid, slot),
            drop_kad_key(pid, pid, slot),
            "domain separators must keep the two namespaces disjoint"
        );
    }

    #[test]
    fn ack_key_is_distinct_from_drop_and_slot_keys() {
        // Phase 5 ACK keys live in their own namespace — sender's
        // republish poll on the ACK key must NEVER collide with the
        // drop or slot keys (which carry actual ciphertext / providers).
        let recip = b"some-recipient-pid";
        let sender = b"some-sender-pid";
        let slot = 99;
        let slot_k = slot_kad_key(recip, slot);
        let drop_k = drop_kad_key(recip, sender, slot);
        let ack_k = ack_kad_key(recip, sender, slot);
        assert_ne!(ack_k, slot_k);
        assert_ne!(ack_k, drop_k);

        // Determinism + sensitivity to inputs.
        assert_eq!(ack_k, ack_kad_key(recip, sender, slot));
        assert_ne!(ack_k, ack_kad_key(recip, sender, slot + 1));
        assert_ne!(ack_k, ack_kad_key(recip, b"other-sender", slot));
    }

    #[test]
    fn record_key_is_32_bytes() {
        let k = slot_kad_key(b"any", 0);
        assert_eq!(k.as_ref().len(), 32, "RecordKey is SHA-256 output, 32 bytes");
    }
}
