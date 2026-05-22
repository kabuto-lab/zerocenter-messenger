# Self-Audit Findings (2026-05-18)

## Methodology

Walked each of the 21 invariants in `audit/INVARIANTS.md` against the source, located the
claimed enforcement sites in `src/`, and stress-tested the suggested attacks mentally
(and against the in-tree tests where applicable). Then read `src/network/scramble.rs`,
`src/network/mailbox.rs`, the relevant slices of `src/core/node.rs`, the full ratchet
and X3DH modules, the storage layer, the signed envelope, and the identity loader.
Finally cross-checked `audit/CRYPTO.md` and `audit/README.md` against the current
code paths (Phase 4c.1 NTOR shipped, frame padding shipped, jitter shipped, DHT
mailbox shipped).

Most invariants are correctly enforced. The serious finding is in the obfuscation
layer's NTOR-derived ChaCha20 keying: the same `(key, nonce)` is used for BOTH
directions, producing identical keystreams and a textbook two-time-pad situation
on the obfs envelope when both peers transmit. The on-wire confidentiality of
message content is unaffected because Noise XX still sits above the obfs layer,
but the obfs layer's own indistinguishability claim does not hold against an
observer who captures both directions. Several smaller defense-in-depth and
documentation issues are also flagged. No issue rises to "exploitable plaintext
recovery against E2EE today" — the headline finding is a hardening defect, not
an E2EE break.

## Findings

### F1: ScrambleStream's NTOR derivation uses one (key, nonce) for both directions → keystream-reuse two-time-pad on the obfs envelope

**Severity:** High
**Location:** `src/network/scramble.rs::scramble_handshake` (lines 614–634); construction
of both ciphers in `ScrambleStream::with_jitter` (lines 229–246).

**Description.** After the elligator2 / X25519 handshake, both peers HKDF a single
44-byte OKM from `shared_secret || obfs_key` and split it into ONE `(chacha_key[32],
chacha_nonce[12])` pair. Both `ScrambleStream::out_cipher` and `in_cipher` are then
initialized with the SAME `(key, nonce)`:

```rust
let out_cipher = ChaCha20::new(key.into(), nonce.into());
let in_cipher  = ChaCha20::new(key.into(), nonce.into());
```

Concretely: on a bidirectional connection, peer A's outbound and peer B's outbound
XOR their respective plaintexts against the SAME keystream bytes. An observer who
captures both directions of a TCP connection just XORs the two captures position-by-
position and recovers `plaintext_A XOR plaintext_B` — the classic two-time-pad attack.

**Impact.** The obfuscation layer's stated goal (per `audit/INVARIANTS.md` §17 and
`audit/THREAT_MODEL.md` §G) is that a DPI box sees "only pseudo-random bytes" — i.e.
the wire is computationally indistinguishable from random. With keystream reuse,
the XOR of the two directions is NOT random: it equals `pt_libp2p_dialer XOR
pt_libp2p_listener`, where both sides are running structured Noise XX + yamux +
multistream-select traffic with substantial known / partially-known content
(fixed-size handshake messages, length-prefixes, protocol-negotiation strings).
A statistical adversary can:
1. Detect that the two directions share a keystream (the XOR will look like
   structured-protocol-XOR-structured-protocol, not random-XOR-random).
2. Recover at least the partially-known prefixes (Noise XX msg-1 begins with a
   32-byte X25519 pubkey; XOR-ing the directions and subtracting known structure
   gives the other side's pubkey).
3. Identify the underlying protocol as libp2p-Noise-XX from the XOR signature alone.

This defeats the headline censorship-resistance claim of the Phase 4c.1 NTOR
work. The frame-padding work (Phase 4c.2) doesn't help — same-length frames
in both directions still produce a recoverable XOR. E2EE of message content
is unaffected (Noise XX above us is correctly keyed), but the obfs layer's
contract is broken.

Note the existing tests `roundtrip_in_memory`, `wire_bytes_are_not_plaintext`,
`ntor_handshake_roundtrips`, etc., all exercise UNIDIRECTIONAL traffic (one
writer, one reader). The defect doesn't surface in unit tests; only a
bidirectional or full Noise-XX integration test would catch it.

**Recommendation.** HKDF-expand 88 bytes (or two separate expansions) into two
direction-distinguished `(key, nonce)` pairs. Standard practice (TLS, Noise,
WireGuard, Obfs4): use info strings like `"chacha-key-nonce-c2s"` and
`"chacha-key-nonce-s2c"` to derive distinct keying for dialer→listener and
listener→dialer. Initialize `out_cipher` from the role-appropriate key/nonce
and `in_cipher` from the other.

---

### F2: ScrambleStream does not validate X25519 shared-secret for low-order / all-zero output

**Severity:** Low
**Location:** `src/network/scramble.rs::scramble_handshake` (line 614).

**Description.** `x25519_dalek::x25519(my_priv, their_pub)` is used as a free
function. The 2.x free function does not reject low-order public keys — if a
peer (or active MITM at the obfs layer) supplies an elligator2 representative
that decodes to a low-order point, `shared_secret` will be all-zeros or another
low-order constant. HKDF then derives the keystream from `0^32 || obfs_key`,
which is a constant for any fixed obfs_key. Per-connection key freshness is
lost on that connection — the keystream becomes a deterministic function of
the (pre-shared) obfs_key.

**Impact.** The forward-secrecy property of the obfs envelope (each session
gets a fresh keystream so a compromised `obfs_key` doesn't let a passive
recorder decrypt past sessions) collapses for any connection whose ephemeral
landed on a low-order point. Confidentiality of message content is unaffected
(Noise XX above), and an attacker without `obfs_key` still can't decrypt the
obfs envelope. The elligator2 `Randomized` decoder is generally biased toward
prime-order-subgroup points, so in practice this is unlikely to occur from
honest peers, but it can be deliberately induced by an MITM that intercepts
the 32-byte representative.

**Recommendation.** After `x25519(my_priv, their_pub)`, check whether
`shared_secret == [0u8; 32]` and either abort the handshake with `io::Error`
or proceed with a domain-separated tag in the HKDF so the failure mode is
documented and distinguishable. Combined with F1's per-direction key fix,
this hardens the obfs envelope against active manipulation.

---

### F3: `load_otpk_private` does not gate on `consumed_at`, enabling session-wipe on first-message replay

**Severity:** Medium
**Location:** `src/storage/store.rs::load_otpk_private` (line 539);
`src/core/node.rs::bootstrap_responder_and_decrypt` (line 1508);
`src/core/node.rs::process_incoming_dm` (line 1466).

**Description.** `load_otpk_private(id)` returns the encrypted private bytes as
long as the row exists, regardless of whether `consumed_at` has been set. The
row is only physically removed by `delete_otpk(id)`, which runs AFTER
`decrypt_first_message` succeeds (line 1567–1573).

Combined behavior: if Bob's in-memory session for Alice is somehow gone
(restart with corrupt persisted blob, DEK rotation, or even a Bob crash
between `bootstrap_responder_and_decrypt` and `persist_session`) AND a
replay of Alice's first message arrives before garbage-collection runs,
`bootstrap_responder_and_decrypt` will:
1. `load_otpk_private(id)` succeeds (row still there).
2. Re-derive the same SK.
3. Build a fresh `RatchetState::new_responder` and `self.sessions.insert(peer, session)` —
   **overwriting any in-memory session** that may have been restored.
4. Decrypt the first message (succeeds — same SK as original).
5. `persist_session` writes the fresh state, overwriting any newer chain
   state previously persisted.
6. `delete_otpk` runs.

If Alice's chain has advanced past message 0 in the meantime, Bob's now-
overwritten session can no longer decrypt Alice's in-flight messages —
all of Alice's subsequent traffic fails AEAD until both sides restart
the session via a fresh prekey fetch.

§2's transport-peer cross-check requires the replay to come from Alice's
transport-level PeerId or via the mailbox `provider == alice` path, so a
random attacker cannot trigger this. But a benign Alice-initiated retry
(network duplicate, mailbox redrop of an already-direct-delivered message),
hitting a Bob whose session state is missing in-memory but had been
persisted, can lose chain synchronization.

**Impact.** Self-inflicted DoS triggered by a legitimate retry path, not a
remote attack. Recovery requires both sides to start a new session.

**Recommendation.** In `load_otpk_private`, return `None` when `consumed_at IS
NOT NULL`. Equivalently, in `bootstrap_responder_and_decrypt`, refuse to
re-bootstrap if a session already exists for that peer (in-memory or
persisted); fall through to the normal `decrypt_and_store` path, where AEAD
failure will be reported but the existing chain is preserved. The current
fallback of "AEAD will fail and they'll re-handshake" is correct in spirit
but loses chain state along the way.

---

### F4: Mailbox poll can fan-out unbounded duplicate `pending_recvs` entries before the prekey response arrives

**Severity:** Low
**Location:** `src/core/node.rs::process_incoming_dm` (lines 1491–1505); the poll
tick at `poll_mailbox_slots` re-querying the current slot every cycle.

**Description.** `poll_mailbox_slots` re-queries the current slot every
`POLL_TICK_SECS` (line 1273-1276). Each fetched record arrives via
`handle_mailbox_record_result` → `process_incoming_dm`. If Bob doesn't yet
have a session and hasn't cached Alice's prekey, every fetch appends the
payload to `pending_recvs[alice]` and (after the first) is a no-op on the
prekey fetch because `inflight_prekey_fetches` has Alice. There is no
de-duplication of `pending_recvs` entries — the same payload can land in the
queue arbitrarily many times across poll cycles.

When the prekey response finally arrives, `process_pending` iterates the
full vec, bootstraps once, then runs `decrypt_and_store` N-1 more times,
each producing an AEAD-failure warning. Memory is bounded by Kad TTL (records
expire) but the queue can grow to dozens of duplicate entries during the
fetch-pending window.

**Impact.** Not exploitable, just noisy. A misconfigured mailbox-poll cadence
plus a slow prekey-fetch response amplifies log spam by orders of magnitude.

**Recommendation.** Dedupe `pending_recvs.entry(peer)` insertions by hashing
the `ct` field (or the full `EncryptedPayload`), and cap the per-peer queue
length at a small constant (e.g. 16) with oldest-first eviction.

---

### F5: `process_incoming_dm` does not check `ProtocolMessage::is_expired` before bootstrapping a session

**Severity:** Low
**Location:** `src/core/node.rs::process_incoming_dm` (lines 1420–1506);
`src/protocol/message.rs::is_expired` (line 227).

**Description.** The envelope has a `ttl` field and `is_expired()` checks
`current_timestamp() > timestamp + ttl`, but no code path in `node.rs` calls
it. A signed envelope from a year ago with `timestamp = old_now` is accepted,
parsed, the signature verified, and (if no session yet) used to bootstrap a
fresh responder ratchet. This is particularly relevant to the mailbox path:
old drops fished out of the DHT before Kad TTL expires can drive responder
bootstrap.

**Impact.** Slow rejection of stale traffic; processing cycles wasted on
messages that semantically should be dropped at the envelope layer.
Combined with F3 (session-wipe on first-message replay), an old mailbox
drop fetched after a Bob-side state loss could overwrite a fresh session
with a year-old one.

**Recommendation.** After `proto_msg.verify()` succeeds, immediately check
`proto_msg.is_expired()` and drop with a `debug!` if so. Tighten the
allowed `ttl` ceiling (currently 7 days; consider rejecting envelopes whose
`timestamp` is more than a few minutes in the future to defend against
clock-skew abuse).

---

### F6: `cli::run_cli_with_handlers` is run in a `tokio::spawn`-blocked context, leading to `futures::executor::block_on` inside handler closures

**Severity:** Informational
**Location:** `src/main.rs` lines 118, 137, 145, 152, 160, 175 (and others).

**Description.** Each CLI handler closure invokes
`futures::executor::block_on(cmd_tx.send(...))` to push a `NodeCommand` to
the node-loop task. Using `block_on` inside a function that may itself be
called from a tokio task (the line reader) is a well-known footgun — it
nests two executors and can deadlock under load. It does not surface here
because the CLI line reader runs on its own thread, but the pattern is
fragile against future refactors.

**Impact.** None today. Future-risk: a refactor that moves CLI input into
the tokio runtime would deadlock.

**Recommendation.** Replace the synchronous `block_on` calls with either a
`tokio::runtime::Handle::block_on` (when on a worker thread) or rewrite
the CLI to be fully async. Best long-term: use `try_send` and panic /
error on full so the deadlock is loud.

---

### F7: Tracing logs emit `info!("Identify from {}: {:?}", peer_id, info)` which dumps the full identify payload

**Severity:** Informational
**Location:** `src/core/node.rs::handle_behaviour_event` (line 670).

**Description.** The `identify` protocol payload contains the peer's public
key, listening addresses, agent string, and protocol set. None of it is
secret per se (it's exchanged in the clear at the libp2p layer), but
emitting it at `info!` means it appears in any remote log aggregator
configured at INFO level. The same applies to `identify::Event::Received`
logged via `info!` with the full `Debug` of `info`.

INVARIANTS §19 commits to keeping "PeerIds, error context, and outbox events"
at info but NOT plaintext. This log line goes further than the invariant
permits — it leaks network-topology metadata (listening addresses) that a
remote log aggregator can use to map who's behind which IP.

**Impact.** Metadata leak only, no plaintext exposure.

**Recommendation.** Downgrade these `info!` lines to `debug!` and replace
the `{:?}` formatter with explicit field selection (peer_id + protocol
list, omitting addresses). Same applies to the `Sent`, `Pushed`, and
`Error` arms — currently all at `info!`.

---

### F8: Outbox is drained EVEN when it was already mailbox-published, leading to duplicate plaintext delivery

**Severity:** Informational
**Location:** `src/core/node.rs::try_send_or_queue` (lines 828–854);
`drain_outbox_for` (line 883); `publish_mailbox_drop` (line 1083).

**Description.** When Alice sends to a disconnected Bob, `try_send_or_queue`
calls BOTH `outbox_add` and `publish_mailbox_drop`. The mailbox publish
encrypts and advances the ratchet state by one message (header.n = 0). When
Bob comes online later (direct connection), `drain_outbox_for` rehydrates
the plaintext from the outbox and feeds it back through `try_send_or_queue`,
which now sees Bob connected and goes through `encrypt_and_send_existing`.
This produces a SECOND ciphertext (header.n = 1) with the same plaintext.
Bob therefore receives the same plaintext twice — once via mailbox
(`header.n = 0`), once via direct (`header.n = 1`). The ratchet correctly
decrypts both because they're under different mks.

**Impact.** UX duplicate: a user sees the same DM twice in `history` and
twice on the terminal. INVARIANTS §21's claim of "ratchet's `try_skipped`
cache silently dedupes" is not what actually happens — the two ciphertexts
are at different chain positions, both decrypt cleanly, both are stored
via `store_message`. No `try_skipped` involvement.

**Recommendation.** Either:
1. On successful direct-delivery, find and delete any matching pending
   mailbox_drops row (best for the "they came back to us" case).
2. On successful mailbox-delivery, delete the matching outbox row (best
   for the "they fetched from DHT" case — but the sender can't know).
3. Dedupe at the recipient's `store_message` call by a content hash within
   a short time window.

At minimum, fix INVARIANTS §21 to reflect reality (the two paths produce
two distinct ciphertexts at distinct chain positions, both decrypt, both
are stored).

---

### F9: `decrypt_first_message`'s in-memory session is left partially installed if AEAD fails after `self.sessions.insert`

**Severity:** Low
**Location:** `src/core/node.rs::bootstrap_responder_and_decrypt` (lines 1556–1574);
`decrypt_first_message` (line 1580).

**Description.** `bootstrap_responder_and_decrypt` inserts the new session
into `self.sessions` BEFORE attempting decrypt. If `decrypt_first_message`
returns false (AEAD failure on the first message — possible if the
attacker substituted a malformed `ct` or if `pn` was tampered), the
freshly-inserted session is NOT removed; it sits in memory with no
chain-state. Subsequent legitimate messages from the same peer will
short-circuit `restore_session_if_persisted` (since `self.sessions` has
the entry) and try to decrypt under the broken session.

**Impact.** A single bad first-message after a state-loss event can wedge
the in-memory session until restart. Requires the attacker to land
either a valid Alice-signed-but-tampered-ciphertext message or a
network glitch corrupting Alice's legitimate first message in transit.

**Recommendation.** Move `self.sessions.insert(peer, session)` to AFTER
`decrypt_first_message` returns true. If decrypt fails, drop the new
session and leave the slot empty so the next legitimate first-message
attempt can re-bootstrap cleanly. Alternatively, on failure, also
remove the persisted session blob so a restart starts cleanly.

---

### F10: Documentation: `audit/CRYPTO.md` §11 describes ScrambleStream as a "Phase 4a stub" that is "not wired into libp2p yet"

**Severity:** Informational
**Location:** `audit/CRYPTO.md` §11 (lines 360–371).

**Description.** This entire section is stale. Phase 4b wired the transport,
Phase 4c.1 added NTOR, Phase 4c.2 added frame padding, and Phase 4c.2′
added IAT jitter. None of this is reflected in `CRYPTO.md`. The text says
"two independent ChaCha20 keystreams (one per direction)" which is what
the implementation SHOULD do but currently does NOT (see F1) — and the
text says "Nonce currently passed as a constructor argument" which is
true of `ScrambleStream::new` but is no longer how the production code
path acquires its nonce (NTOR derivation, see `scramble_handshake`).

A reviewer reading `audit/CRYPTO.md` would conclude the obfs layer is
much simpler than it is, and would miss the F1 keystream-reuse defect
since the doc claims "two independent" streams.

**Impact.** Doc accuracy. A real reviewer following CRYPTO.md as their
spec would not catch F1 because the doc CLAIMS the correct behavior.

**Recommendation.** Rewrite §11 to describe the actual Phase 4c.1 NTOR-
style handshake, the elligator2 representable-keypair retry loop, the
HKDF info string (`"zerocenter-ntor-v1"` + `"chacha-key-nonce"`), the
44-byte OKM split into `(key32, nonce12)`, the frame-padding scheme
(`FRAME_QUANTUM = 256`, `MAX_PENDING_BYTES`, `MAX_PAYLOAD_PER_FRAME`),
and the opt-in jitter. Cross-reference INVARIANTS §17 explicitly.

---

### F11: Documentation: README's "no further trivial compile-time issues" caveat is fine but the build-status line "48/48 tests pass" is out of date

**Severity:** Informational
**Location:** `audit/README.md` line 26.

**Description.** README claims "48/48" tests as of 2026-05-17. The user's
memory says the head-of-tree commit is `be3b607` with "49/49 tests" and
that Phase 4c.2 framing WIP has a known test deadlock in working tree.
The README is one commit behind reality and doesn't mention any in-flight
work. A reviewer arriving at the audit pack should know the working
tree state, not just the last-good HEAD.

**Impact.** Reviewer might run `cargo test` on a non-clean working tree
and see a deadlock, then mistake it for a fresh finding.

**Recommendation.** Bump the test count, add a "Working tree state"
section that distinguishes shipped-on-main from WIP-in-progress, and
point at the README/MEMORY notes about the Phase 4c.2 framing deadlock.

---

### F12: `outbox.peer_id` is plaintext but the column is otherwise INTEGER-keyed; consider HMAC'ing

**Severity:** Informational
**Location:** `src/storage/store.rs` outbox schema (line 144); INVARIANTS §15
already acknowledges plaintext recipient PeerIds.

**Description.** `outbox.peer_id` is BLOB and stored in clear; index
`idx_outbox_peer` is built on it. THREAT_MODEL §D admits this leak
("the *content* is encrypted but the recipient is visible"). It's
documented as a known caveat, not a bug. But a partial mitigation
exists: HMAC the PeerId under the DEK and store the HMAC instead.
Queries by-peer become "compute HMAC(peer) then SELECT WHERE
peer_hmac = ?". Same query performance, no peer-id leak on disk read.

**Impact.** Defense-in-depth gap, already documented.

**Recommendation.** Not urgent. Track for Phase 5 sealed-sender or
metadata-privacy work.

**Status — ACTIONED (2026-05-22).** `outbox.peer_id` now stores
`HMAC-SHA256(DEK, "zerocenter-outbox-peer-v1" || peer_id)` instead of
the raw PeerId (`store.rs::outbox_peer_tag`). The HMAC is deterministic
so the by-peer equality lookup and `idx_outbox_peer` index are
unchanged; it is one-way, which is sufficient because `drain_outbox_for`
always already holds the `PeerId`. A `PRAGMA user_version`-gated
migration re-tags rows from pre-F12 databases on first open. Two tests
added (`outbox_peer_id_is_hmac_tagged_at_rest`,
`outbox_peer_id_migration_retags_legacy_rows`).

---

## Invariants verified clean

- **§1 — Domain separators are distinct** between `zerocenter-dm-v1`,
  `zerocenter-prekey-v1`, `zerocenter-rk-v1`, `zerocenter-x3dh-v1`,
  `zerocenter-x3dh-otpk-v1`, `zerocenter-safety-v1`, `zerocenter-mailbox-v1`,
  `zerocenter-mailbox-drop-v1`, `zerocenter-ntor-v1`. No collisions; no
  call to `Identity::sign` or `keypair.sign` without a domain separator
  was found.

- **§2 — Transport-peer cross-check** is enforced at
  `src/core/node.rs::process_incoming_dm` lines 1446–1454. The mailbox
  path (§21) routes through the same function with the provider PeerId
  as the transport-attribution argument, so the check applies there too.

- **§4 — AEAD nonce uniqueness per `mk`** is correctly maintained.
  `aead_encrypt`/`aead_decrypt` use zero nonce; every `mk` is one-shot
  via `kdf_ck` per message. Skipped-cache hit on `try_skipped` removes
  the entry before returning, so a single `mk` cannot be re-derived.

- **§5 — `MAX_SKIP` bound** is enforced at
  `src/crypto/ratchet.rs::skip_message_keys` line 312 via the
  `until.saturating_sub(self.nr) + skipped.len() > MAX_SKIP` check, plus
  the post-loop oldest-first eviction loop at line 333. Tested by
  `too_many_skipped_returns_error`. `header.n = u32::MAX` correctly
  triggers the error path.

- **§6 — AAD bindings** include `ratchet_ad(sender, recipient) ||
  header.to_aad_bytes()` on both encrypt and decrypt sides; the peer-ID
  ordering is consistent across the encrypt site at
  `src/core/node.rs::encrypt_and_send_existing` and the decrypt sites
  in `decrypt_first_message` / `decrypt_and_store`.

- **§7 — OTPK pop atomicity** uses a single `UPDATE ... RETURNING`
  in `pop_unused_otpk`. SQLite serializes via the database-level
  write lock; concurrent callers cannot both get the same row.

- **§8 — Consume-on-publish semantics** verified at
  `src/storage/store.rs::pop_unused_otpk`; the consume happens
  unconditionally on UPDATE.

- **§9 — At-rest encryption coverage**: `store_message`, `save_session`,
  `add_my_otpk`, `outbox_add`, and `mailbox_drop_record` all route
  through `encrypt_at_rest` before INSERT. Tests
  `*_is_encrypted_at_rest` confirm the raw blobs don't contain
  plaintext markers and start with `AT_REST_VERSION = 1`. No bypass
  INSERT path was found by grepping `INSERT INTO messages|outbox|
  ratchet_sessions|my_otpks|mailbox_drops` in the source.

- **§10 — Decrypt-failure handling**: `decrypt_at_rest` returns `Err`
  on AEAD failure (line 271). `load_session` propagates with `?`.
  `get_messages`, `get_recent_messages`, `get_conversation`,
  `outbox_get_for`, `mailbox_drops_due_for_republish` all use
  `filter_map` to skip on Err with `tracing::warn!`. No silent
  garbage substitution; the test
  `message_with_wrong_dek_is_skipped_not_errored` confirms.

- **§11 — At-rest AAD is empty** (line 235, 269 in `store.rs`).
  Documented trade-off; no row-context binding. Acknowledged.

- **§12 — DEK is keyring-only** (`src/crypto/keyring.rs`). No
  `std::fs::write` or other persistence path touches DEK bytes.

- **§13 — identity.json plaintext** (`src/core/identity.rs::save`)
  is the documented exception.

- **§14 — Bootstrap parse** is enforced at
  `src/core/node.rs::parse_bootstrap_addr` (line 289).

- **§15 — Outbox DEK encryption** (not wire AEAD) verified at
  `outbox_add` (line 568) — uses `encrypt_at_rest`, the local DEK,
  not any wire-layer key.

- **§16 — In-memory pending state is volatile** confirmed: all of
  `pending_sends`, `pending_recvs`, `cached_otpks`,
  `inflight_prekey_fetches`, `pending_provider_queries`,
  `pending_record_queries` are `HashMap`/`HashSet` fields with no
  persistence.

- **§17 — ScrambleStream wiring** is structurally in place; the
  enforcement sites listed in the invariant exist as described.
  But see F1: the *correctness* of the keying is the issue, not
  the wiring.

- **§18 — Sync crypto on the event loop** — noted as a DoS surface,
  not enforced; status unchanged.

- **§19 — No plaintext in tracing logs at `info!`** — `info!` /
  `warn!` lines in `src/core/node.rs` contain only PeerIds, counts,
  and error strings. The plaintext lines were correctly downgraded
  to `debug!`. The `println!` lines that render `🔓 {}: {}` are
  deliberate UI output (out of scope). See F7 for the related
  identify-payload concern, which is metadata-not-plaintext but
  arguably crosses the invariant's spirit.

- **§20 — `--gui` build-time switch** at `src/main.rs::run_gui`
  with `#[cfg(feature = "gui")]` arms (lines 261–273).

- **§21 — Mailbox encryption + dedup** — encryption and signature
  are correctly reused via `ratchet_encrypt_and_wrap` and
  `process_incoming_dm`. The §21 transport-attribution argument
  holds: a provider for `slot_kad_key(victim, slot)` can only place
  records at `drop_kad_key(victim, that_provider, slot)`, so the
  §2 cross-check transitively prevents impersonation. BUT the
  "silently deduped by ratchet's `try_skipped` cache" claim is
  inaccurate (see F8): the two ciphertexts arrive at different chain
  positions, both decrypt cleanly under different mks, both are
  stored, and the user sees a duplicate.

## Doc accuracy

- `audit/CRYPTO.md` §11 is the most stale section — describes a Phase 4a
  stub that no longer matches the code. See F10 for the rewrite
  recommendation.

- `audit/INVARIANTS.md` §21 "Suggested attack" trio is excellent but the
  body's "silently deduped by the ratchet's `try_skipped` cache" claim
  is incorrect; the actual dedup is by AEAD failure on the second
  attempt (when same-position) or by both messages decrypting and being
  stored (when different chain positions). See F8.

- `audit/INVARIANTS.md` §17 paragraph "Per-connection key + nonce
  (Phase 4c.1 — NTOR-style hidden handshake)" describes deriving "a
  fresh ChaCha20 `(key, nonce)`" — singular. It does not state that
  the same `(key, nonce)` is used in BOTH directions. A careful
  reader would not necessarily conclude F1 from this text alone, but
  someone implementing-from-spec would build the buggy version. The
  doc should make the per-direction split explicit (and the impl
  should match).

- `audit/INVARIANTS.md` §10 — "`decrypt_at_rest` returns Err" is
  correct, but "`load_session` propagates the error up" is slightly
  misleading at the caller side: `restore_session_if_persisted`
  converts the Err into a `false` return and logs a `warn!`, which
  effectively treats the session as missing. A DEK rotation will
  cause silent session-wipe behavior even though the invariant text
  reads as if errors propagate to the user.

- `audit/README.md` build-status line "48/48 tests pass" is one
  commit behind. See F11.

- `audit/CRYPTO.md` §3 — "Storage: AEAD-encrypted private bytes,
  plaintext public + signature." Correct. But the §3 line "consumption:
  atomic SQL UPDATE ... RETURNING" pairs with §7 / §8 — together they
  are correct, but the audit pack does not flag F3 (the
  `load_otpk_private`-ignores-`consumed_at` quirk). Worth adding a
  note: "the `consumed_at` column is GC-only; physical row deletion is
  the security-relevant event."

- `audit/THREAT_MODEL.md` row G ("State DPI") claim "Cannot identify
  ZeroCenter traffic by simple signature match" with status "⚠️
  partial — once ScrambleStream is wired (Phase 4b), naive matching
  fails" — the wording reads as if Phase 4b is still pending. Phase
  4b/4c.1/4c.2/4c.2′ are shipped per INVARIANTS §17. Update to "✅
  via ScrambleStream when `--obfs-key` is supplied, subject to F1".

## End of self-audit
