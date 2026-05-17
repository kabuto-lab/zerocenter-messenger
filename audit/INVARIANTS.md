# INVARIANTS.md — Implementation Invariants for Code Review

This document lists numbered invariants the implementation must maintain for the security claims in [THREAT_MODEL.md](THREAT_MODEL.md) to hold. For each:
- **Statement** — what must always be true.
- **Why it matters** — which claim breaks if violated.
- **Enforced at** — file:symbol pointers.
- **Suggested attack** — how a reviewer might try to falsify it.

If you find an invariant that's stated here but **not** enforced (or enforced incorrectly), that's an audit finding.

---

## §1. Signed message envelopes are bound to a single protocol version

**Statement.** No two distinct constructions in ZeroCenter ever produce the same signed-bytes layout for the same Ed25519 key. Cross-protocol signature reuse is impossible.

**Why.** Without this, a signature collected under one purpose (e.g. a DM) could be replayed under another (e.g. a future control message), forging assertions the user never made.

**Enforced at.**
- `src/protocol/message.rs::DOMAIN_SEPARATOR = "zerocenter-dm-v1"` — DM envelope.
- `src/core/identity.rs::PREKEY_SIG_DOMAIN = "zerocenter-prekey-v1"` — both signed prekey and OTPK (see §3).
- `src/main.rs` safety-number handler hashes under `b"zerocenter-safety-v1"` — not a signature, but same hygiene.

**Suggested attack.** Look for any code path that calls `Identity::sign(...)` or `keypair.sign(...)` without a domain-separated layout. Any such call is a potential collision source.

---

## §2. The PeerId of a signed sender is cross-checked against the transport peer

**Statement.** When a DM arrives over `/zerocenter/direct-message/2.0.0`, the receiver verifies the application-layer Ed25519 signature AND checks that the libp2p transport-level peer matches the signed `from`. If either check fails, the message is dropped before any state change.

**Why.** Without the cross-check, a connected peer can relay a captured message and the receiver would treat it as direct delivery (impacting offline-delivery semantics in the future).

**Enforced at.** `src/core/node.rs::process_incoming_dm` steps 2 and 3.

**Suggested attack.** Build a transport peer that connects to victim and sends a captured `ProtocolMessage` signed by a third party. Cross-check should reject. If not — finding.

---

## §3. Prekey signature domain separator does not distinguish long-term vs one-time

**Statement.** Both the signed prekey and one-time prekeys are signed over the same bytes `prekey_signing_bytes(pub) = "zerocenter-prekey-v1" || pub`. Recipients learn which kind it is from the row in `my_otpks` vs the `signed_prekey` field — not from the signature itself.

**Why.** This is documented; the reviewer should consider if it creates risk. **Suggested risk:** an attacker who captures a long-term signed-prekey signature could re-present it as an OTPK signature (or vice versa), if the rest of the code accepts public-key bytes interchangeably. Currently the recipient's only use of the signature is "did identity X authorize this 32-byte X25519 key as a prekey of any kind for X3DH?" — and any "yes" is acceptable cryptographically. But it does mean OTPK semantics rest entirely on the database row, not on cryptographic binding.

**Where it could matter.** If a future feature distinguishes "may be used in 2-DH only" vs "may be used in 3-DH only" semantically, this domain separator would need to split into two.

**Suggested attack.** Send a `PrekeyResponse` with an OTPK field whose `signature` was actually a long-term signed-prekey signature for the same public key. Verifier accepts. Question: does anything downstream care? Currently — no, because the OTPK is just consumed for DH3. Future code should be careful.

---

## §4. AEAD nonce uniqueness per message key

**Statement.** Every `ChaCha20Poly1305::encrypt` call inside the ratchet uses a fresh `mk` derived from `KDF_CK`. The 12-byte nonce is fixed to zero, which is safe **because** each `mk` is used exactly once.

**Why.** ChaCha20-Poly1305 with nonce reuse under the same key is catastrophic (XOR of two ciphertexts reveals XOR of plaintexts; Poly1305 key recoverable).

**Enforced at.** `src/crypto/ratchet.rs::aead_encrypt` (fixed `&[0u8; 12]` nonce) + the contract that `mk` is derived per-message via `kdf_ck` in `encrypt` / `decrypt`.

**Suggested attack.** Find a code path where the same `mk` is used for two distinct encryptions. Note: the skipped-key cache reuses an `mk` once for the original send and once on out-of-order delivery — but the cached entry is **removed** after one decrypt success (`try_skipped` calls `remove` on hit), and the original write is the sender's single use. Confirm the cache eviction path doesn't allow `mk` to be re-derived after deletion.

---

## §5. Skipped-message-key cache is bounded

**Statement.** `RatchetState::skipped` never exceeds `MAX_SKIP = 1000` entries per session. Overflow is bounded by oldest-first eviction OR by rejecting the whole receive with `TooManySkipped`.

**Why.** Without a bound, a malicious peer can force unbounded memory growth by sending a single message with a very large header sequence number, demanding the receiver derive thousands of skipped keys.

**Enforced at.** `src/crypto/ratchet.rs::skip_message_keys`:
- Lines that check `until.saturating_sub(self.nr) + len(skipped) > MAX_SKIP` → return `TooManySkipped`.
- After the per-step loop, `while skipped.len() > MAX_SKIP { skipped.pop_front(); }` evicts.

**Suggested attack.** Send a single message with `header.n = u32::MAX`. Verify `TooManySkipped` returned without OOM. Then send many messages each requiring a small forward skip; verify pool stays ≤ MAX_SKIP.

---

## §6. AEAD AD binds the ratchet header AND both peer IDs

**Statement.** The AAD passed to ChaCha20-Poly1305 for every ratchet message is:
```
ratchet_ad(sender, recipient) || header.to_aad_bytes()
```
i.e. length-prefixed `sender_pid || recipient_pid` concatenated with `dh || pn_be || n_be`.

**Why.** Without the header in AAD, an active attacker could swap header fields (e.g. change `n` to confuse counters) and still produce a valid AEAD tag if they captured the right `mk`. Without the peer IDs in AAD, a message captured from session A→B could be replayed into a session involving different peers if the keys ever collided (e.g. by chance or by handshake reuse).

**Enforced at.**
- `src/crypto/ratchet.rs::aead_encrypt` / `aead_decrypt` — concatenate `ad || header.to_aad_bytes()`.
- `src/core/node.rs::ratchet_ad` — produces the peer-ID portion. Called from both `encrypt_and_send_existing` and `decrypt_first_message` / `decrypt_and_store`.

**Suggested attack.** Capture an Alice→Bob ciphertext. Try to feed it into Alice's session with Carol (which won't have the same keys, but check the wiring) — should fail at AEAD. Modify just `header.n` on a captured message and replay — should fail at AEAD. Modify the per-row `peer_id` in storage — irrelevant for AEAD (storage doesn't AAD-bind row context; see §11).

---

## §7. OTPK consumption is atomic and single-use

**Statement.** Each row in `my_otpks` is popped (and marked `consumed_at`) by AT MOST ONE concurrent prekey-fetch request. No two distinct initiators can derive a shared secret using the same OTPK.

**Why.** Reuse of an OTPK across two distinct initiator sessions weakens forward secrecy: a compromise of the OTPK private bytes reveals BOTH sessions' SKs, not just one.

**Enforced at.** `src/storage/store.rs::pop_unused_otpk` uses a single SQL `UPDATE ... RETURNING` that atomically marks consumed and returns the row. SQLite serializes this at the database lock level. Concurrent callers see one success and one no-row result.

**Suggested attack.** Construct two concurrent prekey requests to a victim. Verify they receive two DIFFERENT OTPKs (not the same one with `consumed_at` clobbered). Run the SQL by hand and check the lock semantics.

---

## §8. OTPK consume-on-publish, not consume-on-confirm

**Statement.** An OTPK is marked `consumed_at` at the moment it is included in a `PrekeyResponse` — NOT after the initiator successfully delivers the first message.

**Why.** Trade-off documented. Marking on confirm leaves a race window where two concurrent fetches both get the same OTPK. The chosen semantics is: every fetch burns one OTPK from the pool, even fetches that never lead to a real session. Pool size (20) is the buffer.

**Where to verify.** `src/storage/store.rs::pop_unused_otpk` — the `UPDATE` happens unconditionally on pop. The row is `delete_otpk`'d after successful first-decrypt in `bootstrap_responder_and_decrypt`, but that's just GC; the security-critical "this OTPK is no longer available" state is already set at pop time.

**Suggested attack.** Repeatedly fetch prekeys from a victim and never send a message — drain their OTPK pool. Verify the pool reseeds via `replenish_otpk_pool` (called in `start` and after each pop). If reseed is missing — DoS opening, finding.

---

## §9. Ratchet state, OTPK private, and message plaintext are encrypted at rest

**Statement.** Every byte written to `messages.ciphertext`, `ratchet_sessions.state_blob`, `my_otpks.x25519_priv`, and `outbox.ciphertext` passes through `MessageStore::encrypt_at_rest` before INSERT.

**Why.** A file-system attacker (Threat Model §D) reading the SQLite database directly must not be able to recover plaintext, session keys, or OTPK secrets.

**Enforced at.**
- `store_message` → `encrypt_at_rest`.
- `save_session` → `encrypt_at_rest`.
- `add_my_otpk` → `encrypt_at_rest` (on the private bytes only).
- `outbox_add` → `encrypt_at_rest`.

**Suggested attack.** Grep for callers of `INSERT INTO messages` / `ratchet_sessions` / `my_otpks` / `outbox` that bypass these methods. None should exist. Verify by reading raw blob bytes — they should be `[1, nonce(12), ct...]`. The tests `*_is_encrypted_at_rest` scan for plaintext markers.

---

## §10. Decrypt-failure on at-rest blobs returns errors / skips rows; never silently returns garbage

**Statement.** `decrypt_at_rest` returns `Err(...)` on AEAD failure. `load_session` propagates the error up. Read methods (`get_messages`, `get_recent_messages`, `get_conversation`, `outbox_get_for`) use `filter_map` to skip rows that fail to decrypt, with a `tracing::warn!`. They NEVER substitute fake data or treat garbage as plaintext.

**Why.** If a row was tampered or the DEK changed (e.g. keyring entry rotated), we must not display ciphertext as plaintext or trust forged session state.

**Enforced at.** `src/storage/store.rs::decrypt_at_rest` returns Result. Callers: `get_*_messages` filter_map; `load_session` propagates.

**Suggested attack.** Set the DEK to value A, write a session, then change DEK to value B and try to load_session — must error. Same for messages — must skip with warn, not crash, not return garbage.

---

## §11. At-rest AEAD does NOT bind row context

**Statement.** The AAD for `encrypt_at_rest` is the empty string. The blob is bound to its DEK and that's it.

**Why this is documented.** A file-system attacker with WRITE access could swap blobs between rows (e.g. copy Alice's session blob into Bob's row). AEAD does not detect this. The downstream `RatchetState` ratchet step would then run with the wrong peer's DH ratchet pubkey and AEAD would fail at the *next* message — but for that single moment, the application would believe Bob's session is what Alice's session looked like.

**Reviewer question.** Is this acceptable? An alternative is to bind the row's `peer_id` (or row id) into the AAD. Cost: one breaking change to the on-disk format.

---

## §12. DEK is never written to disk in plaintext

**Statement.** The 32-byte DEK lives in process memory and the OS keyring. It is never written to `<data_dir>/` or any other file under our control.

**Enforced at.** `src/crypto/keyring.rs::load_or_create_dek` — only writes to `keyring::Entry`. Returns the bytes to the caller (held in `MessageStore::dek` as `[u8; 32]`). No `std::fs::write` calls with DEK material.

**Suggested attack.** Grep all `std::fs::write` and `std::io::Write` paths for any call that touches DEK material. Should be none.

---

## §13. Identity.json contains the long-term Ed25519 + X25519 prekey in plaintext

**Statement.** This is a **deliberate exception** to §9 — explicitly documented in [THREAT_MODEL.md](THREAT_MODEL.md) §D. Encrypting `identity.json` requires another secret (chicken-and-egg) and the chosen acceptable risk is "user-account boundary = identity boundary."

**Suggested mitigation paths (out of scope for v1):**
- Encrypt with a key derived from an interactive passphrase (Argon2) at startup. UX cost.
- Encrypt with a key sealed by TPM / Secure Enclave. Hardware dependency.
- Symmetric encrypt with the DEK (but then the DEK encrypts the keys that bootstrap the DEK — circular). Could be broken by introducing a "boot DEK" that lives in keyring with a different account name.

---

## §14. Bootstrap addresses must contain `/p2p/<PeerId>` suffix

**Statement.** `--bootstrap` addresses missing the `/p2p/...` component are rejected at parse time and logged. The user is warned; startup continues with the remaining valid addresses.

**Why.** Without the PeerId, Kademlia can't index the address; the node would dial but never have a routable entry. Silent acceptance would lead to "the flag didn't work" confusion.

**Enforced at.** `src/core/node.rs::parse_bootstrap_addr`.

---

## §15. Outbox messages are bound to the sending DEK (not the wire AEAD)

**Statement.** A message in `outbox.ciphertext` is encrypted under the LOCAL DEK only. When drained, the plaintext is fed back into `try_send_or_queue` which goes through the normal ratchet encrypt path producing the actual wire ciphertext.

**Why this matters for review.** A reviewer might assume "encrypted twice" provides defense-in-depth. It doesn't — the outbox encryption protects against local disk read; the ratchet encryption protects against on-wire interception. They protect different things.

A corollary: if the local DEK is compromised, queued-but-not-yet-sent messages are recoverable as plaintext from the outbox even though their on-wire ciphertext would still be unreadable.

---

## §16. Pending in-memory state is lost on restart

**Statement.** `pending_sends` and `pending_recvs` and `cached_otpks` (all `HashMap` fields on `P2PNode`) are in-memory only. They do not survive process restart.

**Consequence.** If a user runs `send <bob_pid> hi`, that triggers a prekey fetch, and the user kills the process before the response arrives — the message is lost (it's in `pending_sends` but the queue was in memory). The user-facing CLI message says "queued" but it's only queued for this process lifetime.

**Suggested mitigation (deferred).** Promote pending_sends to a persistent table similar to `outbox` if this UX gap matters. Currently the outbox handles the "not connected" case persistently; only the "not connected to prekey-protocol yet" case is in-memory.

---

## §17. ScrambleStream wiring (Phase 4b — shipped)

**Statement.** When `--obfs-key <32-byte hex>` is supplied, every byte on the TCP socket — *including* the libp2p Noise XX handshake — is XOR'd with a ChaCha20 keystream before it leaves the host, and inverted on receipt. The 32-byte key is pre-shared out of band; both peers must use the same one.

**Per-connection nonce.** On connection open, the dialer generates 12 random bytes, writes them in the clear, and starts the ChaCha20 keystream. The listener reads 12 bytes from the wire and starts the matching keystream. After that point, every subsequent byte is scrambled — Noise's XX handshake, Yamux frames, request-response payloads.

**Enforced at.**
- `src/network/scramble.rs::scramble_handshake` — nonce exchange + wrap.
- `src/network/scramble.rs::ScrambleStream` — `futures::io::AsyncRead+AsyncWrite` impls that apply / invert the keystream.
- `src/network/scramble.rs::MaybeScrambled` — enum that lets the transport builder unify the with-obfs and without-obfs branches into one concrete Output type.
- `src/core/node.rs::P2PNode::start` — `.with_other_transport(|kp| ...)` replaces the previous `.with_tcp(...)` builder so the obfuscation `.and_then(...)` injection point sits BETWEEN `libp2p_tcp::tokio::Transport::new` and the `.upgrade().authenticate(noise).multiplex(yamux)` chain.

**What this defeats.** A DPI box that fingerprints libp2p (e.g. by matching the Noise XX handshake pattern, by yamux frame headers, or by libp2p protocol-negotiation strings) sees only pseudo-random bytes once the obfs key is in play. The 12-byte in-clear nonce header is the only structural artefact left — it looks like 12 random bytes followed by more random bytes.

**Known limitations (Phase 4c candidates).**
- The 12-byte nonce header is in the clear. Real Obfs4 derives the nonce from an NTOR-like handshake so there is no plaintext prefix.
- No length padding, no inter-arrival-time jitter — statistical traffic analysis can still distinguish ZeroCenter traffic from cover noise.

**Short-inner-write resilience (fixed).** `ScrambleStream` carries a `pending: Vec<u8>` of scrambled-but-not-yet-handed-off bytes. On every `poll_write`/`poll_flush`/`poll_close` we drain `pending` BEFORE accepting new caller bytes via `drain_pending(...)`. The keystream is advanced exactly once per byte (at scramble time) and never re-advanced if the inner returns a short write — the un-accepted tail of `scratch` is parked in `pending` and re-tried later. The unit test `short_inner_writes_dont_desync_keystream` exercises this with a 16-byte inner duplex against a 1000-byte message.

**Suggested attack.** Capture two connection openings between the same peer pair. The 12-byte prefixes will differ (random) but byte 13 onward XOR'd against bytes from the same handshake position should yield XOR-of-keystreams = `0` if the same nonce was reused (it isn't — fresh per connection). Confirm via the integration smoke `tests/scripts/two_peer_obfs.sh` (TODO: lift the ad-hoc smoke we ran into a versioned test).

**Suggested attack.** Connect to a peer WITHOUT `--obfs-key` while they have one configured (or vice versa). The Noise XX handshake should fail because one side's "first 12 bytes" become randomized keystream the other side wasn't expecting. Verify the failure mode is a clean Noise timeout, not a hang.

---

## §18. No cryptographic operation runs in non-async contexts that could starve the event loop

**Statement.** Per-message AEAD, KDFs, and Ed25519 sign/verify all run synchronously inside the tokio task that drives the swarm. Throughput is bounded by the slowest of these on a single core. No bounded thread pool.

**Why.** For an audit: this is not a security invariant per se but a DoS surface — a peer flooding ratchet messages forces the receiver to run KDF + AEAD per message on the main event loop. Likely fine for realistic message rates; worth flagging.

---

## §19. Tracing logs may contain sensitive material

**Statement.** `tracing::info!` / `warn!` log lines include peer IDs, error context, and outbox events — but NOT message plaintext at `info` or above.

**History.** Earlier revisions emitted plaintext at `info!` in three sites
(`Send requested to ...: <msg>`, `Decrypted first DM from ...: <pt>`,
`Decrypted DM from ...: <pt>`). These were downgraded to `debug!`; the
plaintext still reaches the user via `println!` to stdout (intentional
terminal output), but no longer rides the `tracing` info channel where
it could land in a remote log aggregator.

**Why this matters.** If logs are sent to a remote aggregator, the aggregator must not see plaintext. For local-only logs this matches the "user trusts their own machine" threat model.

**How to verify.** Grep `src/core/node.rs` for `info!` and `warn!`; only PeerIds, error strings, and counts should appear in the format args — never `&plaintext`, `text` (`String::from_utf8_lossy(&plaintext)`), or `message` (the `String` carried by `NodeCommand::Send`). The `println!` lines that render `🔓 {}: {}` are deliberate UI output and out of scope.

**Future risk.** Any new path that handles plaintext bytes is a candidate for the same bug. A reviewer adding a new log line should default to `debug!` for anything that touched decrypted content.

---

## §20. The `gui` feature is a build-time switch, not a runtime one

**Statement.** Passing `--gui` on a binary built without `--features gui` exits with an error explaining the build situation. The GUI cannot be enabled at runtime in a CLI build.

**Why.** Tauri pulls a webview and a build script — these can't be lazily loaded. Decoupling at build time keeps the headless CLI slim.

**Enforced at.** `src/main.rs::run_gui` with `#[cfg(feature = "gui")]` and `#[cfg(not(feature = "gui"))]` arms.

---

## End of invariants

This list is not exhaustive — it captures what the implementers consider load-bearing. A reviewer should treat anything *not* listed here as also potentially load-bearing and dig in.
