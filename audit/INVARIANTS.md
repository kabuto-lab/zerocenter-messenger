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
- `src/protocol/message.rs::DOMAIN_SEPARATOR = "zerocenter-dm-v1"` — direct-path DM envelope.
- `src/protocol/message.rs::SEALED_DOMAIN_SEPARATOR = "zerocenter-sealed-dm-v1"` — Phase 5 sealed-path DM envelope (see §22). Distinct from the direct domain so a captured direct signature can't be transplanted into a sealed envelope or vice versa.
- `src/core/identity.rs::PREKEY_SIG_DOMAIN = "zerocenter-prekey-v1"` — both signed prekey and OTPK (see §3).
- `src/main.rs` safety-number handler hashes under `b"zerocenter-safety-v1"` — not a signature, but same hygiene.

**Suggested attack.** Look for any code path that calls `Identity::sign(...)` or `keypair.sign(...)` without a domain-separated layout. Any such call is a potential collision source.

---

## §2. The PeerId of a signed sender is cross-checked against the transport peer (DIRECT path only)

**Statement.** When a DM arrives over `/zerocenter/direct-message/2.0.0` on the **direct path** (legacy: `from` + `signature` fields populated), the receiver verifies the application-layer Ed25519 signature AND checks that the libp2p transport-level peer matches the signed `from`. If either check fails, the message is dropped before any state change.

**For sealed-path envelopes** (Phase 5; see §22), the §3 transport-peer cross-check is **intentionally skipped**. The sender PeerId is encrypted inside the seal and decoupled from the transport-level source — this is the entire point of sealed sender. The inner signature inside the seal authenticates the sender; the transport peer is just a delivery agent (e.g. a DHT-mailbox provider). Skipping the cross-check is documented at the relevant code site.

**Why (direct path).** Without the cross-check, a connected peer can relay a captured direct-DM message and the receiver would treat it as direct delivery (impacting offline-delivery semantics).

**Why (sealed path).** A network observer relaying sealed envelopes doesn't know who sent them; we cannot meaningfully ask "did the transport peer match the signed sender" because we are explicitly trying to hide the sender from the transport. Authentication moves entirely to the inner signature.

**Enforced at.** `src/core/node.rs::process_incoming_dm` steps 2 and 3. The `sealed` boolean gates whether step 3 runs.

**Suggested attack (direct).** Build a transport peer that connects to victim and sends a captured direct-path `ProtocolMessage` signed by a third party. Cross-check should reject.

**Suggested attack (sealed).** Substitute the `from` field of a captured envelope while keeping `sealed_sender` intact. The new "from" doesn't matter — `from` is empty for sealed envelopes anyway; what authenticates is the inner signature, which is bound to the original sender PeerId encoded inside the seal. Tampering with the seal's plaintext is prevented by AEAD; tampering with `to`/`payload`/`timestamp`/`ttl` is prevented by the signature scope inside the seal.

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

## §17. ScrambleStream wiring (Phase 4b + 4c.1 + 4c.2 + 4c.2′ — shipped)

**Statement.** When `--obfs-key <32-byte hex>` is supplied, every byte on the TCP socket — *including* the libp2p Noise XX handshake — is XOR'd with a ChaCha20 keystream before it leaves the host, and inverted on receipt. The 32-byte key is pre-shared out of band; both peers must use the same one. The connection-opening handshake itself is hidden behind elligator2-encoded ephemerals so even the first 32 bytes look uniformly random.

**Per-connection key + nonce (Phase 4c.1 — NTOR-style hidden handshake, F1-fixed).** On connection open, each side generates an ephemeral X25519 keypair whose pubkey has an elligator2 `Randomized`-variant representative (retried up to 64 times against ~50% per-attempt success), sends the 32-byte representative on the wire, decodes the peer's 32-byte representative back to a Curve25519 pubkey, and runs X25519 DH to produce `shared_secret`. The handshake refuses `shared_secret == 0` (low-order peer pubkey defence; audit F2). From `shared_secret || obfs_key` (concatenated, 64 bytes) we HKDF-SHA256 with salt `"zerocenter-ntor-v1"` and derive **two** distinct 44-byte OKMs under role-distinguished info strings: `"zc-chacha-d2l-v1"` for dialer→listener traffic and `"zc-chacha-l2d-v1"` for listener→dialer. Each OKM splits into `(chacha_key[32] || chacha_nonce[12])`. The dialer's `out_cipher` initializes from the d2l pair and its `in_cipher` from l2d; the listener mirrors. Without the per-direction split, both peers' `out_cipher` and `in_cipher` would share a keystream — a two-time-pad on any bidirectional connection (audit F1, fixed at commit 2273cf5). After the 32-byte representative exchange (each direction), every subsequent byte is scrambled with the role-appropriate ChaCha20 instance — Noise's XX handshake, Yamux frames, request-response payloads. The pre-shared `obfs_key` keeps its role as the authenticator: a MITM substituting their own ephemerals derives a different OKM-pair and can't decrypt either side's scrambled stream.

**Frame padding (Phase 4c.2).** Above the byte-XOR layer sits a frame protocol: `[u16-be: payload_len] [payload_len bytes payload] [pad to FRAME_QUANTUM-multiple]` with `FRAME_QUANTUM = 256`. The whole frame (header + payload + pad) is XOR'd with the keystream as a unit, so an observer can't separate the header from the payload from the pad. Effect: every frame on the wire is a multiple of 256 bytes. A 48-byte Noise handshake message and a 200-byte DM both look like 256 bytes; a 300-byte DM looks like 512. This collapses the per-message size fingerprint that statistical DPI uses to identify libp2p.

**IAT jitter (Phase 4c.2′ — opt-in).** When `--obfs-jitter-ms <max>` is supplied alongside `--obfs-key`, every `poll_write` that's about to emit a NEW frame first waits a `uniform(0..=max)` ms delay. State machine: `pending_sleep: Option<Pin<Box<tokio::time::Sleep>>>` lives on the struct; `poll_write` drains `pending` first, then polls `pending_sleep` to completion if in progress, else rolls a fresh delay if `jitter_max_ms` is configured. Effect: a passive timing observer can no longer match ZeroCenter's wire-emission cadence against a known reference profile, within the configured window. Cost: up to `max` ms of added per-frame latency, which on a request-response DM path the user trades for traffic-analysis resistance. Default off — users who don't ask pay nothing.

**Enforced at.**
- `src/network/scramble.rs::scramble_handshake` — NTOR-style hidden handshake (elligator2 exchange → X25519 DH → HKDF over `shared || obfs_key`) + wrap; forwards `jitter_max_ms` into the resulting `ScrambleStream`.
- `src/network/scramble.rs::generate_representable_keypair` — retry-loop keygen with hard 64-attempt cap (failure is `io::Error::Other`, not silent — `2^-64` chance under a healthy RNG).
- `src/network/scramble.rs::ScrambleStream` — `futures::io::AsyncRead+AsyncWrite` impls that apply / invert the keystream, with a stateful `ReadState` enum driving the framed reader, a frame builder in `poll_write`, and a `pending_sleep` field that gates new-frame emission behind a per-frame jitter window.
- `src/network/scramble.rs::ScrambleStream::with_jitter` — constructor that wires `jitter_max_ms` into the stream.
- `src/network/scramble.rs::padded_frame_size` — quantizes frame totals to `FRAME_QUANTUM`.
- `src/network/scramble.rs::MaybeScrambled` — enum that lets the transport builder unify the with-obfs and without-obfs branches into one concrete Output type.
- `src/core/node.rs::P2PNode::start` — `.with_other_transport(|kp| ...)` replaces the previous `.with_tcp(...)` builder so the obfuscation `.and_then(...)` injection point sits BETWEEN `libp2p_tcp::tokio::Transport::new` and the `.upgrade().authenticate(noise).multiplex(yamux)` chain. `obfs_jitter_ms` is captured in the same closure and threaded into `scramble_handshake`.

**What this defeats.** A DPI box that fingerprints libp2p (e.g. by matching the Noise XX handshake pattern, by yamux frame headers, or by libp2p protocol-negotiation strings) sees only pseudo-random bytes once the obfs key is in play. With Phase 4c.1 NTOR the connection-opening 32 bytes (each direction) are elligator2-encoded ephemerals — computationally indistinguishable from uniform random — so there is no plaintext prefix to fingerprint. With frame padding (4c.2) the per-message size fingerprint is flattened to a 256-byte quantum, and with opt-in jitter (4c.2′) the inter-arrival timing of frames is randomised within the operator-chosen window.

**Pending buffer is hard-bounded.** `ScrambleStream::pending` is bounded at `MAX_PENDING_BYTES = 4 × FRAME_QUANTUM = 1024` bytes. Two reinforcing mechanisms enforce this: (1) `MAX_PAYLOAD_PER_FRAME = MAX_PENDING_BYTES − 2 = 1022` caps the size of any frame `poll_write` builds, so the parked frame on a Pending inner cannot exceed the bound; (2) `drain_pending` must fully empty `pending` before `poll_write` accepts new caller bytes, so frames never stack. A `debug_assert!` after every modification of `pending` triggers on any invariant violation under test builds. This also tightens the wire-level frame-size fingerprint: every observed frame sits in `{256, 512, 768, 1024}` bytes rather than being any 256-multiple up to ~65 KiB. Larger writes are split into multiple bounded frames by `write_all`'s natural retry loop; no caller-side API change.

**Known limitations.**
- Jitter is bounded above by `max` ms but distributionally uniform — a sophisticated observer with enough samples can still recover the underlying emission distribution. Mitigations (Pareto / piecewise-uniform / Poisson) are out of scope for v1; the goal here is to defeat off-the-shelf timing fingerprinters, not to provide an information-theoretic guarantee.
- The elligator2 `Randomized` variant masks the high two bits of the representative with a fresh `tweak` per attempt; the `to_representative` doc claims indistinguishability from uniform under standard cryptographic assumptions. We rely on the `curve25519-elligator2` crate (v0.1.0-alpha.2) for the constant-time implementation. Crate version is alpha; the surface we use is small (two functions: `Randomized::to_representative`, `EdwardsPoint::from_representative::<Randomized>`) but a reviewer should sanity-check the constant-time claims against the crate source.

**Short-inner-write resilience (fixed).** `ScrambleStream` carries a `pending: Vec<u8>` of scrambled-but-not-yet-handed-off bytes, bounded at `MAX_PENDING_BYTES` (see the "Pending buffer is hard-bounded" subsection above). On every `poll_write`/`poll_flush`/`poll_close` we drain `pending` BEFORE accepting new caller bytes via `drain_pending(...)`. The keystream is advanced exactly once per byte (at scramble time) and never re-advanced if the inner returns a short write — the un-accepted tail of the freshly-scrambled frame is parked in `pending` and re-tried later. The unit test `short_inner_writes_dont_desync_keystream` exercises this with a 16-byte inner duplex against a 1000-byte message; the reader uses `read_to_end` (not `read_exact`) so pad bytes are consumed in the natural read flow and the writer's flush+close terminates cleanly. The `large_payload_respects_pending_bound` test pushes 10 KiB through a 200-byte inner duplex and confirms the debug_assert never fires.

**Frame-padding test coverage.** `frame_padding_rounds_up_to_quantum` confirms 1/50/200/253-byte payloads all emit one 256-byte frame on the wire, and a 300-byte payload emits 512 bytes. `wire_bytes_are_not_plaintext` confirms the framed output contains no plaintext markers and is a `FRAME_QUANTUM`-multiple.

**Jitter test coverage.** `jitter_roundtrips_three_frames` writes three separate frames through a `ScrambleStream::with_jitter(Some(3))` and confirms all three round-trip bit-for-bit through a non-jittered reader — i.e. the sleep gating doesn't corrupt the byte stream, it only delays it. `jitter_zero_is_a_noop` confirms `Some(0)` behaves identically to `None` (no sleep created, no scheduler interaction).

**NTOR-handshake test coverage.** `ntor_handshake_roundtrips` confirms a paired dialer + listener with the same `obfs_key` derive the same (ChaCha20 key, nonce) and a post-handshake byte stream round-trips. `ntor_mismatched_obfs_keys_yield_unreadable_stream` confirms two peers with DIFFERENT `obfs_key`s complete the elligator2 exchange (the points are public) but their HKDFs diverge at `|| obfs_key` and neither side can decrypt the other — the test asserts the plaintext marker never appears in what the listener reads. `ntor_handshake_first_32_bytes_look_uniform` captures the dialer's first 32 bytes from two independent runs and asserts they differ (i.e. ephemerals are fresh per connection) and contain neither all-zeros nor all-ones (basic implementation-bug guard). `representable_keypair_succeeds` confirms the retry loop produces a valid keypair whose representative round-trips back to a curve point.

**Suggested attack.** Capture two connection openings between the same peer pair (same `obfs_key`). The first 32 bytes each direction are fresh ephemerals so they differ. Byte 65 onward XOR'd against bytes from the same handshake position in another capture should yield `XOR-of-keystreams = 0` if the derived ChaCha20 nonces collided (they shouldn't — `shared_secret` differs per connection, so the HKDF output differs). Run the unit test `ntor_handshake_first_32_bytes_look_uniform` for the in-tree analogue; for an end-to-end check, lift the ad-hoc two-peer smoke into a versioned `tests/scripts/two_peer_obfs.sh` (TODO).

**Suggested attack.** Connect to a peer WITHOUT `--obfs-key` while they have one configured (or vice versa). The peer with `--obfs-key` reads 32 bytes expecting an elligator2 representative; the peer without sends raw libp2p TCP bytes (the multistream-select preamble). The decode either fails (`from_representative` returns None → `InvalidData`) or succeeds-with-garbage; either way the X25519 DH below is meaningless and the upper-layer Noise handshake can't recover. The failure should be a clean transport error, not a hang.

**Suggested attack.** Build an MITM box that terminates the elligator2 exchange on both sides (acting as listener-to-dialer and as dialer-to-listener with its own ephemerals). Without the `obfs_key` the MITM derives two unrelated `(chacha_key, nonce)` pairs and can't translate between them — neither end's Noise handshake completes. The `ntor_mismatched_obfs_keys_yield_unreadable_stream` unit test exercises exactly this code path against a same-host duplex.

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

## §21. DHT mailbox is encrypted, signed, and dedups via the ratchet

**Statement.** When a sender publishes an offline-delivery drop to the DHT, the value at the Kad record is the SAME `ProtocolMessage` bytes that would have gone over the direct `request-response` channel — a signed envelope wrapping a Double-Ratchet `EncryptedPayload`. The recipient's ingestion pipeline (`process_incoming_dm`) is invoked identically for mailbox-fetched drops and for direct DMs: signature verification, expiry check (audit F5), transport-peer ↔ signed-sender cross-check (§2), AAD-bound ratchet decrypt (§6), and skipped-key cache (§5).

**Dedup via encrypt-once (Phase 5, fixes F8).** When `try_send_or_queue` finds the recipient disconnected AND we can ratchet-encrypt right now (session OR cached prekey), the offline branch calls `try_encrypt_offline` ONCE and feeds the resulting `ProtocolMessage` wire bytes into BOTH `outbox_add_wire` (new `is_wire_bytes` outbox column) AND `put_mailbox_drop_bytes`. When the recipient ingests via either path, the OTHER path's copy is byte-identical: the ratchet's already-consumed-mk check on the second arrival returns an AEAD failure (warn log only, no double-store). Older databases predating Phase 5 had a plaintext-only outbox; the SQL migration `ALTER TABLE outbox ADD COLUMN is_wire_bytes ... DEFAULT 0` runs idempotently at startup so legacy rows continue to drain through the old plaintext path. The "no session, no cached prekey" case still uses the plaintext outbox alone (mailbox can't help; can't encrypt without a key).

**ACK loop (Phase 5).** After successful mailbox-fetched decrypt the recipient publishes an empty record at `ack_kad_key(self, sender, slot)`. The sender's republish tick issues a `get_record(ack_kad_key)` for each due drop before the next `put_record`; on FoundRecord the sender calls `mailbox_drop_ack(id)` and that row is permanently skipped by `mailbox_drops_due_for_republish`. ACK records are NOT cryptographically authenticated in v0 — a malicious third party publishing a fake ACK can DoS the sender (one drop fails to deliver), but cannot impersonate a real recipient because the underlying message bytes are still authenticated by the ProtocolMessage signature; the legitimate recipient's eventual re-poll surfaces the drop from any DHT node that hasn't expired it. ACK publication is gated on `process_incoming_dm` returning `true` — a corrupt/forged drop that fails envelope-verify, transport-peer cross-check, or ratchet-decrypt does NOT generate an ACK, so the sender keeps trying.

**Why.** The mailbox layer must not introduce a parallel decryption path with different invariants. Reusing the exact `process_incoming_dm` entry-point keeps the security surface flat. The §2 cross-check still holds because the recipient verifies the `from` field of the signed envelope against the PeerId of the provider that fronted the Kad record (the `sender` argument passed into `process_incoming_dm`).

**Enforced at.**
- `src/network/mailbox.rs` — slot/key derivation; `slot_kad_key` and `drop_kad_key` use distinct domain separators (`"zerocenter-mailbox-v1"` vs `"zerocenter-mailbox-drop-v1"`) so the namespaces are disjoint.
- `src/core/node.rs::publish_mailbox_drop` — sender side; calls `ratchet_encrypt_and_wrap` for the same bytes the request-response path would have sent, then `put_record` + `start_providing`.
- `src/core/node.rs::handle_mailbox_record_result` — recipient side; routes fetched bytes through `process_incoming_dm` with the provider's PeerId as the transport-attribution argument.
- `src/core/node.rs::poll_mailbox_slots` — periodic recipient scan; caps fan-out at 24 slots (one day) per poll regardless of how long the recipient has been offline, so a fresh install doesn't blast the DHT.
- `src/core/node.rs::republish_mailbox_drops` — sender-side republish loop; reads `mailbox_drops_due_for_republish(REPUBLISH_AFTER_SECS=1800)` and re-puts each. Sender's own `mailbox_drops` row tracks `expires_at` (default 7 days) so unack'd drops self-prune.

**Known limitations.**
- **Metadata leak.** A passive observer of the providers DHT can correlate `(sender_pid, slot_kad_key(recipient_pid, slot))` and infer that `sender → recipient` traffic happened at some point during that hour. This is no worse than the direct-DM path (which exposes `from`/`to` in the unencrypted envelope) but is more durable: providers records persist in the DHT until Kad TTL expires. Phase 5 sealed-sender / onion routing addresses both paths.
- **No ACK in v0.** Storage scaffolding (`mailbox_drop_ack`) is unused; senders republish until 7-day `expires_at` even after the recipient successfully fetched. A future ACK can be carried out-of-band (a DM when next online) or as a separate Kad record at a derived key.
- **First-message-to-stranger can't use the mailbox.** Publishing requires either an existing ratchet session or a cached responder prekey to encrypt. Brand-new contacts whose prekey we've never fetched still fall back to the outbox-only path; the recipient must come online to us directly for the first message.

**Suggested attack.** Construct two mailbox drops at the same `(recipient, slot)` from two distinct senders. The recipient should fetch and decrypt both — the providers DHT must enumerate both senders, and each `drop_kad_key(recipient, sender, slot)` is distinct so the records don't overwrite.

**Suggested attack.** Tamper with a fetched `ProtocolMessage` value mid-DHT — flip a single bit in `record.value`. The recipient's `process_incoming_dm` invokes `ProtocolMessage::verify` first, which checks the Ed25519 signature; tamper detection is the same as for direct DMs. Mailbox storage does NOT add a separate integrity layer; the envelope signature suffices.

**Suggested attack.** Drop a `ProtocolMessage` whose `from` field does NOT match the provider PeerId fronting the record. The `process_incoming_dm` cross-check (§2 step 2) rejects it; the inconsistency between transport-attribution and signed-sender is enough to drop the message before any state change.

---

## §22. Sealed-sender envelope authentication chain (Phase 5)

**Statement.** When `ProtocolMessage::is_sealed()` is true, the sender's identity is encrypted inside `sealed_sender` and only the recipient (holder of the X25519 prekey private) can recover it. The authentication chain is:

1. **AEAD decrypt** with `(key, nonce)` derived from `HKDF(salt="zerocenter-sealed-sender-v1", ikm=X25519(recipient_prekey_priv, sealed[..32]))`. The first 32 wire bytes are the sender's per-message ephemeral X25519 pubkey. AEAD failure → drop.
2. **Cert parse:** length-prefixed `sender_pid_bytes || signature_bytes`. Malformed → drop.
3. **Sender pubkey extraction** from `sender_pid` via the embedded-protobuf-pubkey convention (multihash code = 0x00). Failure → drop.
4. **Signature verify** under the **sealed domain separator** `"zerocenter-sealed-dm-v1"` over `(to || sender_pid || payload || timestamp || ttl || msg_type)`. Mismatch → drop.

If all four pass, the sender PeerId is authenticated and the message proceeds through `process_incoming_dm` exactly as a direct-path message would (modulo §2's transport-peer cross-check being skipped).

**Why.** The sealed envelope hides the sender from the transport (relays, DHT-mailbox providers, on-path observers) while still allowing the recipient to verify the sender. The encryption guarantees confidentiality of the sender identity; the inner signature guarantees authenticity; the distinct domain separator (§1) prevents cross-path signature replay.

**Per-message forward secrecy at the seal layer.** The per-message ephemeral X25519 private key is dropped at end of `seal_sender_cert` and never persisted. A later compromise of the recipient's prekey does NOT let an attacker decrypt past sealed envelopes — they would also need the ephemeral private, which is gone.

**Limitations.**
- **Recipient PeerId is still clear.** The outer `to` field is required for libp2p routing (and for DHT-mailbox `slot_kad_key` derivation). Hiding the recipient requires onion routing, out of scope for Phase 5.
- **Timing / size correlation.** A passive observer who watches a sender's outbound TCP and a recipient's inbound TCP simultaneously can correlate by timing. The Phase 4c.2 frame padding and 4c.2′ jitter help but aren't sufficient against a global passive adversary.
- **First-contact fallback.** When the sender has no cached prekey for the recipient yet, the envelope falls back to the direct path (clear `from`). This happens once per fresh contact — after the recipient's prekey is fetched and cached, all subsequent sends are sealed. The fallback window is observable; a future improvement is to fetch the prekey synchronously and only send sealed.
- **ACK records are not sealed.** Phase-5 mailbox ACKs (commit 6df48ef) publish at `ack_kad_key(recipient, sender, slot)` with the recipient's PeerId as the value — that's a separate metadata leak. Documented; pluggable later.

**Enforced at.**
- `src/crypto/sealed.rs::seal_sender_cert` / `unseal_sender_cert` — the ECIES layer.
- `src/protocol/message.rs::ProtocolMessage::new_sealed` — sealed envelope construction.
- `src/protocol/message.rs::ProtocolMessage::verify_sealed` — recipient-side verification chain.
- `src/protocol/message.rs::SEALED_DOMAIN_SEPARATOR` — domain hygiene with §1.
- `src/core/node.rs::process_incoming_dm` — routes sealed vs direct based on `is_sealed()`, skips §2 for sealed.
- `src/core/node.rs::ratchet_encrypt_and_wrap` — picks sealed envelope when `cached_prekey(peer)` returns Some.

**Test coverage.**
- `crypto::sealed::tests` (6 tests) — ECIES roundtrip, wrong-key fail, AEAD tamper detection, ephemeral tamper detection, too-short input, randomness of ephemerals across seals.
- `protocol::message::tests::sealed_envelope_roundtrips_through_recipient` — end-to-end seal + unseal + signature verify.
- `protocol::message::tests::sealed_envelope_rejected_by_wrong_recipient` — confirms the X25519 keying gate.
- `protocol::message::tests::sealed_envelope_tampered_payload_fails_signature` — confirms the inner signature scope binds to the outer payload.
- `protocol::message::tests::sealed_signature_uses_distinct_domain` — confirms a direct-path signature wrapped in a sealed envelope fails verify (domain hygiene with §1).
- `protocol::message::tests::verify_sealed_rejects_direct_envelope` — and the inverse.

**Suggested attack.** Capture a sealed envelope and replay it. The inner signature scope includes `timestamp` and `ttl`, so `process_incoming_dm`'s `is_expired()` check (audit F5) drops replays past the TTL. Within the TTL, the ratchet's already-consumed-mk check (§4 / §6) makes the second arrival a silent no-op.

**Suggested attack.** Construct a sealed envelope addressed to victim, sealing a `sender_cert` with mallory's PeerId and mallory's signature. Victim decrypts the seal (mallory's signature verifies, mallory's identity is recovered as the sender). This is correct behavior — mallory really did send the envelope; sealed sender doesn't try to hide that. The recipient knows mallory is the author; the only protected secret is mallory's identity vis-à-vis the network transport. A reviewer should confirm the inner signature verifies under mallory's Ed25519 pubkey and rejects if any field (to/payload/ts/ttl/msg_type) was tampered.

---

## End of invariants

This list is not exhaustive — it captures what the implementers consider load-bearing. A reviewer should treat anything *not* listed here as also potentially load-bearing and dig in.
