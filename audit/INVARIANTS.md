# INVARIANTS.md — Implementation Invariants for Code Review

This document lists numbered invariants the implementation must maintain for the security claims in [THREAT_MODEL.md](THREAT_MODEL.md) to hold. For each:
- **Statement** — what must always be true.
- **Why it matters** — which claim breaks if violated.
- **Enforced at** — file:symbol pointers.
- **Suggested attack** — how a reviewer might try to falsify it.

If you find an invariant that's stated here but **not** enforced (or enforced incorrectly), that's an audit finding.

---

## §1. Signed message envelopes are bound to a single protocol version

**Statement.** No two distinct constructions in ME55 ever produce the same signed-bytes layout for the same Ed25519 key. Cross-protocol signature reuse is impossible.

**Why.** Without this, a signature collected under one purpose (e.g. a DM) could be replayed under another (e.g. a future control message), forging assertions the user never made.

**Enforced at.**
- `src/protocol/message.rs::DOMAIN_SEPARATOR = "ME55-dm-v1"` — direct-path DM envelope.
- `src/protocol/message.rs::SEALED_DOMAIN_SEPARATOR = "ME55-sealed-dm-v1"` — Phase 5 sealed-path DM envelope (see §22). Distinct from the direct domain so a captured direct signature can't be transplanted into a sealed envelope or vice versa.
- `src/core/identity.rs::PREKEY_SIG_DOMAIN = "ME55-prekey-v1"` — both signed prekey and OTPK (see §3).
- `src/core/identity.rs::ML_KEM_PREKEY_SIG_DOMAIN = "ME55-ml-kem-prekey-v1"` — Phase 2 PQ prekey (see §27). Distinct from the X25519 prekey signature so a captured X25519-prekey signature can't be transplanted onto the ML-KEM encapsulation key.
- `src/crypto/x3dh.rs::X3DH_INFO = "ME55-x3dh-v1"` — classical 2-DH X3DH HKDF info tag.
- `src/crypto/x3dh.rs::X3DH_INFO_OTPK = "ME55-x3dh-otpk-v1"` — classical 3-DH X3DH HKDF info tag.
- `src/crypto/x3dh.rs::X3DH_INFO_PQ = "ME55-x3dh-pq-v1"` — Phase 2 hybrid 2-DH X3DH HKDF info tag (see §27). Distinct from classical so a downgrade-attacked classical SK never collides with a hybrid SK.
- `src/crypto/x3dh.rs::X3DH_INFO_OTPK_PQ = "ME55-x3dh-otpk-pq-v1"` — Phase 2 hybrid 3-DH X3DH HKDF info tag.
- `src/crypto/ratchet.rs::SESSION_ID_DOMAIN = "ME55-session-id-v1"` — Phase 4 session id derivation HMAC tag (see §28).
- `src/network/mailbox.rs::SESSION_DROP_KEY_DOMAIN = "ME55-session-mailbox-drop-v1"` — Phase 4 session-keyed mailbox drop addressing. Distinct from `ME55-mailbox-drop-v1` so the two namespaces are disjoint.
- `src/network/mailbox.rs::SESSION_ACK_KEY_DOMAIN = "ME55-session-mailbox-ack-v1"` — Phase 4 session-keyed mailbox ACK addressing.
- `src/main.rs` safety-number handler hashes under `b"ME55-safety-v1"` — not a signature, but same hygiene.

**Suggested attack.** Look for any code path that calls `Identity::sign(...)` or `keypair.sign(...)` without a domain-separated layout. Any such call is a potential collision source.

---

## §2. The PeerId of a signed sender is cross-checked against the transport peer (DIRECT path only)

**Statement.** When a DM arrives over `/ME55/direct-message/2.0.0` on the **direct path** (legacy: `from` + `signature` fields populated), the receiver verifies the application-layer Ed25519 signature AND checks that the libp2p transport-level peer matches the signed `from`. If either check fails, the message is dropped before any state change.

**For sealed-path envelopes** (Phase 5; see §22), the §3 transport-peer cross-check is **intentionally skipped**. The sender PeerId is encrypted inside the seal and decoupled from the transport-level source — this is the entire point of sealed sender. The inner signature inside the seal authenticates the sender; the transport peer is just a delivery agent (e.g. a DHT-mailbox provider). Skipping the cross-check is documented at the relevant code site.

**For Phase 3 deniable envelopes** (`--deniable-dm` opt-in; see §29), the per-message Ed25519 signature is OMITTED on both direct and sealed paths. `verify()` and `verify_sealed()` then return the parsed sender PeerId WITHOUT a cryptographic check — authentication of the message body has moved entirely to the downstream ratchet AEAD (whose key is shared by the two session participants and rotates per message). The §3 transport-peer cross-check still runs for direct deniable envelopes; it gives a coarse "this sender claim matches the transport peer" but is no longer cryptographic, just a sanity gate.

**Why (direct path).** Without the cross-check, a connected peer can relay a captured direct-DM message and the receiver would treat it as direct delivery (impacting offline-delivery semantics).

**Why (sealed path).** A network observer relaying sealed envelopes doesn't know who sent them; we cannot meaningfully ask "did the transport peer match the signed sender" because we are explicitly trying to hide the sender from the transport. Authentication moves entirely to the inner signature.

**Enforced at.** `src/core/node.rs::process_incoming_dm` steps 2 and 3. The `sealed` boolean gates whether step 3 runs.

**Suggested attack (direct).** Build a transport peer that connects to victim and sends a captured direct-path `ProtocolMessage` signed by a third party. Cross-check should reject.

**Suggested attack (sealed).** Substitute the `from` field of a captured envelope while keeping `sealed_sender` intact. The new "from" doesn't matter — `from` is empty for sealed envelopes anyway; what authenticates is the inner signature, which is bound to the original sender PeerId encoded inside the seal. Tampering with the seal's plaintext is prevented by AEAD; tampering with `to`/`payload`/`timestamp`/`ttl` is prevented by the signature scope inside the seal.

---

## §3. Prekey signature domain separator does not distinguish long-term vs one-time

**Statement.** Both the signed prekey and one-time prekeys are signed over the same bytes `prekey_signing_bytes(pub) = "ME55-prekey-v1" || pub`. Recipients learn which kind it is from the row in `my_otpks` vs the `signed_prekey` field — not from the signature itself.

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

**Why.** Trade-off documented. Marking on confirm leaves a race window where two concurrent fetches both get the same OTPK. The chosen semantics is: every fetch burns one OTPK from the pool, even fetches that never lead to a real session. Pool size (now 100 after Phase 5; see §23) is the buffer.

**Where to verify.** `src/storage/store.rs::pop_unused_otpk` — the `UPDATE` happens unconditionally on pop. The row is `delete_otpk`'d after successful first-decrypt in `bootstrap_responder_and_decrypt`, but that's just GC; the security-critical "this OTPK is no longer available" state is already set at pop time.

**Suggested attack.** Repeatedly fetch prekeys from a victim and never send a message — drain their OTPK pool. Verify the pool reseeds via `replenish_otpk_pool` (called in `start` and after each pop) AND the per-peer rate limit (§23) blunts the attack within a single attacker identity.

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

**Per-connection key + nonce (Phase 4c.1 — NTOR-style hidden handshake, F1-fixed).** On connection open, each side generates an ephemeral X25519 keypair whose pubkey has an elligator2 `Randomized`-variant representative (retried up to 64 times against ~50% per-attempt success), sends the 32-byte representative on the wire, decodes the peer's 32-byte representative back to a Curve25519 pubkey, and runs X25519 DH to produce `shared_secret`. The handshake refuses `shared_secret == 0` (low-order peer pubkey defence; audit F2). From `shared_secret || obfs_key` (concatenated, 64 bytes) we HKDF-SHA256 with salt `"ME55-ntor-v1"` and derive **two** distinct 44-byte OKMs under role-distinguished info strings: `"zc-chacha-d2l-v1"` for dialer→listener traffic and `"zc-chacha-l2d-v1"` for listener→dialer. Each OKM splits into `(chacha_key[32] || chacha_nonce[12])`. The dialer's `out_cipher` initializes from the d2l pair and its `in_cipher` from l2d; the listener mirrors. Without the per-direction split, both peers' `out_cipher` and `in_cipher` would share a keystream — a two-time-pad on any bidirectional connection (audit F1, fixed at commit 2273cf5). After the 32-byte representative exchange (each direction), every subsequent byte is scrambled with the role-appropriate ChaCha20 instance — Noise's XX handshake, Yamux frames, request-response payloads. The pre-shared `obfs_key` keeps its role as the authenticator: a MITM substituting their own ephemerals derives a different OKM-pair and can't decrypt either side's scrambled stream.

**Frame padding (Phase 4c.2).** Above the byte-XOR layer sits a frame protocol: `[u16-be: payload_len] [payload_len bytes payload] [pad to FRAME_QUANTUM-multiple]` with `FRAME_QUANTUM = 256`. The whole frame (header + payload + pad) is XOR'd with the keystream as a unit, so an observer can't separate the header from the payload from the pad. Effect: every frame on the wire is a multiple of 256 bytes. A 48-byte Noise handshake message and a 200-byte DM both look like 256 bytes; a 300-byte DM looks like 512. This collapses the per-message size fingerprint that statistical DPI uses to identify libp2p.

**IAT jitter (Phase 4c.2′ — opt-in).** When `--obfs-jitter-ms <max>` is supplied alongside `--obfs-key`, every `poll_write` that's about to emit a NEW frame first waits a `uniform(0..=max)` ms delay. State machine: `pending_sleep: Option<Pin<Box<tokio::time::Sleep>>>` lives on the struct; `poll_write` drains `pending` first, then polls `pending_sleep` to completion if in progress, else rolls a fresh delay if `jitter_max_ms` is configured. Effect: a passive timing observer can no longer match ME55's wire-emission cadence against a known reference profile, within the configured window. Cost: up to `max` ms of added per-frame latency, which on a request-response DM path the user trades for traffic-analysis resistance. Default off — users who don't ask pay nothing.

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
- `src/network/mailbox.rs` — slot/key derivation; `slot_kad_key` and `drop_kad_key` use distinct domain separators (`"ME55-mailbox-v1"` vs `"ME55-mailbox-drop-v1"`) so the namespaces are disjoint.
- `src/core/node.rs::publish_mailbox_drop` — sender side; calls `ratchet_encrypt_and_wrap` for the same bytes the request-response path would have sent, then `put_record` + `start_providing`.
- `src/core/node.rs::handle_mailbox_record_result` — recipient side; routes fetched bytes through `process_incoming_dm` with the provider's PeerId as the transport-attribution argument.
- `src/core/node.rs::poll_mailbox_slots` — periodic recipient scan; caps fan-out at 24 slots (one day) per poll regardless of how long the recipient has been offline, so a fresh install doesn't blast the DHT.
- `src/core/node.rs::republish_mailbox_drops` — sender-side republish loop; reads `mailbox_drops_due_for_republish(REPUBLISH_AFTER_SECS=1800)` and re-puts each. Sender's own `mailbox_drops` row tracks `expires_at` (default 7 days) so unack'd drops self-prune.

**Known limitations.**
- **Phase-4 session-keyed addressing closes the legacy metadata leak for established sessions** (see §28). A passive observer of the DHT no longer sees `(sender_pid, recipient_pid)` for drops between peers with an active Double-Ratchet session — the drop is published in PARALLEL under `session_drop_kad_key(session_id, slot)`, whose preimage contains no PeerId. The legacy `drop_kad_key(recipient, sender, slot)` is also still published for the Phase-4 migration window so pre-Phase-4 recipients can still fetch; this means the legacy leak survives until both ends are Phase-4, after which we can drop the legacy publish path.
- **First-contact (no session) still leaks via legacy keys.** Until X3DH completes there is no `session_id`, so the drop can only be published under the legacy `drop_kad_key`. The first message metadata is still visible; subsequent messages migrate to session-keyed addressing.
- **First-message-to-stranger can't use the mailbox at all.** Publishing requires either an existing ratchet session or a cached responder prekey to encrypt. Brand-new contacts whose prekey we've never fetched still fall back to the outbox-only path; the recipient must come online to us directly for the first message.

**Suggested attack.** Construct two mailbox drops at the same `(recipient, slot)` from two distinct senders. The recipient should fetch and decrypt both — the providers DHT must enumerate both senders, and each `drop_kad_key(recipient, sender, slot)` is distinct so the records don't overwrite.

**Suggested attack.** Tamper with a fetched `ProtocolMessage` value mid-DHT — flip a single bit in `record.value`. The recipient's `process_incoming_dm` invokes `ProtocolMessage::verify` first, which checks the Ed25519 signature; tamper detection is the same as for direct DMs. Mailbox storage does NOT add a separate integrity layer; the envelope signature suffices.

**Suggested attack.** Drop a `ProtocolMessage` whose `from` field does NOT match the provider PeerId fronting the record. The `process_incoming_dm` cross-check (§2 step 2) rejects it; the inconsistency between transport-attribution and signed-sender is enough to drop the message before any state change.

---

## §22. Sealed-sender envelope authentication chain (Phase 5)

**Statement.** When `ProtocolMessage::is_sealed()` is true, the sender's identity is encrypted inside `sealed_sender` and only the recipient (holder of the X25519 prekey private) can recover it. The authentication chain is:

1. **AEAD decrypt** with `(key, nonce)` derived from `HKDF(salt="ME55-sealed-sender-v1", ikm=X25519(recipient_prekey_priv, sealed[..32]))`. The first 32 wire bytes are the sender's per-message ephemeral X25519 pubkey. AEAD failure → drop.
2. **Cert parse:** length-prefixed `sender_pid_bytes || signature_bytes`. Malformed → drop.
3. **Sender pubkey extraction** from `sender_pid` via the embedded-protobuf-pubkey convention (multihash code = 0x00). Failure → drop.
4. **Signature verify** under the **sealed domain separator** `"ME55-sealed-dm-v1"` over `(to || sender_pid || payload || timestamp || ttl || msg_type)`. Mismatch → drop.

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

## §23. OTPK pool-drain defence (Phase 5)

**Statement.** A single remote peer cannot drain our one-time-prekey pool by rapid-fire `PrekeyRequest`s. The responder honors AT MOST one OTPK-attached `PrekeyResponse` per peer per `OTPK_FETCH_COOLDOWN_SECS = 60` seconds. Within that window, subsequent requests from the same peer still receive a valid signed-prekey response, but with `otpk: None` — forcing the requester into the 2-DH variant of X3DH for their subsequent attempts.

**Why.** Without per-peer rate limiting, an attacker who can rapidly issue `PrekeyRequest`s drains the OTPK pool faster than `replenish_otpk_pool` can refill, forcing every subsequent legitimate first-message into 2-DH (weaker forward secrecy than 3-DH). The pool size (`OTPK_POOL_TARGET = 100`, bumped from 20 in Phase 5) gives a raw cost-to-drain of 100 OTPKs per uncoordinated attacker; the per-peer cooldown caps a single PeerId's throughput at `1 OTPK / cooldown` — making a single-identity drain attack arbitrarily slow.

**Sybil note.** An attacker who can produce many PeerIds can bypass the per-peer limit by rotating identities. Each Sybil identity has the same `1 / cooldown` ceiling though, so the total attacker throughput is `N_sybils × (1 OTPK / cooldown)`. With `OTPK_POOL_TARGET = 100` and `cooldown = 60s`, the attacker needs 100 Sybil identities active simultaneously to keep the pool depleted indefinitely. Per-IP rate limiting at the transport layer would compound this — currently not implemented (libp2p transport limits exist but aren't tied to our application gate).

**Enforced at.**
- `src/core/node.rs::OTPK_POOL_TARGET = 100` — raw pool depth.
- `src/core/node.rs::OTPK_FETCH_COOLDOWN_SECS = 60` — per-peer cooldown.
- `src/core/node.rs::should_attach_otpk` — gate predicate, delegated to the pure helper `check_and_update_otpk_gate(map, peer, now, cooldown)` for unit-testability.
- `src/core/node.rs::handle_prekey_event` Request arm — gate before `pop_one_otpk_bundle`.
- `src/core/node.rs::prune_recent_otpk_fetches` — periodic prune of the tracking map (called from the hourly cleanup tick) so the map can't grow unboundedly.

**What this DOES NOT defend against.**
- A patient attacker who waits `cooldown` seconds between requests can still drain the pool from a single identity, eventually. The fix there is either a larger cooldown or a smaller per-peer total quota — out of scope for v0.
- An attacker who controls a Sybil army (cheap PeerId generation) can bypass per-peer limits. Mitigation: IP-level rate limiting or PoW on prekey-fetch, both substantial additions.
- A legitimate user with a flaky network who retries their PrekeyRequest within 60s will get a `None` OTPK on the retry and fall back to 2-DH for that send. This is a deliberate trade-off; 2-DH still has post-compromise security from the ratchet step, just weaker first-message FS.

**Test coverage.** `otpk_gate_tests` (4 tests, file-bottom in `node.rs`): first-call-allows-and-records, repeat-within-cooldown-is-blocked, repeat-past-cooldown-is-allowed, distinct-peers-do-not-share-the-cooldown.

**Suggested attack.** Issue 200 PrekeyRequests from a single PeerId in 1 second. Expected: 1 honored OTPK, 199 None-OTPK responses, all with valid signed-prekey. Pool deficit: 1 per minute per identity ceiling.

---

## §24. Per-message Ed25519 signatures prevent cross-member impersonation in groups (Phase 5)

**Statement.** Every group message (`EncryptedPayload.kind = 2`) carries an Ed25519 signature produced under the sender's per-chain signing key, with canonical signing bytes prefixed by `GROUP_MSG_DOMAIN_SEPARATOR = b"ME55-group-msg-v1"` and binding `(group_id, sender_pid)` via the associated-data scope. Receivers verify the signature **before any chain state mutation** using the `verify_pub` field of the locally-cached `ReceiverChain` (installed from a `SenderKeyBundle` delivered over the outer 1:1 DR session). Decryption only proceeds on signature success.

**Why.** Each member of a group ends up with every other member's symmetric `chain_key` (it's part of the `SenderKeyBundle` they distribute), so without the Ed25519 sig any member could mint a ciphertext claiming to be from any other chain owner. The per-message signature is the unforgeable bind from "ciphertext at index N on chain X" to "signed by the owner of chain X". The `(group_id, sender_pid)` AD prevents a captured ciphertext from being replayed under a different group context or attributed to a different sender.

**Enforced at.**
- `src/crypto/megolm.rs::canonical_sign_bytes` — canonical layout `DOMAIN || index_be || ad_len_be || ad || ct_len_be || ct`, every variable-length field length-prefixed.
- `src/crypto/megolm.rs::SenderChain::encrypt` — Ed25519 sign with `sign_priv` from the chain's birth.
- `src/crypto/megolm.rs::ReceiverChain::decrypt` — `VerifyingKey::from_bytes` + `verify(canonical, sig)` is step 1, before the past-message lookup or chain-forward walk. A signature failure is a no-op on chain state (the function returns `Err(BadSignature)` immediately).
- `src/protocol/group.rs::build_group_ad` — `group_id (32) || sender_pid_len_be (4) || sender_pid` AD layout.

**Test coverage.**
- `crypto::megolm::tests::signature_tamper_rejected_before_state_mutation` — sig flip → `BadSignature` AND chain state unchanged.
- `crypto::megolm::tests::ciphertext_tamper_rejected_by_signature` — ct flip → `BadSignature` (caught by sig before AEAD).
- `crypto::megolm::tests::ad_mismatch_rejected_by_signature` — verifier uses a different AD → `BadSignature`.
- `crypto::megolm::tests::cross_chain_message_rejected_by_signature` — ciphertext from chain A rejected by chain B's verifier.
- `protocol::group::tests::group_ad_mismatch_breaks_megolm_decrypt` — AD swap on receive side fails verification.

**Suggested attack.** Obtain Bob's `chain_key` (e.g. as a co-member of a group). Mint a ciphertext under that key at some index, signed by your own Ed25519. Send to Carol. Carol's `their_sender_keys[(group_id, bob_pid)].verify_pub` is Bob's verify key, not yours — verify fails before any state mutation. Now try the reverse: substitute Bob's verify_pub into your fake ReceiverChain row. To install that row you'd need to deliver a SenderKeyDistribution claiming to be from Bob over the 1:1 DR channel, which requires Bob's DR session keys (out of scope of in-group attackers).

---

## §25. Group membership state is only valid under founder Ed25519 signature (Phase 5)

**Statement.** Three protocol points enforce the founder authority model:

1. **CreateGroup acceptance.** A recipient installs a `GroupControl::CreateGroup` row only if (a) `founder_sig` verifies against `founder_pid`'s embedded Ed25519 pubkey under `canonical_create_bytes`, (b) the outer DR sender PeerId equals `founder_pid`, and (c) the recipient is in the `members` list. (a) prevents forgery; (b) prevents a stranger from spoofing the founder field; (c) prevents being silently added to a group you're not in.

2. **MembershipUpdate acceptance.** A recipient applies a `GroupControl::MembershipUpdate` only if `founder_sig` verifies against the **locally-stored** `groups.founder_pid` for the named `group_id` (not a founder PID that might be embedded in the update — the update carries no such field). This forces the verifier to use a founder PID they previously committed to via the matching CreateGroup, preventing a stranger from spoofing updates against a group they didn't found.

3. **Epoch monotonicity.** A `MembershipUpdate` with `epoch <= stored_row.epoch` is rejected as a stale replay before any state mutation.

`Leave` is also signed (`leaver_sig` over `canonical_leave_bytes` under the leaver's identity), so other members can verify the announcement even when the leaver isn't currently a peer of theirs at the moment they see the message (e.g. forwarded via a relay).

`SenderKeyDistribution` is the one variant that carries no inner signature — authentication is inherited from the outer 1:1 DR session that already authenticates the sender. Recipients additionally check that the DR-verified sender is in the local `group_members` list before installing the bundle.

**Why.** Without founder authority, anyone could push membership state changes (silently add a Sybil to spy, kick a legitimate member out of fanout). Without epoch monotonicity, an attacker who captured an old MembershipUpdate could replay it after a contradictory update has already been applied, re-introducing a removed member.

**Enforced at.**
- `src/protocol/group.rs::GROUP_CTRL_DOMAIN_SEPARATOR = b"ME55-group-ctrl-v1"` — distinct from §1's DM/sealed domain separators so a captured DM signature can't be replayed as group control authorization.
- `src/protocol/group.rs::canonical_create_bytes` / `canonical_update_bytes` / `canonical_leave_bytes` — canonical signing bytes with length-prefixed variable fields. Member lists are sorted before encoding so semantically-equal sets produce byte-identical signatures (defends against subtle re-ordering attempts).
- `src/protocol/group.rs::GroupControl::verify_signature` — covers CreateGroup, Leave, SenderKeyDistribution.
- `src/protocol/group.rs::GroupControl::verify_membership_update(founder_pid)` — caller MUST supply the locally-stored founder PID; the plain `verify_signature` deliberately returns `BadSignature` for the MembershipUpdate variant so a careless call site can't accept an unverified update.
- `src/core/node.rs::process_group_control` — three arms (`CreateGroup`, `MembershipUpdate`, `Leave`) each verify the relevant signature; the `MembershipUpdate` arm additionally enforces `epoch > stored_row.epoch`.

**Test coverage.**
- `protocol::group::tests::create_group_signs_and_verifies` — happy path.
- `protocol::group::tests::create_group_tampered_member_list_fails` — drop one member → BadSignature.
- `protocol::group::tests::create_group_member_order_does_not_affect_sig` — sorted-canonical bytes give byte-identical signatures regardless of insert order.
- `protocol::group::tests::membership_update_verifies_against_founder_pid` — plain `verify_signature` returns BadSignature; `verify_membership_update(founder_pid)` succeeds.
- `protocol::group::tests::membership_update_wrong_founder_fails` — attaching the wrong founder PID at verify time fails.
- `protocol::group::tests::leave_signs_and_verifies` and `leave_with_wrong_keypair_fails_verify`.

**Suggested attack.**
- Replay a CreateGroup with a swapped `founder_pid` field but the same `founder_sig` — `canonical_create_bytes` includes `founder_pid` so the sig binding fails.
- Mint a MembershipUpdate signed by your own Ed25519, send to a group you're a member of. Recipient looks up the locally-stored `groups.founder_pid` (which is the real founder) and verifies your sig against it → fails.
- Capture epoch=N from the wire, wait for the founder to issue epoch=N+1 (e.g. removing a Sybil), then replay epoch=N to re-introduce the Sybil — recipient sees `epoch=N <= stored=N+1` and rejects.
- Issue an unsigned `SenderKeyDistribution` from outside the group — outer DR sender PID is cross-checked against the local `group_members` list and rejected.

---

## §26. Sender-key rotation on remove/leave is forward-secrecy best-effort, not retroactive (Phase 5)

**Statement.** When the founder issues a remove or any member sends a Leave, every other member rotates their own `SenderChain`: a fresh chain key + Ed25519 keypair is generated, the `my_sender_keys` row is overwritten, and a `SenderKeyDistribution` for the new bundle is broadcast to every remaining member. Future messages from each member use chain keys the departed peer never had cached, so even a saved copy of the old `their_sender_keys` blob on the departed peer's disk is useless for any post-rotation ciphertext.

The rotation is event-driven (one rotation per remove/leave event), not per-message. Messages sent BETWEEN the rotation trigger and a given member receiving the new bundle remain decryptable by the departed peer IF the departed peer somehow still receives them — which in normal operation they wouldn't (other members no longer fan out to a peer absent from `group_members`).

**Why.** Without rotation, the symmetric chain key cached by every member is effectively shared with the departed peer forever — they could continue decrypting traffic for the lifetime of each member's chain. Rotation supersedes that cache with material the departed peer cannot acquire.

**Enforced at.**
- `src/core/node.rs::rotate_my_sender_chain_and_broadcast` — generates a fresh `SenderChain`, overwrites the local `my_sender_keys` row, builds a `SenderKeyDistribution` for the new bundle, and fans out to every remaining group member via the existing 1:1 DR.
- `src/core/node.rs::handle_group_remove` — founder rotates immediately after broadcasting the MembershipUpdate.
- `src/core/node.rs::process_group_control` MembershipUpdate arm — non-founder members rotate on receipt if `removed` is non-empty.
- `src/core/node.rs::process_group_control` Leave arm — every member (other than the leaver) rotates on receipt.

**What this DOES NOT defend against.**
- **Retroactive decryption.** Messages already in flight (or stored on a relay) at the moment of the rotation event are decryptable by the departed peer with their cached old chain key. True per-message retro-PFS would require chain rotation on every send, multiplying onboarding cost by message rate.
- **Sloppy fan-out.** If a non-departed member's code accidentally still includes the departed PID in fan-out after applying the MembershipUpdate, rotation doesn't help — the message is delivered with the new chain key wrapped in the 1:1 DR to a peer who has no `their_sender_keys` row for the new chain (so they fail to decrypt anyway). Defence-in-depth: keep the membership check in `group_send`/`deliver_kind_to_member` callers tight.
- **Member-key compromise before rotation propagates.** A remaining member whose own chain key is cached by the departed peer is at risk until the rotation event arrives at them. In poor-connectivity scenarios this window can be unbounded — there is no liveness guarantee.
- **No prekey-fetch onboarding for the new joiner.** If a newly-added member has never DM'd existing members before, they have no 1:1 DR session for `deliver_kind_to_member` to ride — the bundle delivery is warn-and-skipped. New joiners must first complete a 1:1 prekey-fetch + first message before group bundle distribution works. v0 limitation.

**Suggested attack.** Position a node so it captures every message on the wire. Join a group, then arrange to be removed (or leave). Continue capturing. Try to decrypt: only ciphertexts sent BEFORE the rotation events propagated to each respective sender are decryptable. Post-rotation ciphertexts produce `MessageKeyMissing` or `BadSignature` (depending on which chain was hit) — because the chain key for that index was never derivable from the bundles you held.

---

## §27. Hybrid X3DH preserves classical-X25519 security even if ML-KEM-768 is broken (Phase 2)

**Statement.** The Phase 2 PQ-X3DH derivation feeds BOTH the classical X25519 DH outputs AND the ML-KEM-768 shared secret into a single HKDF-SHA256. The resulting session key `SK = HKDF(salt=0, ikm = dh1 || dh2 [|| dh3] || ss_pq, info = X3DH_INFO_PQ [or X3DH_INFO_OTPK_PQ])` is secure as long as **at least one** of (classical X25519 DH problem, ML-KEM-768 lattice problem) remains intractable. Compromise of either primitive alone does NOT reveal `SK`.

**Why.** ML-KEM is young; deployed crypto must protect against the possibility that it's broken before its expected lifetime. Classical X25519 is well-studied but vulnerable to a future quantum computer (Shor). Hybrid is the standard defence — Signal PQXDH (2023) and iMessage PQ3 (2024) take the same approach for the same reason.

**Enforced at.**
- `src/crypto/x3dh.rs::derive_shared_secret_pq` / `derive_shared_secret_3_pq` — HKDF ikm concatenates classical DH outputs WITH the ML-KEM shared secret. Domain separator `ME55-x3dh-pq-v1` / `ME55-x3dh-otpk-pq-v1`.
- `src/crypto/x3dh.rs::pq_encapsulate` / `pq_decapsulate` — ML-KEM-768 RustCrypto wrapper; encapsulation returns `(ct, ss)` where `ss` is fed to HKDF and `ct` is transmitted in `EncryptedPayload::ml_kem_ct`.
- `src/core/identity.rs` — long-term ML-KEM-768 keypair lives alongside the X25519 prekey, both Ed25519-signed by the identity key under distinct domain separators (`ME55-prekey-v1` vs `ME55-ml-kem-prekey-v1`).
- `src/core/node.rs::build_x3dh_hello` — initiator's PQ encapsulation path; `bootstrap_responder_and_decrypt` is the responder's PQ decapsulation path with the four-way (OTPK × PQ) classical-fallback ladder.

**Downgrade safety.** A man-in-the-middle who strips the `ml_kem_ct` from a Phase-2 initiator's first message cannot cause the responder to compute the classical-only `SK`. The HKDF info tag is selected by the responder based on the PRESENCE of `ml_kem_ct`: present ⇒ `X3DH_INFO_PQ`, absent ⇒ `X3DH_INFO`. If the initiator computed `SK_hybrid` and the responder computes `SK_classical` (because the ct was stripped), the SKs DIFFER, AEAD on the first message FAILS, and the session does not establish. The MITM cannot recover either party's PQ secret either; they just denied service.

**Suggested attack.** Replace a Phase-2 initiator's `ml_kem_ct` with random bytes. ML-KEM-768 is IND-CCA secure — the responder's `pq_decapsulate` yields a pseudo-random `ss` (not an error), but that `ss` does not match what the initiator generated, so `SK_hybrid_initiator ≠ SK_hybrid_responder` and AEAD fails. Session does not establish; no information leaked.

---

## §28. DHT mailbox drops under an active session leak no PeerId to passive observers (Phase 4)

**Statement.** Once two peers complete X3DH and derive a Double-Ratchet root key, both compute the same 32-byte `session_id = HMAC-SHA256(sk, "ME55-session-id-v1")`. All subsequent DHT mailbox drops for this conversation are published in parallel under `session_drop_kad_key(session_id, slot) = SHA-256("ME55-session-mailbox-drop-v1" || session_id || slot)`. The preimage contains NEITHER party's PeerId, so a passive observer of the DHT sees only an opaque hash and cannot link the drop to either party's identity without breaking HMAC-SHA256.

**Why.** The legacy `drop_kad_key(recipient_pid, sender_pid, slot)` includes both PeerIds in its hash preimage. While the preimage isn't directly recoverable, a DHT-wide enumeration attacker knows the set of PeerIds in the network and can test all `(R, S, slot)` tuples against observed Kad keys — Bitcoin-style hash analysis at scale. `session_id` is private to the two parties, so no enumeration is possible.

**Enforced at.**
- `src/crypto/ratchet.rs::derive_session_id` — HMAC-SHA256(sk, SESSION_ID_DOMAIN). Symmetric: both `new_initiator(sk, ...)` and `new_responder(sk, ...)` derive the same `session_id` because the X3DH output `sk` is symmetric.
- `src/crypto/ratchet.rs::RatchetState::session_id()` — public getter; persisted via JSON serde with `#[serde(default)]` so pre-Phase-4 stored sessions migrate by deriving `[0u8; 32]` (degraded but functional — drops continue under legacy keys only).
- `src/network/mailbox.rs::session_drop_kad_key` / `session_ack_kad_key` — distinct domain separators from the legacy keys.
- `src/core/node.rs::put_mailbox_drop_bytes` — parallel PUT under both legacy and session keys during the Phase-4 migration window.
- `src/core/node.rs::poll_mailbox_slots` — parallel GET_RECORD under session keys for every active session.
- `src/core/node.rs::publish_mailbox_ack` / `republish_mailbox_drops` — parallel ACK + republish under session keys.

**Known limitations.**
- **First contact (no session yet) still uses legacy keys.** Until X3DH completes there is no `session_id` to derive; the very first drop unavoidably appears under `drop_kad_key(recipient, sender, slot)` and leaks identity. The leak is bounded to first contact only — every subsequent drop in the conversation is session-keyed and opaque.
- **Migration window legacy parallel publish.** Until the network is uniformly Phase-4, drops are published under BOTH keys so pre-Phase-4 recipients can still fetch. This means the legacy leak is still present for any conversation either side hasn't upgraded yet. The eventual cleanup (drop the legacy publish path) is a one-line code change once telemetry shows zero legacy fetches.
- **Republish + ACK loops do not yet purge legacy keys after Phase-4 completes.** Once both sides know they're talking under a session key (e.g. ACK observed under session_ack_key), the legacy republish could be skipped to reduce DHT load. Optimisation; not a correctness concern.

**Suggested attack.** Run a global passive DHT crawler. Enumerate all Kad records and their preimages. For the legacy `drop_kad_key` namespace you can correlate `(R, S, slot)` tuples against observed records by brute-forcing the much-smaller PeerId set. Now try the same for `session_drop_kad_key`: you'd need to enumerate over 2²⁵⁶ possible session_id values, which is computationally infeasible.

---

## §29. Deniable DMs hold up the ratchet AEAD as the sole per-message authenticator (Phase 3, opt-in)

**Statement.** When `config.deniable_dm = true` (CLI flag `--deniable-dm`), outgoing 1:1 DMs are constructed via `ProtocolMessage::new_direct_deniable` / `new_sealed_deniable` — empty per-message Ed25519 signature on direct path, empty inner signature inside the seal on sealed path. The receiving `verify()` / `verify_sealed()` returns the parsed sender PeerId WITHOUT a cryptographic check. The body's authenticity comes from the Double-Ratchet AEAD (ChaCha20-Poly1305, INVARIANTS §6) keyed by per-message symmetric material derived from a session secret known to exactly the two participants.

**Why.** With per-message Ed25519 signatures, ANY third party who later obtains a transcript and the sender's pubkey can mathematically prove "Alice authored this exact ciphertext at this exact time". This is the OPPOSITE of Signal's deniability property — and useful in coercive scenarios. Removing the per-message sig gives "online deniability": either session participant could have produced the envelope (both hold the symmetric key); a third party cannot prove which.

**Enforced at.**
- `src/protocol/message.rs::new_direct_deniable` — emits envelope with `signature: Vec::new()`.
- `src/protocol/message.rs::new_sealed_deniable` — emits sealed cert with empty inner signature payload (length-prefixed zero-length).
- `src/protocol/message.rs::verify` — branches on `signature.is_empty()`; empty ⇒ return parsed sender without crypto check.
- `src/protocol/message.rs::verify_sealed` — branches on inner `sig_bytes.is_empty()`; empty ⇒ return parsed sender without crypto check.
- `src/core/node.rs` — `ratchet_encrypt_and_wrap_bytes` selects deniable vs signed constructor per `self.config.deniable_dm`. Per-call branching covers all four (direct × sealed × signed × deniable) constructions.

**Wire compatibility.** Deniable envelopes are wire-incompatible with pre-Phase-3 peers, who require `signature.is_empty() ⇒ MissingSignature`. Opt-in is therefore lossy: a deniable-mode sender talking to a signed-mode receiver is silently dropped at receive-side `verify()`. Both peers must enable `--deniable-dm` for the conversation to work. Wire shape itself is unchanged (just an empty `signature` field); no protocol-ID bump.

**Group chats are NOT deniable.** Megolm per-message Ed25519 signatures in `src/protocol/group.rs` are load-bearing for §24 (cross-member anti-impersonation). Removing them would require a designated-verifier signature scheme or MLS rewrite — deferred to Phase 6.

**Suggested attack.** Construct a deniable envelope with a forged `from = victim_pid` and ciphertext from a totally different session. `verify()` returns Ok(victim_pid). Downstream `process_incoming_dm` then attempts ratchet decryption against the victim's existing session; the AEAD fails (different key) and the message is dropped without state mutation. The forgery cost was zero, the impact was zero — exactly what we want.

**Suggested attack.** Modify a deniable envelope's `payload` byte. The envelope passes `verify()` (no crypto on payload). The inner AEAD on the ratchet message then fails — same drop. Same property as for non-deniable: any tamper is caught at AEAD, just not earlier.

---

## End of invariants

This list is not exhaustive — it captures what the implementers consider load-bearing. A reviewer should treat anything *not* listed here as also potentially load-bearing and dig in.
