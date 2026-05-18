# ZeroCenter Messenger — Roadmap

Living document tracking what's done, what's in flight, and what's queued. Last refreshed 2026-05-17.

## Status snapshot

| Layer | Status |
|---|---|
| libp2p transport (TCP+Noise+Yamux, +DNS, +Kad, +mDNS, +identify) | ✅ |
| Signed DM envelope + transport-peer ↔ signed-sender cross-check | ✅ |
| Double Ratchet E2EE (Signal spec) + X3DH-lite handshake | ✅ |
| At-rest AEAD (DEK in OS keyring, ChaCha20-Poly1305 over messages / sessions / OTPK privates / outbox / mailbox drops) | ✅ |
| One-time prekey pool (3-DH X3DH variant) | ✅ |
| Persistent outbox (drained on connect / mDNS) | ✅ |
| Safety-number anti-MITM CLI | ✅ |
| `--obfs-key` ChaCha20 wire obfuscation, wired into the libp2p Transport | ✅ |
| `--obfs-key` 256-byte frame padding (Phase 4c.2) | ✅ |
| `--obfs-jitter-ms` opt-in IAT jitter (Phase 4c.2′) | ✅ |
| QUIC | ⏸ disabled (see `[[project-quic-disabled]]`; revisit when ring-on-MSVC settles) |
| GUI (Tauri 2.x) | 🟡 handlers scaffolded; deps + build.rs + tauri.conf.json 2.x migration TODO |
| DHT mailbox store-and-forward | 🟡 storage tables + methods scaffolded; network layer TODO |
| External security audit | ❌ not started; `audit/` pack ready for reviewer |
| Group chats (Megolm-style) | ❌ |
| Deniability | ❌ (intentional non-deniability for v1) |

Build: rustc 1.95 / cargo 1.95 / VS Build Tools. `cargo test --lib`: 52/52 (50 after 4c.2 + 2 new jitter tests: `jitter_roundtrips_three_frames`, `jitter_zero_is_a_noop`). `target/release/zerocenter.exe` is ~9.13 MB and tracked in-tree.

## Done — chronological commits

Most recent first.

| Commit | Title | What it shipped |
|---|---|---|
| _(pending push)_ | feat(scramble): Phase 4c.2′ — opt-in IAT jitter via `--obfs-jitter-ms` | New CLI flag plumbed through `Config::obfs_jitter_ms` into `scramble_handshake` → `ScrambleStream::with_jitter`. `pending_sleep: Option<Pin<Box<tokio::time::Sleep>>>` on the struct; `poll_write` gates each new frame behind a `uniform(0..=max)` ms delay after the `pending` drain step. Two new tests: `jitter_roundtrips_three_frames` (3 frames with jitter=3 ms round-trip cleanly) and `jitter_zero_is_a_noop`. |
| 3c4fd8d | feat(scramble): Phase 4c.2 — 256-byte frame padding | `ReadState` enum + `padded_frame_size` + framed `poll_read`/`poll_write` in `src/network/scramble.rs`. Length-prefixed frames padded to a 256-byte quantum, hiding per-message size from statistical DPI. Wire-format-breaking under `--obfs-key`. New test `frame_padding_rounds_up_to_quantum`; existing `short_inner_writes_dont_desync_keystream` reader switched to `read_to_end` so pad bytes drain on writer EOF. |
| 0cd1dd7 | fix(scramble): pending-buffer so short inner writes don't desync ChaCha20 | Phase 4c.3. `drain_pending` helper; `pending` Vec carries scrambled-but-unsent tails across polls so the keystream never advances past unsent bytes. |
| 8f04035 | docs(audit): refresh README — code now compiles, ScrambleStream wired | Removed the "never been compiled" build-status claim; added a fixes-table; updated caveat #6 for Phase 4b shipped. |
| fb13ad9 | chore: refresh zerocenter.exe to Phase 4b release build | Tracked the 9.11 MB binary; the pre-2026-04-15 stale artefact was replaced. |
| 2e7ac96 | feat(obfs): Phase 4b — wire ScrambleStream into the libp2p Transport | `SwarmBuilder::with_other_transport` replacement, `.and_then(scramble_handshake)` injection, `MaybeScrambled<S>` enum unifies obfs/no-obfs branches, ScrambleStream retargeted from tokio-io to futures-io. End-to-end two-peer smoke verified. |
| 2da79aa | fix(logs): downgrade plaintext-bearing info! to debug! (INVARIANTS §19) | Three `info!` sites in `node.rs` (Send requested, Decrypted first DM, Decrypted DM) went to `debug!`. |
| 7caa646 | feat: land Phase 3+3.5+4a-scaffold, compile-clean & tests green | The big push: Phase 3 + 3.5 + 4a primitive landed in tree (untracked until this commit), plus six surface-level fixes from the first real `cargo check`. |
| eec7b8d | (pre-session) fix(clippy): use HashMap::keys() and introduce ContactRow type alias | |
| 10469d8 | (pre-session) fix(main): separate Sender clone for history handler | |
| 7e56ba7 | (pre-session) fix: resolve 4 pre-existing compile errors | |
| 1e10f88 | (pre-session) Initial commit: Phase 1+2 complete, Phase 3 step 1 | |

## In flight

_None._ Phase 4c.2 framing and Phase 4c.2′ IAT jitter both shipped 2026-05-18. Phase 4c.1 (NTOR-style hidden nonce + elligator2) remains the only Phase 4c sub-item open; deferred — substantial scope.

## Remaining — prioritised forward plan

### Phase 4c continuation

3 sub-items proposed; tackled in order:

- **(3) Short-write keystream resync** — ✅ done (commit 0cd1dd7).
- **(2) Length padding** — ✅ done (commit 3c4fd8d).
- **(2′) IAT jitter** — ✅ done (Phase 4c.2′ commit pending push). Opt-in via `--obfs-jitter-ms <max>`; `Option<Pin<Box<tokio::time::Sleep>>>` on `ScrambleStream`; gates each new frame behind a `uniform(0..=max)` ms delay after the `pending` drain step.
- **(1) Hidden nonce (NTOR-style + elligator2)** — deferred. Real Obfs4 equivalent. Substantial scope: elligator2 encoding of X25519 ephemeral pubkeys, NTOR handshake, derive nonce from shared secret. Requires either picking up a curve25519-dalek feature for elligator2 or hand-rolling the encoding. Won't tackle until there's a clear ask for full Obfs4 parity — current 12-byte plaintext-nonce header gives a length-only fingerprint that a knowledgeable attacker can match anyway; the meaningful win is in (2) and (2′), which are already covering the realistic DPI / statistical attacks.

### Phase 4 — non-obfs threads

- **GUI (Tauri 2.x) actual build.** `src/gui/app.rs` has all `#[tauri::command]` handlers wired through `NodeCommand::Query*` with oneshot replies. To make `cargo build --features gui` succeed:
  1. Add `tauri = "2"` and `tauri-build = "2"` (build-dep) to `Cargo.toml`.
  2. Add a top-level `build.rs` calling `tauri_build::build()`.
  3. Migrate `tauri.conf.json` from 1.x schema to 2.x (the existing file is from the original scaffolding; expect breaking-schema changes).
  4. Verify the webview launches and the `invoke()` round-trip hits the node loop. Test on Windows first since that's the toolchain in use.
  5. Sketch a minimal `dist/index.html` UI to actually exercise the commands.

- **DHT mailbox network layer.** Storage scaffolding (tables, methods) is in `src/storage/store.rs::mailbox_drop_*`. Missing pieces:
  1. Republish loop: periodic task that reads `mailbox_drops_due_for_republish(threshold)` and re-puts each row to Kademlia.
  2. Slot-derivation: `slot_id = floor(unix_ts / SLOT_SECONDS)` → Kad key. Pick SLOT_SECONDS (probably 3600 — 1-hour buckets).
  3. Recipient-side polling: at startup and on a timer, query Kad keys for `mailbox_last_polled_slot()..now_slot`, decrypt any drops addressed to us, append to local message store, ACK back to sender (which causes `mailbox_drop_ack` and republish loop drops the row).
  4. Drop format: serialized `EncryptedPayload` (already Double-Ratchet'd), addressed to a Kad key derived from `recipient_pid + slot_id` so multiple peers can drop without colliding.
  5. Hardest sub-problem: keeping `(recipient_pid, slot_id) → kad_key` consistent without leaking the recipient. Use HMAC over an out-of-band shared secret? Simplest v0: just public key — accept the metadata leak as a documented limitation, fix in Phase 5.

### Phase 5 — security & functional gaps

- **External security audit.** `audit/` pack is review-ready (README, CRYPTO, THREAT_MODEL, INVARIANTS — 20 numbered invariants with file:line pointers and suggested attacks). Find a reviewer; package the repo at a specific commit; receive findings; remediate.
- **Group chats (Megolm-style).** Each group has a sender-keys session; each member maintains a ratchet per other member for delivering new sender keys. Big lift. Out of scope until 1-1 hardens.
- **Deniability.** Currently every DM carries an Ed25519 signature over the ciphertext — non-repudiation by design, opposite of Signal. To get deniability we'd replace per-message Ed25519 with a deniable AKE (e.g. SPK signature plus per-conversation HMAC). Big crypto change; postponed until external audit lands on the v1 design.
- **Sealed sender / metadata privacy.** Today `from` is in clear in the outer envelope. Sealed-sender encrypts the sender PeerId so only the recipient can identify the author. Useful but requires receiver-side fan-out (try-decrypt against all session keys) — costly without group hints.
- **One-time prekey rotation under load.** Pool target = 20. A motivated attacker could fetch and discard 20 prekeys to drain the pool; we then fall back to 2-DH X3DH (weaker forward secrecy on first message). Mitigation: rate-limit prekey-fetch per remote peer, or grow the pool exponentially under demand.

## Known debt (not phase-tagged)

- `audit/README.md` and `audit/INVARIANTS.md` need a refresh whenever framing/jitter changes the threat-model story. The "build status" table in `audit/README.md` is now accurate but the source-tree paragraph hasn't grown the framing additions.
- `ScrambleStream`'s `pending: Vec<u8>` has no upper bound. A misbehaving inner that never accepts writes would let this grow unboundedly. Bound by something like 4 × FRAME_QUANTUM and return `WouldBlock` past that — Phase 4c.2′ candidate.
- `pending_sends` / `pending_recvs` / `cached_otpks` on `P2PNode` are in-memory only (INVARIANTS §16). A `send` issued mid-prekey-fetch is lost on restart. Persistent table would fix; see INVARIANTS §16 for the trade-off.
- `info!`-level log lines still mention PeerIds verbatim everywhere. Plaintext is fixed (INVARIANTS §19) but PeerIds are still metadata. For high-paranoia deployments we'd want a config to redact those too.
- QUIC re-enable: ring 0.17.14 built fine on the current MSVC toolchain in this session. The `[[project-quic-disabled]]` blocker may already be obsolete — needs a real test. Re-enable `quic` in `Cargo.toml`, restore `.with_quic()` in `node.rs::start` after `with_other_transport(...)`, run two-peer smoke.

## Conventions

- Each commit message names the phase (`feat(obfs): Phase 4b — ...`) and surfaces verification (test count, smoke result).
- Wire-format changes need both peers on the same version. Document in commit message AND bump the `/zerocenter/<protocol>/<ver>` strings in `src/network/behaviour.rs` if applicable.
- Any new `info!`/`warn!` that touches decrypted bytes defaults to `debug!` (INVARIANTS §19).
- `audit/INVARIANTS.md` is load-bearing; new invariants get appended with the next number, fixed ones get a "(fixed)" annotation rather than a deletion (so reviewers can see the history of claims).
