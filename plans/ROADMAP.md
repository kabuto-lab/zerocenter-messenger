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
| NTOR-style hidden-nonce handshake via elligator2 (Phase 4c.1) | ✅ |
| QUIC | ⏸ disabled (see `[[project-quic-disabled]]`; revisit when ring-on-MSVC settles) |
| GUI (Tauri 2.x) | ✅ (build wired; basic chat UI; UX polish like push-style refresh deferred to v1) |
| DHT mailbox store-and-forward | ✅ (encrypt-once + ACK loop shipped Phase 5; sealed-sender still deferred) |
| External security audit | ❌ not started; `audit/` pack ready for reviewer (self-audit done) |
| Sealed sender (Phase 5) | ✅ ECIES-encrypted sender cert; sealed when recipient's prekey is cached |
| Group chats (Megolm-style) | ❌ |
| Deniability | ❌ (intentional non-deniability for v1) |

Build: rustc 1.95 / cargo 1.95 / VS Build Tools. `cargo test --lib`: 79/79 on default features. `cargo build --release` (default, headless CLI) produces a ~9.24 MB `zerocenter.exe`; `cargo build --release --features gui` additionally pulls Tauri 2.x and its webview2 toolchain (Windows). The tracked in-tree `zerocenter.exe` is the default build — the GUI artefact is significantly larger and isn't checked in.

## Done — chronological commits

Most recent first.

| Commit | Title | What it shipped |
|---|---|---|
| _(pending push)_ | feat(scramble): Phase 4c.1 — NTOR-style hidden-nonce handshake via elligator2 | New dep `curve25519-elligator2 = "0.1.0-alpha.2"`. `scramble_handshake` rewritten: each side generates an X25519 ephemeral whose pubkey has an elligator2 `Randomized` representative (retry up to 64×), exchanges the 32-byte representative, DH's the peer's decoded pubkey, HKDF's `shared_secret \|\| obfs_key` (salt `zerocenter-ntor-v1`) to derive a per-connection `(chacha_key, chacha_nonce)`. Replaces the in-clear 12-byte nonce prefix from Phase 4b. Three net-new tests; legacy handshake test replaced 1:1. Wire-format-breaking for `--obfs-key` users (both peers must upgrade). |
| 1d1d829 | feat(scramble): Phase 4c.2′ — opt-in IAT jitter via `--obfs-jitter-ms` | New CLI flag plumbed through `Config::obfs_jitter_ms` into `scramble_handshake` → `ScrambleStream::with_jitter`. `pending_sleep: Option<Pin<Box<tokio::time::Sleep>>>` on the struct; `poll_write` gates each new frame behind a `uniform(0..=max)` ms delay after the `pending` drain step. Two new tests: `jitter_roundtrips_three_frames` (3 frames with jitter=3 ms round-trip cleanly) and `jitter_zero_is_a_noop`. |
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

_None._ Phase 4c is complete: 4b (XOR + ScrambleStream wired into transport) + 4c.1 (NTOR-style hidden handshake) + 4c.2 (256-byte frame padding) + 4c.2′ (opt-in IAT jitter) + 4c.3 (short-write keystream resync). All shipped between 2026-05-17 and 2026-05-18. Next priorities (in roughly increasing scope): unbounded-`pending` bound, Tauri GUI build wiring, DHT mailbox network layer, external audit, Phase 5 functional gaps.

## Remaining — prioritised forward plan

### Phase 4c continuation

3 sub-items proposed; tackled in order:

- **(3) Short-write keystream resync** — ✅ done (commit 0cd1dd7).
- **(2) Length padding** — ✅ done (commit 3c4fd8d).
- **(2′) IAT jitter** — ✅ done (commit 1d1d829).
- **(1) NTOR-style hidden nonce + elligator2** — ✅ done (Phase 4c.1 commit pending push). `curve25519-elligator2 = "0.1.0-alpha.2"` dep; `scramble_handshake` does ephemeral-X25519 + elligator2 exchange + X25519 DH + HKDF over `shared || obfs_key`.
- **(1) Hidden nonce (NTOR-style + elligator2)** — deferred. Real Obfs4 equivalent. Substantial scope: elligator2 encoding of X25519 ephemeral pubkeys, NTOR handshake, derive nonce from shared secret. Requires either picking up a curve25519-dalek feature for elligator2 or hand-rolling the encoding. Won't tackle until there's a clear ask for full Obfs4 parity — current 12-byte plaintext-nonce header gives a length-only fingerprint that a knowledgeable attacker can match anyway; the meaningful win is in (2) and (2′), which are already covering the realistic DPI / statistical attacks.

### Phase 4 — non-obfs threads

- **GUI (Tauri 2.x) — ✅ build wired.** `cargo build --release --features gui` produces a working `zerocenter --gui` binary. Pieces in place:
  - `Cargo.toml`: `tauri = "2"` + `tauri-build = "2"` both `optional = true`, gated by `gui = ["dep:tauri", "dep:tauri-build"]`. Default headless CLI build pulls neither.
  - `build.rs` at the repo root: feature-gated `tauri_build::build()` call. Default builds skip it.
  - `tauri.conf.json` migrated to v2 schema: top-level `productName`/`version`/`identifier`, `build.frontendDist`/`devUrl`, `app.windows` + `app.security`, `bundle.active = false` (we don't run the bundler in v0; `cargo build` only).
  - `capabilities/default.json` grants the `main` window the `core:default` + `core:window:default` permission sets. Our `#[tauri::command]` invokes don't require explicit allowlist entries in v2; the core permission set is sufficient.
  - `icons/icon.ico` placeholder (1150-byte 16×16 grey square) keeps `tauri-build` happy on Windows. Replace with a real branded icon before shipping.
  - `src/core/mod.rs` re-exports `ContactDto`/`MessageDto` so `src/gui/app.rs` can name them from outside the `core::node` private module.
  - `dist/index.html` is the existing scaffolding from the original Tauri 1.x sketch — contacts list + chat pane + add-contact modal, calls our `invoke()` handlers verbatim. Functional but the v0 UI doesn't push-refresh on inbound messages; the user has to re-open the chat to see new ones. v1: emit a Tauri event from the node loop on `process_incoming_dm` success and wire `listen()` on the frontend.
  - `gen/` (Tauri-emitted capability schemas) is gitignored; regenerated on every `--features gui` build.

- **DHT mailbox network layer — ✅ v0 shipped.** Module `src/network/mailbox.rs` exposes `slot_id_for(unix_seconds)` (1-hour buckets), `slot_kad_key(recipient, slot)`, `drop_kad_key(recipient, sender, slot)` — both keyed by SHA-256 with distinct domain separators. `src/core/node.rs::publish_mailbox_drop` triggers on the offline branch of `try_send_or_queue` in addition to `outbox_add`; uses the new `ratchet_encrypt_and_wrap` helper (factored out of `encrypt_and_send_existing`) to produce the same `ProtocolMessage` wire bytes the direct-DM path would, then `put_record(drop_kad_key)` + `start_providing(slot_kad_key)`. Republish tick (every 600s) re-puts rows older than 1800s; poll tick (every 600s) queries `get_providers` for slot range `last_polled..now_slot` (capped at last 24 slots), and for each returned provider issues `get_record(drop_kad_key(self, provider, slot))`. Fetched bytes route through the same `process_incoming_dm` pipeline as direct DMs (signature verification, transport-peer ↔ signed-sender cross-check, ratchet decrypt, ratchet dedup). See `audit/INVARIANTS.md` §21 for the security story. Remaining v1 work: ACK flow (storage scaffolding exists; sender-side republish doesn't currently observe recipient ACKs); sealed-sender to plug the providers DHT metadata leak (Phase 5).

### Phase 5 — security & functional gaps

- **External security audit.** `audit/` pack is review-ready (README, CRYPTO, THREAT_MODEL, INVARIANTS — 20 numbered invariants with file:line pointers and suggested attacks). Find a reviewer; package the repo at a specific commit; receive findings; remediate.
- **Group chats (Megolm-style).** Each group has a sender-keys session; each member maintains a ratchet per other member for delivering new sender keys. Big lift. Out of scope until 1-1 hardens.
- **Deniability.** Currently every DM carries an Ed25519 signature over the ciphertext — non-repudiation by design, opposite of Signal. To get deniability we'd replace per-message Ed25519 with a deniable AKE (e.g. SPK signature plus per-conversation HMAC). Big crypto change; postponed until external audit lands on the v1 design.
- **Sealed sender / metadata privacy.** Today `from` is in clear in the outer envelope. Sealed-sender encrypts the sender PeerId so only the recipient can identify the author. Useful but requires receiver-side fan-out (try-decrypt against all session keys) — costly without group hints.
- **One-time prekey rotation under load.** Pool target = 20. A motivated attacker could fetch and discard 20 prekeys to drain the pool; we then fall back to 2-DH X3DH (weaker forward secrecy on first message). Mitigation: rate-limit prekey-fetch per remote peer, or grow the pool exponentially under demand.

## Known debt (not phase-tagged)

- `audit/README.md` and `audit/INVARIANTS.md` need a refresh whenever framing/jitter changes the threat-model story. The "build status" table in `audit/README.md` is now accurate but the source-tree paragraph hasn't grown the framing additions.
- ~~`ScrambleStream`'s `pending: Vec<u8>` has no upper bound.~~ Bounded at `MAX_PENDING_BYTES = 4 × FRAME_QUANTUM = 1024` bytes. `MAX_PAYLOAD_PER_FRAME` lowered to `MAX_PENDING_BYTES − 2 = 1022` so each built frame fits in the bound; `debug_assert!` guards every modification of `pending`. (Side benefit: wire-level frame size is now ≤ 1024 bytes always, tightening the obfs fingerprint.)
- `pending_sends` / `pending_recvs` / `cached_otpks` on `P2PNode` are in-memory only (INVARIANTS §16). A `send` issued mid-prekey-fetch is lost on restart. Persistent table would fix; see INVARIANTS §16 for the trade-off.
- `info!`-level log lines still mention PeerIds verbatim everywhere. Plaintext is fixed (INVARIANTS §19) but PeerIds are still metadata. For high-paranoia deployments we'd want a config to redact those too.
- QUIC re-enable: ring 0.17.14 built fine on the current MSVC toolchain in this session. The `[[project-quic-disabled]]` blocker may already be obsolete — needs a real test. Re-enable `quic` in `Cargo.toml`, restore `.with_quic()` in `node.rs::start` after `with_other_transport(...)`, run two-peer smoke.

## Conventions

- Each commit message names the phase (`feat(obfs): Phase 4b — ...`) and surfaces verification (test count, smoke result).
- Wire-format changes need both peers on the same version. Document in commit message AND bump the `/zerocenter/<protocol>/<ver>` strings in `src/network/behaviour.rs` if applicable.
- Any new `info!`/`warn!` that touches decrypted bytes defaults to `debug!` (INVARIANTS §19).
- `audit/INVARIANTS.md` is load-bearing; new invariants get appended with the next number, fixed ones get a "(fixed)" annotation rather than a deletion (so reviewers can see the history of claims).
