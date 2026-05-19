# ZeroCenter Messenger — Roadmap

Living document tracking what's done, what's in flight, and what's queued. Last refreshed 2026-05-19.

## Status snapshot

| Layer | Status |
|---|---|
| libp2p transport (TCP+Noise+Yamux, +DNS, +Kad, +mDNS, +identify) | ✅ |
| Signed DM envelope + transport-peer ↔ signed-sender cross-check | ✅ |
| Double Ratchet E2EE (Signal spec) + X3DH-lite handshake | ✅ |
| At-rest AEAD (DEK in OS keyring, ChaCha20-Poly1305 over messages / sessions / OTPK privates / outbox / mailbox drops / group sender keys) | ✅ |
| One-time prekey pool (3-DH X3DH variant) | ✅ |
| Persistent outbox (drained on connect / mDNS) | ✅ |
| Safety-number anti-MITM CLI | ✅ |
| `--obfs-key` ChaCha20 wire obfuscation, wired into the libp2p Transport (Phase 4b) | ✅ |
| `--obfs-key` 256-byte frame padding (Phase 4c.2) | ✅ |
| `--obfs-jitter-ms` opt-in IAT jitter (Phase 4c.2′) | ✅ |
| NTOR-style hidden-nonce handshake via elligator2 (Phase 4c.1) | ✅ |
| `pending` buffer bound (Phase 4c.3 / d3e5d16) | ✅ |
| QUIC | ⏸ disabled (see `[[project-quic-disabled]]`; revisit when ring-on-MSVC settles) |
| GUI (Tauri 2.x) | ✅ build wired; push-refresh on inbound DMs shipped (4a52acc) |
| DHT mailbox store-and-forward (Phase 4) | ✅ (v0 shipped: encrypt-once + ACK loop + sealed-sender all in Phase 5) |
| Sealed sender (Phase 5) | ✅ ECIES-encrypted sender cert; sealed when recipient's prekey is cached |
| Mailbox encrypt-once (Phase 5) | ✅ same ciphertext bytes shared between outbox and DHT-mailbox drop |
| Mailbox ACK loop (Phase 5) | ✅ recipient publishes empty ack record; sender skips republish |
| OTPK rotation under load (Phase 5) | ✅ per-peer 60s cooldown + pool target bumped 20→100 |
| Self-audit pass (12 findings, 6 actioned) | ✅ `audit/SELF_AUDIT.md` |
| External security audit | ❌ not started; `audit/` pack ready for reviewer (self-audit done) |
| Group chats (Megolm-style, founder-signed) | 🚧 in flight (storage schema shipped 94710ba; 7 tasks remaining) |
| Deniability | ❌ (intentional non-deniability for v1) |

Build: rustc 1.95 / cargo 1.95 / VS Build Tools. `cargo test --lib`: **93/93** on default features (`--features gui` matches). `cargo build --release` (default, headless CLI) produces a ~9.27 MB `zerocenter.exe`; `cargo build --release --features gui` additionally pulls Tauri 2.x and its webview2 toolchain (Windows). The tracked in-tree `zerocenter.exe` is the default build — the GUI artefact is significantly larger and isn't checked in.

## Done — chronological commits

Most recent first.

| Commit | Title | What it shipped |
|---|---|---|
| 94710ba | feat(groups): Phase 5 group-chat storage schema + foundational types | First commit of the Megolm track. 5 new SQLite tables (`groups`, `group_members`, `my_sender_keys`, `their_sender_keys`, `group_messages`), all sender-chain blobs and group-message plaintext AEAD-wrapped under the DEK. New `protocol::group` module with `GroupId = [u8; 32]`, `GROUP_CTRL_DOMAIN_SEPARATOR`, `GROUP_MSG_DOMAIN_SEPARATOR`. 10 new tests. 93/93 (was 83/83). |
| 4a52acc | feat(gui): Phase 5 GUI v1 push-refresh on inbound DMs | New `GuiEvent::DmReceived { peer }` enum + opt-in `gui_tx: Option<mpsc::Sender<GuiEvent>>` on `P2PNode`. `try_send` so a stalled webview never blocks the swarm loop. Emit on success branches of `decrypt_first_message` + `decrypt_and_store` (covers live, mailbox, bootstrap, pending-drain). Tauri setup spawns a forwarder task → `app.emit("dm-received", peer_base58)`. Frontend re-runs `loadContacts()` and `loadMessages()` on the matching open chat. No new deps; no capability changes. |
| 2c2b658 | feat(prekey): Phase 5 OTPK pool-drain defence — per-peer rate limit + 100-pool | `recent_otpk_fetches: HashMap<PeerId, i64>` + `should_attach_otpk` gate. 60s per-peer cooldown after a honored OTPK fetch → repeat requesters still get a valid signed-prekey response but `otpk: None`, forcing them into 2-DH fallback. `OTPK_POOL_TARGET` bumped 20 → 100. INVARIANTS §23 covers the Sybil note + what-it-doesn't-defend. |
| 2894fc9 | feat(crypto): Phase 5 sealed sender — ECIES-encrypted sender cert | New `src/crypto/sealed.rs`. ECIES: ephemeral X25519 + HKDF-SHA256 → ChaCha20-Poly1305 over `(sender_pid \|\| signature)`. `ProtocolMessage` grew `sealed_sender: Vec<u8>` alongside `from`/`signature` (all 3 `#[serde(default)]`). Distinct `SEALED_DOMAIN_SEPARATOR=b"zerocenter-sealed-dm-v1"`. `ratchet_encrypt_and_wrap` picks sealed when `cached_prekey(peer).is_some()`. `process_incoming_dm` routes by `is_sealed()` and SKIPS the transport-peer cross-check for sealed envelopes. INVARIANT §22, CRYPTO.md §5 + §11A rewritten. 11 new tests. |
| 6df48ef | feat(mailbox): Phase 5 ACK loop — recipient ACKs, sender skips republish | `ack_kad_key(recipient, sender, slot)` (SHA-256, domain sep `"zerocenter-mailbox-ack-v1"`). Recipient publishes empty record after successful mailbox-fetched decrypt. Sender's republish tick parallel-fires `get_record(ack_kad_key)` and calls `mailbox_drop_ack(drop_id)` on FoundRecord. `pending_ack_queries: HashMap<kad::QueryId, drop_id>` for distinct dispatch from `pending_record_queries`. ACK not crypto-authenticated (v0 trade-off: fake ACK DoSes one drop, can't impersonate). |
| 8516f1b | feat(mailbox): Phase 5 encrypt-once for outbox + DHT mailbox (fixes F8) | `outbox` table grew `is_wire_bytes` via idempotent ALTER TABLE. `try_encrypt_offline(peer, plaintext)` returns wire bytes; outbox AND mailbox use the SAME ciphertext (so ratchet's already-consumed-mk on second arrival = silent no-op). `drain_outbox_for` branches on the kind flag. Closes the encrypt-twice gap from the self-audit. |
| 835c299 | fix(audit): address self-audit findings F3, F5, F7, F9 + refresh audit pack | F3: `load_otpk_private` SQL-gates on `consumed_at IS NULL`. F5: drop expired envelopes before any state-modifying work. F7: downgrade verbose Identify info dump to `debug!`. F9: install responder session only after first-message decrypt succeeds. CRYPTO.md §11 rewritten end-to-end; INVARIANTS §17 + §21 corrected. |
| 2273cf5 | docs(audit): land SELF_AUDIT.md from the self-review pass | Comprehensive self-audit ran a general-purpose subagent against the 21-invariant pack. 12 findings; 6 actioned (in subsequent commits incl. 835c299), 6 documented/deferred. New `audit/SELF_AUDIT.md`. |
| 52447d3 | feat(gui): Tauri 2.x GUI build wired behind `--features gui` | `tauri = "2"` + `tauri-build = "2"` both `optional = true`; `gui = ["dep:tauri", "dep:tauri-build"]`. `build.rs` feature-gates the build script. `tauri.conf.json` migrated to v2 schema. `capabilities/default.json` grants `core:default` + `core:window:default`. 1150-byte placeholder `icons/icon.ico` (whitelisted in .gitignore). `cargo build --release --features gui` produces a working `zerocenter --gui` binary. |
| 52cfe5c | feat(mailbox): DHT mailbox store-and-forward (v0) | New `src/network/mailbox.rs`. `SLOT_SECONDS=3600`, `slot_kad_key`/`drop_kad_key` SHA-256-keyed. Sender publishes via `put_record(drop_key)` + `start_providing(slot_key)` whenever `try_send_or_queue` would outbox. Recipient polls `get_providers(slot_key)` for slot range, fetches each `drop_key` via `get_record`, routes through `process_incoming_dm`. Republish/poll ticks every 600s. INVARIANTS §21. 7 new tests. |
| d3e5d16 | fix(scramble): bound `ScrambleStream::pending` at 4 × FRAME_QUANTUM | `MAX_PENDING_BYTES = 1024` ; `MAX_PAYLOAD_PER_FRAME` lowered to 1022 so every built frame fits. Side benefit: every wire frame is now in {256, 512, 768, 1024}. `debug_assert!` guards every `pending` modification. |
| d36a5d5 | feat(scramble): Phase 4c.1 — NTOR-style hidden-nonce handshake via elligator2 | New dep `curve25519-elligator2 = "0.1.0-alpha.2"`. `scramble_handshake` rewritten: each side generates an X25519 ephemeral whose pubkey has an elligator2 `Randomized` representative (retry up to 64×). HKDF over `shared_secret \|\| obfs_key` (salt `zerocenter-ntor-v1`) → per-connection `(chacha_key, chacha_nonce)`. Replaces the in-clear 12-byte nonce prefix. Wire-format-breaking for `--obfs-key` users. |
| 1d1d829 | feat(scramble): Phase 4c.2′ — opt-in IAT jitter via `--obfs-jitter-ms` | `Config::obfs_jitter_ms` → `scramble_handshake` → `ScrambleStream::with_jitter`. `pending_sleep: Option<Pin<Box<tokio::time::Sleep>>>` on the struct; `poll_write` gates each new frame behind a `uniform(0..=max)` ms delay after the `pending` drain step. |
| 3c4fd8d | feat(scramble): Phase 4c.2 — 256-byte frame padding | `ReadState` enum + `padded_frame_size` + framed `poll_read`/`poll_write`. Length-prefixed frames padded to a 256-byte quantum. |
| 0cd1dd7 | fix(scramble): pending-buffer so short inner writes don't desync ChaCha20 | Phase 4c.3. `drain_pending` helper; scrambled-but-unsent tails carry across polls. |
| 8f04035 | docs(audit): refresh README — code now compiles, ScrambleStream wired | Removed "never been compiled" claim; added fixes-table; caveat #6 for Phase 4b shipped. |
| fb13ad9 | chore: refresh zerocenter.exe to Phase 4b release build | Tracked the 9.11 MB binary. |
| 2e7ac96 | feat(obfs): Phase 4b — wire ScrambleStream into the libp2p Transport | `SwarmBuilder::with_other_transport` replacement, `.and_then(scramble_handshake)`, `MaybeScrambled<S>` enum. Two-peer smoke verified. |
| 2da79aa | fix(logs): downgrade plaintext-bearing info! to debug! (INVARIANTS §19) | Three `info!` sites in `node.rs` went to `debug!`. |
| 7caa646 | feat: land Phase 3+3.5+4a-scaffold, compile-clean & tests green | The big push: Phase 3 + 3.5 + 4a primitive landed in tree, plus six surface-level fixes from the first real `cargo check`. |

## In flight

**Phase 5 group chats (Megolm-style, founder-signed authority).** 8-task track, 1 of 8 commits shipped (94710ba). Estimated ~1500-1750 LOC total. Trust model: group founder is the sole authority for membership changes — every `MembershipUpdate` carries founder Ed25519 signature (INVARIANTS §25 will land with task 3).

Task graph (each blocks the next):

1. ✅ **Group storage schema + types** — shipped 94710ba.
2. 🚧 **Megolm sender-chain crypto module** (`src/crypto/megolm.rs`). `SenderChain::encrypt(plaintext, ad) -> (index, ct, sig)` (HMAC-SHA256 chain advance + ChaCha20-Poly1305 + Ed25519 sign). `ReceiverChain::decrypt` with bounded skipped-keys cache (MAX_SKIP=1000, mirrors DR). Tests for round-trip / ping-pong / out-of-order / MAX_SKIP.
3. ⏳ **Group control envelope + sender-key distribution.** `GroupControl` enum (`CreateGroup`, `MembershipUpdate`, `SenderKeyDistribution`, `Leave`). Wire: extend `EncryptedPayload` with `kind: u8` (serde default 0=text, 1=group-ctrl, 2=group-msg). Founder Ed25519 signature verified on every `MembershipUpdate`. `process_incoming_dm` routes on `payload.kind` after ratchet-decrypt.
4. ⏳ **Group message send/receive fan-out.** Send = encrypt-once with own SenderChain → N-1 unicast via existing 1:1 `encrypt_and_send`. Receive = route in `decrypt_and_store` on `payload.kind=2`, look up sender's chain, fast-forward, verify Ed25519, decrypt, store.
5. ⏳ **Group CLI** — `group create / list / send / add / remove / leave`.
6. ⏳ **Membership rotation on add/remove/leave** — founder rotates own SenderChain on remove; redistributes only to remaining members. Leaver broadcasts signed `Leave`; others stop fan-out.
7. ⏳ **Group GUI surface + push-refresh** — new Tauri commands, `GuiEvent::GroupMessageReceived`, frontend groups list / chat / control modal.
8. ⏳ **Audit pack + INVARIANTS** — §24 (per-message Ed25519 prevents cross-member impersonation), §25 (membership only valid under founder sig), §26 (sender-key rotation is PFS-best-effort, not retro-PFS). CRYPTO.md §12 for Megolm.

## Remaining — prioritised forward plan

### Phase 5 — remaining functional gaps (after group chats land)

- **External security audit.** `audit/` pack is review-ready (README, CRYPTO, THREAT_MODEL, INVARIANTS — 23+ numbered invariants with file:line pointers and suggested attacks, plus `SELF_AUDIT.md` from the self-pass). Find a reviewer; package the repo at a specific commit; receive findings; remediate.
- **Deniability.** Currently every DM carries an Ed25519 signature over the ciphertext — non-repudiation by design, opposite of Signal. To get deniability we'd replace per-message Ed25519 with a deniable AKE (e.g. SPK signature + per-conversation HMAC). Big crypto change; postponed until external audit lands on the v1 design.
- **Real branded icon** to replace the 1150-byte placeholder at `icons/icon.ico` before any user-facing shipping. Not code work.

### Audit-flagged debt deferred from the self-pass

- **F4** — `pending_recvs` unbounded duplicates during prekey-fetch window. Low severity, noise only. Cap queue + dedupe by ciphertext hash. ~30 LOC.
- **F12** — `outbox.peer_id` plaintext on disk. Defense-in-depth gap. HMAC the column under the local DEK. ~50 LOC + migration.

## Known debt (not phase-tagged)

- `audit/README.md` build-status table still says "48/48 on rustc 1.95" — pre-existing drift; the real count is 93/93 after the Phase 5 group-storage commit. Refresh due with task 8 of the group-chats track.
- `pending_sends` / `pending_recvs` / `cached_otpks` on `P2PNode` are in-memory only (INVARIANTS §16). A `send` issued mid-prekey-fetch is lost on restart. Persistent table would fix; see INVARIANTS §16 for the trade-off.
- `info!`-level log lines still mention PeerIds verbatim everywhere. Plaintext is fixed (INVARIANTS §19) but PeerIds are still metadata. For high-paranoia deployments we'd want a config to redact those too.
- QUIC re-enable: `[[project-quic-disabled]]` blocker may already be obsolete on current MSVC toolchain — needs a real test. Re-enable `quic` in `Cargo.toml`, restore `.with_quic()` in `node.rs::start` after `with_other_transport(...)`, run two-peer smoke.
- Known pre-existing test flake: `storage::store::tests::mailbox_drops_basic_lifecycle` races on `chrono_time()` calls that span a 1-second boundary; re-run if it fails on first try (not an audit finding).
- Stray untracked working-tree files (not commit blockers): `Managing_Public_Money_*.docx` (unrelated user files), `.claude/settings.local.json` harness state.

## Conventions

- Each commit message names the phase (`feat(groups): Phase 5 — ...`) and surfaces verification (test count, smoke result).
- Wire-format changes need both peers on the same version. Document in commit message AND bump the `/zerocenter/<protocol>/<ver>` strings in `src/network/behaviour.rs` if applicable.
- Any new `info!`/`warn!` that touches decrypted bytes defaults to `debug!` (INVARIANTS §19).
- `audit/INVARIANTS.md` is load-bearing; new invariants get appended with the next number, fixed ones get a "(fixed)" annotation rather than a deletion (so reviewers can see the history of claims).
- Git on this repo needs a per-call `-c safe.directory=F:/__Qwen1/ME55` override (owner mismatch on Windows). For commits, also pass `-c user.name="kabuto-lab" -c user.email="hdart.ru@gmail.com"` to match the existing commit-history author.
