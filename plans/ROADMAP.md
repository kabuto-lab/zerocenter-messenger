# ZeroCenter Messenger — Roadmap

Living document tracking what's done, what's in flight, and what's queued. Last refreshed 2026-05-22 (F12 — `outbox.peer_id` HMAC-tagged at rest; `tauri.conf.json` `withGlobalTauri` fix).

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
| Self-audit pass (12 findings, 7 actioned) | ✅ `audit/SELF_AUDIT.md` |
| External security audit | ❌ not started; `audit/` pack ready for reviewer (self-audit done) |
| Group chats (Megolm-style, founder-signed) | ✅ full 8-commit track shipped: storage + Megolm crypto + GroupControl wire + send/receive fan-out + CLI + membership rotation + Tauri GUI + audit pack |
| Deniability | ❌ (intentional non-deniability for v1) |

Build: rustc 1.95 / cargo 1.95 / VS Build Tools. `cargo test --lib`: **119/119** on default features (`--features gui` matches). `cargo build --release` (default, headless CLI) produces a ~9.27 MB `zerocenter.exe`; `cargo build --release --features gui` additionally pulls Tauri 2.x and its webview2 toolchain (Windows). The tracked in-tree `zerocenter.exe` is the default build — the GUI artefact is significantly larger and isn't checked in.

## Done — chronological commits

Most recent first.

| Commit | Title | What it shipped |
|---|---|---|
| 74328e7 | feat(storage): F12 — HMAC the outbox.peer_id column under the DEK | Self-audit finding F12 actioned. The persistent outbox stored the recipient PeerId in the clear in `outbox.peer_id`; message bodies were AEAD-encrypted at rest but a disk-read attacker without the OS-keyring DEK could still enumerate who had mail queued. The column now holds `HMAC-SHA256(DEK, "zerocenter-outbox-peer-v1" \|\| peer_id)` via the new `outbox_peer_tag` helper — keyed by the DEK so the mapping is opaque without the keyring, deterministic so the by-peer equality lookup and `idx_outbox_peer` index are unchanged, one-way (sufficient: `drain_outbox_for` always already holds the `PeerId`). A `PRAGMA user_version` gate re-tags pre-F12 rows once on first open. Two outbox tests adjusted, two added; 119/119 on default and `--features gui`. `SELF_AUDIT.md` F12 marked ACTIONED. |
| 4694498 | fix(gui): enable withGlobalTauri so the frontend event API resolves | `dist/index.html` drives push-refresh through `window.__TAURI__.event` (the `listen('dm-received')` / `listen('group-msg-received')` handlers from 4a52acc + d1556c1). Without `"withGlobalTauri": true` in `tauri.conf.json` that global is never injected, so the listeners throw at load and live refresh silently breaks — the user is back to re-opening a chat to see new messages. Also corrected two stale roadmap claims: b365be4 is on `main` as of 52d4744, not "awaiting merge". |
| b365be4 | fix(prekey): separate OTPK served/consumed states — first DM was unconditionally dropped | Found during live two-node DM testing. The audit-F3 fix (835c299) gated `load_otpk_private` on `consumed_at IS NULL`, but `pop_unused_otpk` sets `consumed_at` at *serve* time — so the private OTPK was refused for the very first legitimate responder X3DH, and every 3-DH first message was dropped with `OTPK id=N not found in our store`, permanently desyncing the session. Fix splits the lifecycle into two columns: `served_at` (set on pop; blocks re-serving the same OTPK) and `consumed_at` (set by the new `mark_otpk_consumed` after a successful first-decrypt — the F3 replay gate). `load_otpk_private` now gates on `consumed_at` only, so a served-but-not-spent OTPK still loads. Idempotent `ALTER TABLE` + `served_at` backfill migrates pre-fix DBs. The F3 unit test (which encoded the buggy behaviour) was replaced with a full serve→load→consume lifecycle test. Merged into `main` (now at `52d4744`); 117/117. |
| 5794f82 | docs(audit): Phase 5 group-chat audit pack — INVARIANTS §24-§26, CRYPTO §12, threat model J | Audit pack refreshed for the group-chat track. New INVARIANTS §24 (per-message Ed25519 cross-member impersonation defence), §25 (founder authority + epoch monotonicity), §26 (rotation FS semantics, best-effort not retroactive). New CRYPTO.md §12 (Megolm sender chains, 8 sub-sections). THREAT_MODEL gained section J (compromised group member). README test count refreshed, source tree + suggested-review-order expanded. Pure docs, no code changes. |
| d1556c1 | feat(groups): Phase 5 GUI surface for groups + group-msg push-refresh | Two new DTOs (`GroupDto`, `GroupMessageDto`) + two query NodeCommands (`QueryGroups`, `QueryGroupMessages`). Seven new Tauri commands wired (`get_groups`, `get_group_messages`, `create_group`, `send_group_message`, `add_group_member`, `remove_group_member`, `leave_group`). Frontend `dist/index.html` gained a Groups sidebar section, mode-aware chat view (contact vs group), three new modals (Create Group / Add Member / Remove Member), per-mode chat-header controls (founder-only Add/Remove + Leave), and a `listen('group-msg-received')` listener that refreshes the open group conversation. `escapeHtml` added wherever user-controlled strings interpolate into innerHTML. |
| db1b241 | feat(groups): Phase 5 membership rotation on add/remove/leave | Forward-secrecy gap closed: every remaining member rotates their `SenderChain` on remove/leave so the departed peer's cached chain key is dead-on-arrival for future messages. Threaded `&mut Swarm` through `decrypt_first_message` / `decrypt_and_store` / `bootstrap_responder_and_decrypt` / `dispatch_decrypted_content` / `process_group_control`. New `rotate_my_sender_chain_and_broadcast` + `send_my_bundle_to` helpers. Founder rotates on remove; recipients rotate on receiving `MembershipUpdate(removed)` or `Leave`. On `add`, existing members forward their current bundle to the new joiner (no rotation — adds don't compromise existing chains). Documents PFS-best-effort-not-retroactive semantics inline. |
| 1973d4e | feat(groups): Phase 5 group CLI — create / list / send / add / remove / leave | Six new fire-and-forget NodeCommand variants. `group <subcommand>` chord installed in `cli.rs` with subcommand parsing; main.rs handler routes to `NodeCommand::GroupCreate/List/Send/Add/Remove/Leave`. New `parse_group_id_hex` helper. Node-side handlers: `handle_group_create` (random 32-byte GroupId via OsRng → signed CreateGroup → install locally + broadcast), `handle_group_list`, `handle_group_add` / `handle_group_remove` (founder-only with signed `MembershipUpdate`, epoch bump, broadcast to remaining members), `handle_group_leave` (self-signed Leave + group_forget). |
| cc52b4c | feat(groups): Phase 5 group message send/receive — kind=2 fan-out | `GroupMessageEnvelope { group_id, msg: EncryptedGroupMessage }` wire type + `build_group_ad(group_id, sender_pid)`. `ratchet_encrypt_and_wrap_bytes` refactor (existing text helper now a thin forward with kind=0). `deliver_kind_to_member` wraps encrypt + send_request for one fan-out target. `group_send`: load/create my SenderChain → distribute bundle if fresh → Megolm-encrypt once → fan out as kind=2 envelopes via N-1 unicasts. `process_group_message`: cross-check membership, load ReceiverChain, decrypt, persist, emit `GuiEvent::GroupMessageReceived`. dispatch_decrypted_content kind=2 arm wired. |
| 88c483a | feat(groups): Phase 5 GroupControl envelope + receive-side routing | EncryptedPayload grew `kind: u8` (backward-compatible serde default + skip-if-zero). GroupControl enum (CreateGroup / MembershipUpdate / SenderKeyDistribution / Leave) with founder-signed authority semantics — only the founder mints Create / Update; Leave is self-signed; SenderKeyDistribution inherits authentication from outer DR session. `verify_membership_update(founder_pid)` enforces the locally-stored-founder bind. Recipient routing: dispatch_decrypted_content + process_group_control with full per-variant handlers (member install, epoch monotonicity, sender-key install, leave processing). |
| 4d0a7b0 | feat(groups): Phase 5 Megolm sender-chain crypto module | New `src/crypto/megolm.rs`. SenderChain (chain advance via HMAC-SHA256 with same constants as DR ratchet, ChaCha20-Poly1305 with zero nonce, per-message Ed25519 sig). ReceiverChain with skipped-keys cache (`VecDeque<SkippedKey>`, `MAX_SKIP=1000`, oldest-first eviction). Signature verified BEFORE chain state mutation so forgeries can't poison the skipped cache. JSON serialization for at-rest persistence. SenderKeyBundle wire type. 12 unit tests covering happy-path, ping-pong, out-of-order, replay → MessageKeyMissing, tamper rejection (sig / ct / AD), MAX_SKIP enforcement, JSON round-trips, late-joiner install, cross-chain rejection. |
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

_None._ The Phase 5 group-chats track (94710ba → 5794f82) completed 2026-05-19; ~2500 LOC across 8 commits with full test + audit-pack coverage. Next priorities below.

## Remaining — prioritised forward plan

### Phase 5 — remaining functional gaps

- **External security audit.** `audit/` pack is review-ready: README, CRYPTO (14 sections incl. §12 Megolm), THREAT_MODEL (10 adversary classes incl. J for compromised group member), INVARIANTS (26 numbered with file:line pointers and suggested attacks), plus `SELF_AUDIT.md` from the self-pass. **The self-audit predates the group-chat track** — §24-§26 and CRYPTO.md §12 are explicitly not-yet-self-audited. Find a reviewer; package the repo at a specific commit; receive findings; remediate.
- **Deniability.** Currently every DM (and group message) carries an Ed25519 signature over the ciphertext — non-repudiation by design, opposite of Signal. To get deniability we'd replace per-message Ed25519 with a deniable AKE (e.g. SPK signature + per-conversation HMAC). Big crypto change; postponed until external audit lands on the v1 design. Note: the Megolm per-message sig in group chats is load-bearing for cross-member anti-impersonation (INVARIANTS §24), so deniability there has additional design constraints.
- **Real branded icon** to replace the 1150-byte placeholder at `icons/icon.ico` before any user-facing shipping. Not code work.

### Group-chats v1 (post-v0 polish)

- **Prekey-fetch onboarding for new joiners** (currently warn-and-skip if no prior 1:1 DR with an existing member). Add a flow where `process_group_control / SenderKeyDistribution` triggers a prekey fetch for unknown peers.
- **Founder-key rotation primitive.** v0 has no way to rotate the founder — compromising the founder gives MembershipUpdate authority indefinitely. Options: dedicated `RotateFounder` control message signed by the outgoing founder, or CRDT-style admin set.
- **Per-message retro-PFS** (currently event-driven rotation). True retro-PFS would chain-rotate on every send, multiplying onboarding bandwidth by the message rate. Defer unless threat model evolves.
- **No-op leave on absent group.** Current `handle_group_leave` errors quietly when the group is unknown; could be silent-success for nicer UX.

### Audit-flagged debt deferred from the self-pass

- **F4** — `pending_recvs` unbounded duplicates during prekey-fetch window. Low severity, noise only. Cap queue + dedupe by ciphertext hash. ~30 LOC.
- **F12** — `outbox.peer_id` plaintext on disk. ✅ **Actioned** in `74328e7` — the column is now an HMAC tag under the DEK.

## Known debt (not phase-tagged)

- `audit/README.md` test count was refreshed to 117/117 by commit 5794f82.
- `pending_sends` / `pending_recvs` / `cached_otpks` on `P2PNode` are in-memory only (INVARIANTS §16). A `send` issued mid-prekey-fetch is lost on restart. Persistent table would fix; see INVARIANTS §16 for the trade-off.
- `info!`-level log lines still mention PeerIds verbatim everywhere. Plaintext is fixed (INVARIANTS §19) but PeerIds are still metadata. For high-paranoia deployments we'd want a config to redact those too.
- QUIC re-enable: `[[project-quic-disabled]]` blocker may already be obsolete on current MSVC toolchain — needs a real test. Re-enable `quic` in `Cargo.toml`, restore `.with_quic()` in `node.rs::start` after `with_other_transport(...)`, run two-peer smoke.
- Known pre-existing test flake: `storage::store::tests::mailbox_drops_basic_lifecycle` races on `chrono_time()` calls that span a 1-second boundary; re-run if it fails on first try (not an audit finding).
- Stray untracked working-tree files (not commit blockers): `Managing_Public_Money_*.docx` (unrelated user files), `.claude/settings.local.json` harness state, `TEST_GUIDE.html` + `bats/` (testing helpers — untracked by choice).
- The OTPK serve/consume regression (fixed in b365be4) means the 3-DH X3DH path was silently broken from 835c299 until 2026-05-20. No release shipped in that window, but any `messages.db` created against an affected build may hold half-open sessions — wipe and re-handshake if in doubt.

## Conventions

- Each commit message names the phase (`feat(groups): Phase 5 — ...`) and surfaces verification (test count, smoke result).
- Wire-format changes need both peers on the same version. Document in commit message AND bump the `/zerocenter/<protocol>/<ver>` strings in `src/network/behaviour.rs` if applicable.
- Any new `info!`/`warn!` that touches decrypted bytes defaults to `debug!` (INVARIANTS §19).
- `audit/INVARIANTS.md` is load-bearing; new invariants get appended with the next number, fixed ones get a "(fixed)" annotation rather than a deletion (so reviewers can see the history of claims).
- Git on this repo needs a per-call `-c safe.directory=F:/__Qwen1/ME55` override (owner mismatch on Windows). For commits, also pass `-c user.name="kabuto-lab" -c user.email="hdart.ru@gmail.com"` to match the existing commit-history author.
