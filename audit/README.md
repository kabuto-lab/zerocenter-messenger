# ME55 Messenger — External Security Audit Pack

This directory is the entry point for an external security review.

## What ME55 is

A censorship-resistant, leaderless P2P messenger written in Rust on top of `libp2p` 0.53. Identity is Ed25519. Direct messages are Double-Ratchet encrypted (Signal-spec) after an X3DH-lite handshake. At-rest data is AEAD-encrypted with a per-profile data-encryption key (DEK) stored in the OS keyring.

There is no central server, no operator, no bootstrap-must-be-online dependency beyond what the user explicitly configures.

## Scope of the audit

| In scope | Out of scope |
|---|---|
| Cryptographic constructions and KDFs (see [CRYPTO.md](CRYPTO.md)) | The libp2p stack itself (Noise, Yamux, Kad) — assume secure |
| Wire formats — `ProtocolMessage`, `EncryptedPayload`, `PrekeyResponse`, `GroupControl`, `GroupMessageEnvelope` | OS keyring backend (Windows DPAPI / macOS Keychain / etc.) — assume secure |
| At-rest encryption and key management | Side-channel and timing attacks |
| Application-layer signing + transport-peer cross-check | Quantum resistance (we use X25519 + Ed25519 — both classically secure only) |
| Replay / forgery / tamper resistance | UI/UX vulnerabilities and JS injection in `dist/index.html` (basic `escapeHtml` in place; full XSS review out of scope) |
| Forward secrecy and post-compromise security | DoS at the libp2p layer |
| Group-chat construction (Megolm-style sender chains, founder-signed membership, rotation on remove/leave — see CRYPTO.md §12 and INVARIANTS §24-§26) | Supply-chain attacks beyond `Cargo.lock` pinning |
| Threat model claims (see [THREAT_MODEL.md](THREAT_MODEL.md)) | |
| Invariants the implementation must maintain (see [INVARIANTS.md](INVARIANTS.md)) | |

## Build status — read this first

**As of 2026-05-19 the codebase compiles clean and `cargo test --lib` passes 117/117** on rustc 1.95.0 / cargo 1.95.0 with VS Build Tools (Windows). The committed `ME55.exe` is the default-feature (CLI) release binary produced by `cargo build --release`. The `--features gui` build additionally pulls Tauri 2.x and produces a separately-buildable larger binary that is not tracked in-tree.

Phase 4 shipped end-to-end: ScrambleStream (`--obfs-key`) is wired into the libp2p Transport, NTOR-style hidden-nonce handshake via elligator2 is in place, 256-byte frame padding (`MAX_PENDING_BYTES = 1024` bound) is in place, opt-in IAT jitter (`--obfs-jitter-ms <MAX_MS>`) is in place, and the DHT mailbox store-and-forward layer is functional with encrypt-once + ACK loop + sealed sender (Phase 5). Phase 5 also shipped OTPK pool-drain defence + the full Megolm-style group-chat track (storage / crypto / wire / CLI / membership rotation / Tauri GUI; see CRYPTO.md §12 and INVARIANTS §24-§26). See `plans/ROADMAP.md` for the full status table. The most recent self-audit (`audit/SELF_AUDIT.md`) drove fixes for F1 (per-direction keystream keying — wire-format-breaking), F2 (low-order pubkey check), F3 (consumed_at gate on `load_otpk_private`), F5 (stale envelope drop), F7 (identify-event log downgrade), and F9 (session-insert order in responder bootstrap). The self-audit predates the group-chat track; a reviewer should treat §24-§26 (and CRYPTO.md §12) as not-yet-self-audited.

**Historical note for reviewers.** Phase 3, Phase 3.5, and Phase 4 were originally authored *without* a working Rust toolchain — written from memory against published crate APIs. The first end-to-end compile happened in commit 7caa646 and surfaced six categories of surface-level fixes; all are now in the tree:

| Site | Fix | Commit |
|---|---|---|
| `src/core/node.rs::replenish_otpk_pool` | Added missing `use ed25519_dalek::Signer` so `SigningKey::sign` resolved | 7caa646 |
| `src/crypto/ratchet.rs::kdf_ck` | Disambiguated `new_from_slice` via `<HmacSha256 as HmacKeyInit>` (both `Mac` and `digest::KeyInit` were in scope) | 7caa646 |
| `src/crypto/ratchet.rs::RatchetState` | Dropped `Debug` derive (`StaticSecret` doesn't impl `Debug`; also avoids accidentally leaking RK/CK material to `{:?}` logs) | 7caa646 |
| `src/network/behaviour.rs` / `src/core/identity.rs` signature fields | Added tuple-style serde adapters at `src/serde_helpers.rs` for `[u8; 64]` and `Option<[u8; 64]>` — serde's built-in array impls cap at `N = 32` | 7caa646 |
| `src/storage/store.rs` × 4 INSERT helpers | Replaced `conn.execute(...)? as i64` (which returns affected-rows count = always 1) with `conn.last_insert_rowid()`. The mailbox-cleanup test surfaced this; the wrong return value was previously masked in production because every caller discarded the id | 7caa646 |
| Phase 4b transport wiring | Replaced `SwarmBuilder::with_tcp(...)` with `with_other_transport(|kp| ...)` so the optional `ScrambleStream` layer could be spliced in via `.and_then(...)` between raw TCP and Noise. Required retargeting `ScrambleStream` from `tokio::io` to `futures::io` trait flavour. See §17 below — and commit 2e7ac96 | 2e7ac96 |

A reviewer should NOT expect any further trivial compile-time issues. Substantive review work (cryptographic constructions, threat-model fidelity, invariant enforcement) is the actual deliverable from here.

## Pack contents

| File | Purpose |
|---|---|
| [README.md](README.md) | This file. Pack entry point. |
| [CRYPTO.md](CRYPTO.md) | Formal description of every primitive and construction used. Each construction lists: inputs, domain separator, exact KDF parameters, output, and a file:line pointer to the implementation. |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Adversary capabilities. For each adversary class: what we claim to defend against and what we explicitly don't. |
| [INVARIANTS.md](INVARIANTS.md) | Numbered invariants the implementation must maintain. Each invariant: statement, where it's enforced, how to falsify it (suggested attack scenarios for the reviewer). |

## How to navigate the codebase

```
src/
├── core/
│   ├── identity.rs      — Ed25519 identity + signed X25519 prekey, lazy migration
│   ├── config.rs        — config struct (profile, bootstrap nodes, obfs key)
│   └── node.rs          — main event loop, send/recv flow, session + outbox management,
│                          Phase 5 group send/receive + membership rotation
├── crypto/
│   ├── keyring.rs       — DEK lookup/creation via `keyring` crate
│   ├── x3dh.rs          — X3DH-lite key agreement (2-DH and 3-DH variants)
│   ├── sealed.rs        — Phase 5 sealed-sender ECIES (CRYPTO.md §5+§11A, INVARIANTS §22)
│   ├── ratchet.rs       — Double Ratchet (state + KDFs + AEAD + skipped-key cache)
│   └── megolm.rs        — Phase 5 Megolm-style group sender chain (CRYPTO.md §12,
│                          INVARIANTS §24-§26)
├── network/
│   ├── behaviour.rs     — libp2p NetworkBehaviour (Kad/Gossipsub/mDNS/request-response × 2)
│   ├── mailbox.rs       — Phase 4-mailbox slot/drop kad-keys + ACK kad-keys
│   └── scramble.rs      — ChaCha20-keystream wire obfuscation (ScrambleStream +
│                          MaybeScrambled + scramble_handshake; Phase 4a primitive
│                          + Phase 4b transport-stack wiring + 4c.1/4c.2/4c.2′)
├── protocol/
│   ├── message.rs       — ProtocolMessage signed envelope + EncryptedPayload wire format
│   │                      (kind discriminator: 0=text, 1=GroupControl, 2=GroupMessage)
│   └── group.rs         — Phase 5 GroupId / GroupControl / GroupMessageEnvelope wire types
├── storage/
│   └── store.rs         — SQLite layer with at-rest encryption (DM + Phase 5 groups)
├── serde_helpers.rs     — tuple-style serde adapters for [u8;64] / Option<[u8;64]>
│                          (built-in array impls cap at N=32)
├── cli.rs               — CLI parser and line-reader (DMs + `group <subcommand>` chord)
├── gui/app.rs           — Tauri command handlers (feature-gated, includes group commands)
├── main.rs              — entry point
└── lib.rs               — module declarations
```

## Suggested review order

1. Skim **THREAT_MODEL.md** — understand what we claim, what we don't.
2. Read **CRYPTO.md** end to end. Pay particular attention to:
   - Domain-separator strings.
   - KDF parameter choices (HKDF info, HMAC constants).
   - The X3DH variants — especially the **3-DH OTPK variant**.
   - At-rest blob format.
3. Walk **INVARIANTS.md** with the source open. For each invariant, locate the enforcement site and ask "how would I break this?".
4. Specifically check:
   - `src/protocol/message.rs::verify` / `verify_sealed` (envelope signature, direct + sealed paths)
   - `src/core/node.rs::process_incoming_dm` (transport-peer cross-check + kind discriminator routing)
   - `src/core/node.rs::dispatch_decrypted_content` (post-decrypt fan-out: text vs group control vs group message)
   - `src/core/node.rs::bootstrap_responder_and_decrypt` (3-DH responder path, OTPK consume timing)
   - `src/crypto/ratchet.rs::skip_message_keys` (MAX_SKIP bound, oldest-first eviction)
   - `src/crypto/megolm.rs::ReceiverChain::decrypt` (Ed25519-before-state-mutation, MAX_SKIP enforcement, replay → MessageKeyMissing)
   - `src/protocol/group.rs::GroupControl::verify_signature` / `verify_membership_update` (founder authority surface)
   - `src/core/node.rs::process_group_control` (epoch monotonicity, sender-PID-in-members cross-check on SenderKeyDistribution)
   - `src/core/node.rs::rotate_my_sender_chain_and_broadcast` (rotation FS semantics, INVARIANTS §26)
   - `src/storage/store.rs::encrypt_at_rest` / `decrypt_at_rest` (nonce uniqueness, version byte)

## Known caveats

These are acknowledged limitations, not undiscovered bugs:

1. **No deniability.** Every DM carries an Ed25519 signature over the ciphertext. Recipients can prove authorship to a third party. Chosen for verification simplicity; opposite of Signal's deniability property.

2. **Initial-DM MITM not cryptographically prevented.** Without an out-of-band exchange, a network attacker who can substitute *both* peers' libp2p identify exchanges could relay. Mitigated only by the `safety` command (compare 160-bit fingerprint OOB).

3. **No metadata privacy.** Sender + recipient PeerIds are visible to any on-path observer. The DHT reveals lookup intentions. With the Phase 4 mailbox layer this leak is more durable than before: the providers DHT records `(sender_pid, slot_kad_key(recipient_pid, slot))` for every offline drop, persisting until Kad TTL expires. Mitigation requires onion routing + sealed-sender (Phase 5; see INVARIANTS §21 for the mailbox-specific story).

4. **Session state at rest is encrypted only with a DEK derived from the user's logon session.** A local attacker who compromises the user account can decrypt everything. Standard for DPAPI-class protection; documented.

5. **OTPK consumption is on-pop, not on-confirm.** A prekey-fetch that doesn't lead to a real session still burns one OTPK. Trade-off for race-free single-use semantics. Pool size (20) is the buffer.

6. **Group chat is Megolm-style with founder-signed authority and best-effort rotation on remove.** Each member ships their own symmetric `SenderChain`; chain keys flow via the existing 1:1 Double Ratchet sessions. Per-message Ed25519 over `GROUP_MSG_DOMAIN_SEPARATOR` distinguishes chain owners and prevents cross-member impersonation (INVARIANTS §24). Group membership is only valid under the founder's signature with epoch monotonicity (§25). On remove/leave, every remaining member rotates their `SenderChain` — best-effort PFS, not per-message retroactive (§26). The new joiner has no other members' chains until existing members forward their bundles in response to the MembershipUpdate; if no prior 1:1 DR session exists with an existing member, that bundle delivery is warn-and-skipped (v0 limitation). The construction has NOT been external-audited yet — the existing `audit/SELF_AUDIT.md` predates the group track.

7. **Obfuscation transport (ScrambleStream) — Phase 4b XOR layer + Phase 4c.1 NTOR-style hidden handshake + Phase 4c.2 256-byte frame padding + Phase 4c.2′ opt-in IAT jitter.** When `--obfs-key <32-byte hex>` is supplied, every byte on the TCP socket (Noise XX handshake included) is XOR'd with a ChaCha20 keystream, so a DPI box matching libp2p / Noise signatures sees only random bytes. The connection-opening 32 bytes (each direction) are elligator2-encoded ephemeral X25519 pubkeys — uniformly random to a passive observer; both sides DH and HKDF (`shared_secret || obfs_key`) to derive the per-connection ChaCha20 `(key, nonce)`, so the pre-shared `obfs_key` still authenticates the obfuscation envelope but is never transmitted. Frame padding (4c.2) rounds every frame to a 256-byte quantum (`FRAME_QUANTUM`) so per-message size doesn't fingerprint ME55 — a 48-byte Noise handshake and a 200-byte DM both occupy 256 bytes; a 300-byte DM occupies 512. Phase 4c.2′ adds opt-in `--obfs-jitter-ms <max>`: every new frame waits a `uniform(0..=max)` ms delay before emission so the inter-arrival cadence is randomised within the operator-chosen window. Remaining caveats: jitter distribution is uniform (a sophisticated observer with enough samples can still recover the underlying emission pattern); the `curve25519-elligator2 = 0.1.0-alpha.2` crate is alpha (surface used is small — only `Randomized::to_representative` and `EdwardsPoint::from_representative::<Randomized>` — but reviewers should sanity-check constant-time claims). `ScrambleStream::pending` is hard-bounded at `4 × FRAME_QUANTUM = 1024` bytes via a `MAX_PAYLOAD_PER_FRAME` cap and a `debug_assert!`. See INVARIANTS §17.

## Contact / questions

This pack was generated as a structured deliverable for review. Implementation lives at `F:/__Qwen1/ME55/`. Open questions or findings should be reported per-file with `file:line` references where possible.
