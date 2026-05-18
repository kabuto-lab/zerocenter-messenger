# ZeroCenter Messenger — External Security Audit Pack

This directory is the entry point for an external security review.

## What ZeroCenter is

A censorship-resistant, leaderless P2P messenger written in Rust on top of `libp2p` 0.53. Identity is Ed25519. Direct messages are Double-Ratchet encrypted (Signal-spec) after an X3DH-lite handshake. At-rest data is AEAD-encrypted with a per-profile data-encryption key (DEK) stored in the OS keyring.

There is no central server, no operator, no bootstrap-must-be-online dependency beyond what the user explicitly configures.

## Scope of the audit

| In scope | Out of scope |
|---|---|
| Cryptographic constructions and KDFs (see [CRYPTO.md](CRYPTO.md)) | Web frontend code in `dist/index.html` — not yet wired to Tauri |
| Wire formats — `ProtocolMessage`, `EncryptedPayload`, `PrekeyResponse` | Tauri 2.x integration (planned, not implemented; see `plans/phase4-gui.md`) |
| At-rest encryption and key management | The libp2p stack itself (Noise, Yamux, Kad) — assume secure |
| Application-layer signing + transport-peer cross-check | OS keyring backend (Windows DPAPI / macOS Keychain / etc.) — assume secure |
| Replay / forgery / tamper resistance | Side-channel and timing attacks |
| Forward secrecy and post-compromise security | Quantum resistance (we use X25519 + Ed25519 — both classically secure only) |
| Threat model claims (see [THREAT_MODEL.md](THREAT_MODEL.md)) | UI/UX vulnerabilities |
| Invariants the implementation must maintain (see [INVARIANTS.md](INVARIANTS.md)) | DoS at the libp2p layer |

## Build status — read this first

**As of 2026-05-17 the codebase compiles clean and `cargo test` passes 48/48** on rustc 1.95.0 / cargo 1.95.0 with VS Build Tools (Windows). The committed `zerocenter.exe` (commit fb13ad9, 9.11 MB) is the release binary produced by `cargo build --release` against this audit pack's source — it represents the audited code, not an older artefact.

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
│   └── node.rs          — main event loop, send/recv flow, session + outbox management
├── crypto/
│   ├── keyring.rs       — DEK lookup/creation via `keyring` crate
│   ├── x3dh.rs          — X3DH-lite key agreement (2-DH and 3-DH variants)
│   └── ratchet.rs       — Double Ratchet (state + KDFs + AEAD + skipped-key cache)
├── network/
│   ├── behaviour.rs     — libp2p NetworkBehaviour (Kad/Gossipsub/mDNS/request-response × 2)
│   └── scramble.rs      — ChaCha20-keystream wire obfuscation (ScrambleStream +
│                          MaybeScrambled + scramble_handshake; Phase 4a primitive
│                          + Phase 4b transport-stack wiring)
├── protocol/
│   └── message.rs       — ProtocolMessage signed envelope + EncryptedPayload wire format
├── storage/
│   └── store.rs         — SQLite layer with at-rest encryption
├── serde_helpers.rs     — tuple-style serde adapters for [u8;64] / Option<[u8;64]>
│                          (built-in array impls cap at N=32)
├── cli.rs               — CLI parser and line-reader
├── gui/app.rs           — Tauri command handlers (feature-gated, dep not yet added)
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
   - `src/protocol/message.rs::verify` (envelope signature)
   - `src/core/node.rs::process_incoming_dm` (transport-peer cross-check + payload routing)
   - `src/core/node.rs::bootstrap_responder_and_decrypt` (3-DH responder path, OTPK consume timing)
   - `src/crypto/ratchet.rs::skip_message_keys` (MAX_SKIP bound, oldest-first eviction)
   - `src/storage/store.rs::encrypt_at_rest` / `decrypt_at_rest` (nonce uniqueness, version byte)

## Known caveats

These are acknowledged limitations, not undiscovered bugs:

1. **No deniability.** Every DM carries an Ed25519 signature over the ciphertext. Recipients can prove authorship to a third party. Chosen for verification simplicity; opposite of Signal's deniability property.

2. **Initial-DM MITM not cryptographically prevented.** Without an out-of-band exchange, a network attacker who can substitute *both* peers' libp2p identify exchanges could relay. Mitigated only by the `safety` command (compare 160-bit fingerprint OOB).

3. **No metadata privacy.** Sender + recipient PeerIds are visible to any on-path observer. The DHT reveals lookup intentions. Mitigation requires onion routing (Phase 4+).

4. **Session state at rest is encrypted only with a DEK derived from the user's logon session.** A local attacker who compromises the user account can decrypt everything. Standard for DPAPI-class protection; documented.

5. **OTPK consumption is on-pop, not on-confirm.** A prekey-fetch that doesn't lead to a real session still burns one OTPK. Trade-off for race-free single-use semantics. Pool size (20) is the buffer.

6. **Obfuscation transport (ScrambleStream) wired in Phase 4b + frame-padded in Phase 4c.2 + optional IAT jitter in Phase 4c.2′ — defeats pattern-matching DPI, per-message size fingerprinting, and (opt-in) emission-timing fingerprinting.** When `--obfs-key <32-byte hex>` is supplied, every byte on the TCP socket (Noise XX handshake included) is XOR'd with a ChaCha20 keystream, so a DPI box matching libp2p / Noise signatures sees only random bytes. On top of that, Phase 4c.2 pads every frame up to a 256-byte quantum (`FRAME_QUANTUM`) — a 48-byte Noise handshake and a 200-byte DM both occupy 256 bytes on the wire; a 300-byte DM occupies 512 — so per-message size no longer fingerprints ZeroCenter traffic. Phase 4c.2′ adds opt-in `--obfs-jitter-ms <max>`: every new frame waits a `uniform(0..=max)` ms delay before emission so the inter-arrival cadence is randomised within the operator-chosen window. Caveats remaining (Phase 4c.1 candidate): the per-connection 12-byte nonce is sent in the clear (real Obfs4 derives it from an NTOR handshake — no plaintext prefix). The earlier short-inner-write bug (keystream advancing past unsent bytes) has been fixed via a `pending` write-buffer; see INVARIANTS §17.

## Contact / questions

This pack was generated as a structured deliverable for review. Implementation lives at `F:/__Qwen1/ME55/`. Open questions or findings should be reported per-file with `file:line` references where possible.
