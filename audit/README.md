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

**The codebase in this audit pack has never been compiled in the sessions that authored Phase 3, Phase 3.5, and Phase 4.** A Rust toolchain was unavailable. Implementation was written from memory against published crate APIs (libp2p 0.53, x25519-dalek 2.0, ed25519-dalek 2.1, chacha20poly1305 0.10, hkdf 0.12, hmac 0.12, keyring 3, sha2 0.10).

A reviewer should expect:
- **Logic / design**: ready for review as-is.
- **Type-level correctness**: likely a handful of small surface-level fixes (trait-in-scope misses, `&[u8; N]` → `&[u8]` coercions through `Option`, exact variant names in libp2p enums) that surface on the first `cargo check`.
- **Tests**: written but not run.

The `zerocenter.exe` binary in the repo predates Phase 3 (2026-04-15) and is **not** representative of the audited code.

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
│   └── scramble.rs      — ChaCha20-keystream wrapper (Phase 4a baseline obfuscation)
├── protocol/
│   └── message.rs       — ProtocolMessage signed envelope + EncryptedPayload wire format
├── storage/
│   └── store.rs         — SQLite layer with at-rest encryption
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

6. **Obfuscation transport (ScrambleStream) is not yet wired into libp2p.** The module ships and its primitive is sound, but on the wire today Noise XX is still recognizable to DPI.

## Contact / questions

This pack was generated as a structured deliverable for review. Implementation lives at `F:/__Qwen1/ME55/`. Open questions or findings should be reported per-file with `file:line` references where possible.
