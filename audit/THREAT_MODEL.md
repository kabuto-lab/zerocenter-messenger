# THREAT_MODEL.md — Adversary Classes and Claims

This document enumerates the adversary capabilities the implementation is meant to defend against, the explicit claims for each, and the explicit non-claims. A reviewer should read this **before** the code, then use it as a checklist while reading.

## A. Passive network observer

**Capability:** sees every byte on the wire between two ZeroCenter peers. Cannot inject, modify, or block.

| Claim | Status | Where |
|---|---|---|
| Cannot read message plaintext. | ✅ | Payload is ChaCha20-Poly1305 ciphertext under a Double-Ratchet message key. |
| Cannot link two messages by content. | ✅ | Each message has a fresh `mk`; ciphertexts are pseudorandom. |
| Cannot tell which DM session a message belongs to. | ⚠️ partial | The DH ratchet pubkey in the header is the same for many messages within a chain — observable correlator. Acceptable in this threat model. |
| Cannot identify the protocol as ZeroCenter. | ❌ no | The libp2p Noise XX handshake is recognizable. Mitigation requires Phase 4b ScrambleStream wiring + Phase 4c full Obfs4. |
| Cannot tell who is talking to whom. | ❌ no | Sender + recipient PeerIds are visible in `ProtocolMessage` and at the libp2p layer. Out of scope; needs onion routing. |
| Cannot tell how often or how much they talk. | ❌ no | Timing and size are unmodified. Out of scope. |

## B. Active on-path attacker (MITM)

**Capability:** A, plus can drop, modify, inject, or replay packets.

| Claim | Status | Where |
|---|---|---|
| Cannot forge a DM as another peer. | ✅ | Application-layer Ed25519 sig over a domain-separated canonical layout; `verify_strict` rejects malleable encodings. |
| Cannot replay a DM into a different session. | ✅ | AEAD AD includes both peer IDs and the ratchet header; message keys advance per-message. |
| Cannot replay a DM into the same session. | ✅ | Message keys are single-use; the chain advances. Replay either decrypts (and is a duplicate of an already-seen message) or finds the receiving chain past that point. Skipped-key cache caps the window. |
| Cannot tamper with an in-flight message undetected. | ✅ | AEAD authentication. |
| Cannot substitute their own prekey for the responder's. | ✅ | Prekeys are Ed25519-signed by the long-term identity; recipients verify before use. |
| Cannot substitute their own OTPK. | ✅ | Same — Ed25519 sig over `prekey_signing_bytes(pub)`. Reviewer should note the shared domain separator with signed prekeys (see INVARIANTS §3). |
| Cannot MITM the FIRST EVER session between two peers. | ⚠️ partial | Defended only by the assumption that PeerIds are exchanged out of band by the user. If the attacker can manipulate which PeerId the user types, they can MITM. Mitigated by the `safety` command + out-of-band fingerprint comparison. |
| Cannot retroactively decrypt past traffic by compromising a session key. | ✅ | Forward secrecy via the symmetric chain ratchet. |
| Cannot continue decrypting after the next DH ratchet step. | ✅ | Post-compromise security via the DH ratchet. |
| Cannot defeat traffic-analysis-based correlation. | ❌ no | Out of scope. |

## C. Compromised peer (your contact's device)

**Capability:** A + B, plus full control over one endpoint of the conversation.

| Claim | Status |
|---|---|
| Can read all past and future messages of conversations with you. | trivially yes — they're a legitimate endpoint |
| Can impersonate the compromised user to others. | trivially yes |
| Cannot impersonate you to others. | ✅ Your private Ed25519 + X25519 keys are not exposed to the peer. |
| Cannot decrypt conversations between you and a *third* party. | ✅ Per-session keys are isolated. |

## D. Compromised local file system (offline read)

**Capability:** can read every byte under your `<data_dir>/`, including `messages.db` and `identity.json`. Cannot read OS keyring (separate boundary).

| Claim | Status | Notes |
|---|---|---|
| Cannot decrypt past message history. | ✅ | `messages.ciphertext` is AEAD-encrypted under the DEK; DEK lives in OS keyring. |
| Cannot decrypt queued outgoing messages. | ✅ | Same — `outbox.ciphertext`. |
| Cannot decrypt or forge from ratchet sessions. | ✅ | `ratchet_sessions.state_blob` AEAD-encrypted. |
| Cannot use OTPKs to impersonate. | ✅ | OTPK private bytes AEAD-encrypted. |
| Cannot read your Ed25519 / X25519 long-term keys. | ❌ no | `identity.json` is **plaintext**. The chicken-and-egg of encrypting it requires another secret; known caveat. **This is the single biggest unencrypted-at-rest exposure.** Anyone with disk read can impersonate the user. |
| Cannot tell who you talked to (just from the file). | ❌ no | PeerId columns are plaintext (used as indices). Contact list is in `contacts` table. |
| Cannot tell what's queued for whom (just envelope). | ⚠️ partial | `outbox.peer_id` is plaintext; the *content* is encrypted but the recipient is visible. |

## E. Compromised local user session (online attacker on your machine)

**Capability:** D + can read OS keyring entries scoped to the current user (via legitimate `keyring`-crate-equivalent APIs).

| Claim | Status |
|---|---|
| Cannot do worse than D. | ❌ — they get the DEK on top, so they can read EVERYTHING. |
| Reduced to "control your account = control your communications." | ✅ (this IS the standard threat model boundary; we don't claim to defend further) |

The DEK + identity.json being co-readable by the user-session boundary is intentional. Resisting an online local attacker requires either trusted-hardware enclaves (TPM, Secure Enclave) or interactive passphrase entry on every start — out of scope for v1.

## F. Compromised libp2p / dependency

**Capability:** a malicious or buggy version of `libp2p`, `noise`, `chacha20poly1305`, etc.

| Claim | Status |
|---|---|
| Defended against bugs in `libp2p::noise`. | ❌ no — transport encryption is delegated. We rely on Noise being correct. |
| Defended against bugs in the AEAD or KDF. | ❌ no — we rely on `chacha20poly1305`, `hkdf`, `hmac`, `sha2` being correct. These are widely-used `RustCrypto` crates; a reviewer should verify the versions. |
| Defended against a supply-chain attack adding malicious code. | ❌ no — `Cargo.lock` pins versions but nothing prevents a future `cargo update` from pulling compromised code. Standard Rust ecosystem risk. |

A reviewer focused on supply chain should consider: pinning fewer transitive deps via `cargo vendor`, requiring code-signed releases, etc.

## G. State-level adversary doing DPI / censorship

**Capability:** controls a national-level router; can pattern-match traffic, block by signature, do active probing.

| Claim | Status |
|---|---|
| Cannot identify ZeroCenter traffic by simple signature match. | ✅ via ScrambleStream when `--obfs-key` is supplied. Phase 4b wired the transport; Phase 4c.1 hides the connection-opening 32 bytes (each direction) behind elligator2-encoded ephemerals so the wire has no plaintext nonce prefix to fingerprint. Subject to commit-2273cf5 fix (audit F1) for per-direction keystream split. Without `--obfs-key`, vanilla libp2p Noise XX is recognizable. |
| Cannot identify by statistical analysis (entropy, packet sizes). | ✅ partial — Phase 4c.2 256-byte frame padding flattens per-message size to a 1024-byte bound; Phase 4c.2′ `--obfs-jitter-ms <max>` randomizes inter-arrival timing within an operator-chosen window. Defeats off-the-shelf statistical fingerprinters; a sophisticated observer with enough samples can still recover the underlying uniform-distribution emission pattern. |
| Cannot identify by active probing. | ⚠️ partial — without `obfs_key` a prober gets no handshake response, so passive probing fails. Real Obfs4-style probe defence (server fingerprint, time-bucketed replay) is not implemented; an attacker holding `obfs_key` (e.g. obtained from a compromised bridge line) can probe ZeroCenter peers and identify them. |
| Cannot block by IP. | ❌ no — IPs are visible at the network layer. |
| Cannot break authentication / confidentiality of traffic they can't block. | ✅ — full E2EE remains. |

## H. Quantum adversary

**Capability:** has a fault-tolerant quantum computer capable of running Shor's algorithm in practice.

| Claim | Status |
|---|---|
| Defended against retroactive decryption of recorded ciphertext. | ❌ no — X25519 and Ed25519 are classically secure only. A "store now, decrypt later" attacker who captures today's traffic and runs Shor in 2040 can decrypt. |

Post-quantum integration is not on the Phase 4 roadmap; a separate Phase 5 conversation.

## I. Coercion attacker

**Capability:** can compel a user to hand over keys, decrypt past messages, etc.

| Claim | Status |
|---|---|
| Defended against. | ❌ no — there's no deniability, no plausibly-deniable encrypted volumes, no panic-button wipe. |

Out of scope — different design space (plausible deniability, ephemeral devices, etc.).

## Summary table

| Adversary | Confidentiality | Authenticity | Forward sec. | Post-comp. sec. | Censorship resist. |
|---|---|---|---|---|---|
| A. Passive observer | ✅ | ✅ | ✅ | ✅ | ❌ (Phase 4) |
| B. Active MITM | ✅ | ✅ | ✅ | ✅ | n/a |
| C. Compromised peer | n/a (legitimate endpoint) | n/a | n/a | n/a | n/a |
| D. Offline disk read | ✅ msg/state/otpk | ⚠️ identity.json plaintext | ✅ | ✅ | n/a |
| E. Online local user | ❌ DEK readable | ❌ | n/a | n/a | n/a |
| F. Bad dependency | depends | depends | depends | depends | depends |
| G. State DPI | ✅ content | ✅ | ✅ | ✅ | ✅ via `--obfs-key`; ⚠️ statistical / active probing partial |
| H. Quantum | ❌ | ❌ | ❌ | ❌ | n/a |
| I. Coercion | ❌ no defense | ❌ | ❌ | ❌ | ❌ |
