# CRYPTO.md — Formal Specification

This document lists every cryptographic primitive and construction used by ZeroCenter, with exact parameters and a pointer to the implementation. The intent is that a reviewer can map every byte going through every KDF / AEAD / signature.

## Notation

- `||` = byte-string concatenation.
- `len_be32(x)` = the length of `x` as a 4-byte big-endian unsigned integer.
- `HKDF(salt, ikm, info, L)` = HKDF-SHA256 extracting from `ikm` with optional `salt`, expanding to `L` bytes under `info`.
- `HMAC(key, msg)` = HMAC-SHA256.
- `DH(priv, pub)` = X25519 scalar multiplication producing a 32-byte shared secret.
- `Sign(sk, msg)` = Ed25519 signature (deterministic per RFC 8032).
- `Verify(pk, msg, sig)` = strict Ed25519 verification (rejects malleable encodings).
- `AEAD(key, nonce, ad, pt)` = ChaCha20-Poly1305 encryption. Output is `ct || tag` where `|tag| = 16`.

## 1. Identity

**Goal:** long-term keypair that authenticates the peer across all interactions and embeds in the libp2p PeerId.

- **Algorithm:** Ed25519 (`ed25519-dalek` 2.1).
- **Generation:** `SigningKey::generate(&mut OsRng)` at first run.
- **PeerId:** `PeerId::from(Keypair::ed25519_from_bytes(sk_bytes).public())`. The PeerId is a multihash where code = 0 ("identity") embeds the protobuf-encoded public key inline. This lets any party extract the verifying key from a PeerId without an out-of-band exchange.
- **Storage:** plaintext at `<data_dir>/identity.json` (`chmod 0600` on Unix; default ACL on Windows — known weakness, documented).
- **File:** `src/core/identity.rs:30`

## 2. Signed Prekey

**Goal:** long-term X25519 keypair, authenticated by the Ed25519 identity, used by initiators as the first DH input in X3DH.

- **Algorithm:** X25519 (`x25519-dalek` 2.0, `static_secrets` feature).
- **Signature:** Ed25519 over `prekey_signing_bytes(pub)` where
  ```
  prekey_signing_bytes(pub) = "zerocenter-prekey-v1" || pub
  ```
- **Storage:** plaintext in `identity.json` alongside the Ed25519 fields.
- **Verification:** recipients extract the Ed25519 verifying key from the responder's PeerId and check the signature before using the prekey.
- **Files:**
  - generation: `src/core/identity.rs:269` (`generate_signed_prekey`)
  - canonical signing bytes: `src/core/identity.rs:255` (`prekey_signing_bytes`)
  - verification: `src/core/node.rs::verify_and_store_prekey`

## 3. One-Time Prekey (OTPK)

**Goal:** single-use X25519 keypair used as DH3 in the 3-DH variant of X3DH. Improves forward secrecy on the very first message of a session.

- **Algorithm:** X25519, same as signed prekey.
- **Signature:** Ed25519 over `prekey_signing_bytes(otpk_pub)` — same domain separator as the signed prekey. (Rationale: both are "this is a valid X25519 prekey from this identity"; the distinction between long-term and one-time lives in the database row, not in the signed bytes. A reviewer should check if this is acceptable; see [INVARIANTS.md](INVARIANTS.md) §3.)
- **Pool size:** 20 unused OTPKs at all times (`P2PNode::OTPK_POOL_TARGET`).
- **Consumption:** atomic SQL `UPDATE my_otpks SET consumed_at = ? WHERE id = (SELECT id FROM my_otpks WHERE consumed_at IS NULL ORDER BY id ASC LIMIT 1) RETURNING ...`. Marks "in-flight" on pop, not on confirm — prevents the same OTPK being handed to two concurrent requesters.
- **Storage:** AEAD-encrypted private bytes, plaintext public + signature.
- **Files:**
  - generation: `src/core/node.rs::replenish_otpk_pool`
  - atomic pop: `src/storage/store.rs::pop_unused_otpk`
  - publication: `src/core/node.rs::handle_prekey_event` (Request arm)
  - consumption: `src/core/node.rs::bootstrap_responder_and_decrypt`

## 4. Transport-layer encryption

**Goal:** hop-level confidentiality + integrity between two libp2p peers.

- **Protocol:** Noise XX pattern (`libp2p::noise` over the libp2p `Transport` stack).
- **Cipher:** ChaCha20-Poly1305.
- **Authentication:** the libp2p identity Keypair derived from our Ed25519 identity (same key material).
- **Trust assumption:** libp2p's Noise implementation is treated as a black box; not audited here.
- **File:** `src/core/node.rs::start` (swarm builder)

## 5. Application-layer envelope (`ProtocolMessage`)

**Goal:** sender-authenticated, tamper-evident message envelope. Survives across libp2p versions.

### 5.1 Structure
```rust
pub struct ProtocolMessage {
    pub to:            Vec<u8>,   // recipient PeerId bytes (always clear)
    pub from:          Vec<u8>,   // sender PeerId bytes; empty on Phase 5 sealed envelopes
    pub sealed_sender: Vec<u8>,   // Phase 5 sealed envelope; empty on legacy direct envelopes
    pub payload:       Vec<u8>,   // serialized EncryptedPayload (Phase 3+) or raw bytes
    pub timestamp:     i64,       // unix seconds
    pub ttl:           i64,       // seconds
    pub msg_type:      MessageType,
    pub signature:     Vec<u8>,   // Ed25519 sig (direct path); empty on sealed envelopes
}
```

Two authentication paths share the same struct. `is_sealed()` returns true iff `sealed_sender` is non-empty; the receiver routes to `verify` or `verify_sealed` based on that.

### 5.2 Direct-path canonical signing bytes
```
direct_signing_bytes() =
    "zerocenter-dm-v1"          // domain separator
 || len_be32(to)    || to
 || len_be32(from)  || from
 || len_be32(payload) || payload
 || i64_be(timestamp)
 || i64_be(ttl)
 || u8(msg_type)
```
Length-prefixed; deterministic; excludes `signature` itself.

### 5.3 Sealed-path canonical signing bytes (Phase 5)
```
sealed_signing_bytes(sender_pid) =
    "zerocenter-sealed-dm-v1"   // DISTINCT domain separator (§1)
 || len_be32(to)         || to
 || len_be32(sender_pid) || sender_pid
 || len_be32(payload)    || payload
 || i64_be(timestamp)
 || i64_be(ttl)
 || u8(msg_type)
```
Different domain from §5.2 so a captured direct signature can't be transplanted into a sealed envelope. `sender_pid` is passed in because the envelope's own `from` is empty for sealed envelopes — the PeerId lives inside `sealed_sender` and only appears after unsealing.

### 5.4 Direct verification (`ProtocolMessage::verify`)
1. Reject if `is_sealed()` (caller should route to `verify_sealed`).
2. Reject if signature is empty (MissingSignature).
3. Parse `from` as PeerId.
4. Reject if multihash code ≠ 0 (no inline public key).
5. Decode protobuf public key from multihash digest.
6. `Verify(pk, direct_signing_bytes(), signature)` — if false, reject (BadSignature).
7. Return the parsed PeerId.

### 5.5 Sealed verification (`ProtocolMessage::verify_sealed`)
1. Reject if not `is_sealed()`.
2. Call `crypto::sealed::unseal_sender_cert(recipient_x25519_priv, sealed_sender)`. AEAD failure → SealDecryptFailed.
3. Parse the cert as length-prefixed `sender_pid || signature`. Malformed → MalformedSealedCert.
4. Extract sender pubkey from `sender_pid` (same multihash convention as §5.4).
5. `Verify(pk, sealed_signing_bytes(sender_pid), signature)` — if false, reject (BadSignature).
6. Return the recovered sender PeerId.

### 5.6 Cross-check at receive (DIRECT path only)
After `verify` returns the *signed* sender PeerId, the receiver also checks:
- `transport_peer == verified_sender`. Reject otherwise. Prevents a connected peer relaying captured direct messages.
- **For sealed envelopes the cross-check is skipped** — the transport peer is decoupled from the signed sender by design.
- **Enforced at:** `src/core/node.rs::process_incoming_dm` (step 3, gated on the `sealed` flag).

### 5.7 Domain separators
`zerocenter-dm-v1` (direct) and `zerocenter-sealed-dm-v1` (sealed). Distinct to prevent cross-path signature replay (INVARIANTS §1).

**Files:** `src/protocol/message.rs`, `src/crypto/sealed.rs`, `src/core/node.rs::process_incoming_dm`

## 6. End-to-end payload (`EncryptedPayload`)

What lives inside `ProtocolMessage.payload` for Phase 3+ direct messages.

```rust
pub struct EncryptedPayload {
    pub dh:       [u8; 32],         // sender's current DH ratchet pubkey
    pub pn:       u32,              // previous sending chain length
    pub n:        u32,              // sequence in current sending chain
    pub ct:       Vec<u8>,          // AEAD output (includes 16-byte tag)
    pub x3dh_eph: Option<[u8; 32]>, // initiator's X3DH ephemeral pub (first msg only)
    pub otpk_id:  Option<i64>,      // responder's OTPK row id (first msg, 3-DH only)
}
```

Serialized as JSON (`serde_json`) and put into `ProtocolMessage.payload`. JSON was chosen over a binary format for debuggability; this is a minor space cost vs `bincode`.

**File:** `src/protocol/message.rs:32-78`

## 7. X3DH-lite (initial key agreement)

Both variants derive a 32-byte shared secret `SK` used as the Double Ratchet's initial root key.

### 7.1 2-DH variant (no OTPK)

```
DH1 = DH(initiator_ephemeral, responder_signed_prekey)
DH2 = DH(initiator_identity_x25519, responder_signed_prekey)
SK  = HKDF(
        salt = 0^32,
        ikm  = DH1 || DH2,
        info = "zerocenter-x3dh-v1",
        L    = 32)
```

- **Files:**
  - initiator: `src/crypto/x3dh.rs::initiator_derive`
  - responder: `src/crypto/x3dh.rs::responder_derive`

### 7.2 3-DH variant (with OTPK)

Active when the responder included an OTPK in its `PrekeyResponse`.

```
DH1 = DH(initiator_ephemeral, responder_signed_prekey)
DH2 = DH(initiator_identity_x25519, responder_signed_prekey)
DH3 = DH(initiator_ephemeral, responder_otpk)
SK  = HKDF(
        salt = 0^32,
        ikm  = DH1 || DH2 || DH3,
        info = "zerocenter-x3dh-otpk-v1",  // DISTINCT FROM 2-DH
        L    = 32)
```

- **Distinct info string** ensures 2-DH and 3-DH never produce the same SK from coincident inputs.
- **Ephemeral is `StaticSecret`-backed, not `EphemeralSecret`** — we need two DHs from the same private key; both `chacha20-dalek`'s `EphemeralSecret` and `StaticSecret` are `ZeroizeOnDrop`, so the secret is zeroed at end of scope either way. Documented in code.
- **Files:**
  - initiator: `src/crypto/x3dh.rs::initiator_derive_with_otpk`
  - responder: `src/crypto/x3dh.rs::responder_derive_with_otpk`

### 7.3 Zero salt

HKDF's salt is 32 zero bytes — conventional for X3DH-style initial derivations (Signal makes the same choice). The domain separator in `info` provides the protocol binding.

### 7.4 Test vectors

In-tree only (no external test vectors). See `src/crypto/x3dh.rs` test module: both-sides-agree, different-responders-yield-different-SK, wrong-identity-at-responder-yields-different-SK, ephemeral-is-fresh-per-call (2-DH); both-sides-agree-with-OTPK, OTPK-vs-no-OTPK-differ, wrong-OTPK-at-responder-differs (3-DH).

## 8. Double Ratchet

Faithful implementation of the Signal Double Ratchet (https://signal.org/docs/specifications/doubleratchet/).

### 8.1 Per-session state

```rust
pub struct RatchetState {
    dhs_secret:  StaticSecret,         // our current DH ratchet keypair (priv)
    dhs_public:  PublicKey,            // ...(pub)
    dhr:         Option<PublicKey>,    // peer's last-seen DH ratchet pubkey
    rk:          [u8; 32],             // root key
    cks:         Option<[u8; 32]>,     // current sending chain key
    ckr:         Option<[u8; 32]>,     // current receiving chain key
    ns:          u32,                  // messages sent in current sending chain
    nr:          u32,                  // messages received in current receiving chain
    pn:          u32,                  // length of previous sending chain
    skipped:     VecDeque<SkippedKey>, // out-of-order recovery cache
}
```

### 8.2 Initialization

**Initiator** (after X3DH yields `sk`, knows responder's signed prekey pub `spk`):
```
state.dhs_secret = StaticSecret::random()
state.dhs_public = PublicKey::from(state.dhs_secret)
state.dhr        = Some(spk)
(state.rk, state.cks) = KDF_RK(sk, DH(state.dhs_secret, spk))
state.ckr = None
state.ns = state.nr = state.pn = 0
```

**Responder** (after X3DH yields `sk`, owns signed prekey secret `spk_secret`):
```
state.dhs_secret = spk_secret
state.dhs_public = PublicKey::from(spk_secret)
state.dhr        = None
state.rk         = sk
state.cks        = state.ckr = None
state.ns = state.nr = state.pn = 0
```

### 8.3 Root-key KDF (KDF_RK)

```
(new_rk, ck) = split64(HKDF(
    salt = rk,
    ikm  = dh_out,
    info = "zerocenter-rk-v1",
    L    = 64))
```
First 32 bytes are the new root key; second 32 bytes are the new chain key.

**File:** `src/crypto/ratchet.rs::kdf_rk`

### 8.4 Chain-key KDF (KDF_CK)

Per Signal spec — HMAC-SHA256 with `ck` as key, separate one-byte constants for the two outputs:
```
mk     = HMAC(ck, 0x01)
new_ck = HMAC(ck, 0x02)
```

**File:** `src/crypto/ratchet.rs::kdf_ck`

### 8.5 Per-message AEAD

```
ciphertext = AEAD(
    key   = mk,
    nonce = 0^12,                              // safe: mk is single-use
    ad    = ratchet_ad(sender, recipient) || header.to_aad_bytes(),
    pt    = plaintext)
```

Where:
```
ratchet_ad(s, r) = len_be32(|s|) || s || len_be32(|r|) || r
header.to_aad_bytes() = dh(32) || pn_be(4) || n_be(4)
```

Binding the header into the AAD means any header swap (different DH pubkey, different sequence) fails AEAD verification.

**Files:**
- `src/crypto/ratchet.rs::aead_encrypt` / `aead_decrypt`
- `src/core/node.rs::ratchet_ad`

### 8.6 DH ratchet step

Triggered when a received header carries a `dh` value different from our cached `dhr`:
```
state.pn  = state.ns
state.ns  = 0
state.nr  = 0
state.dhr = Some(incoming_dh)

# Derive new receiving chain from the OLD dhs
(state.rk, state.ckr) = KDF_RK(state.rk, DH(state.dhs_secret, incoming_dh))

# Rotate keypair, derive new sending chain
state.dhs_secret = StaticSecret::random()
state.dhs_public = PublicKey::from(state.dhs_secret)
(state.rk, state.cks) = KDF_RK(state.rk, DH(state.dhs_secret, incoming_dh))
```

**File:** `src/crypto/ratchet.rs::dh_ratchet_step`

### 8.7 Skipped-key cache

When a message arrives ahead of expected `nr`, derive (and cache) the message keys for the skipped indices so they can decrypt later out-of-order arrivals.

- **Bound:** `MAX_SKIP = 1000` per session.
- **Eviction:** oldest-first (`VecDeque::pop_front`) once the cap is exceeded.
- **Sweep across DH steps:** before the DH ratchet step, derive and cache keys for the *previous* receiving chain up to `header.pn`.
- **Failure:** if a single message would require skipping more than `MAX_SKIP` keys in one step, return `TooManySkipped` and drop the message rather than burn CPU.

**Files:**
- skipping: `src/crypto/ratchet.rs::skip_message_keys`
- lookup: `src/crypto/ratchet.rs::try_skipped`

## 9. Safety number (out-of-band MITM detection)

```
fingerprint = SHA-256(
    "zerocenter-safety-v1"
 || len_be32(|a|) || a
 || len_be32(|b|) || b
)[:20]
```

Where `(a, b) = sort_ascending(my_pid_bytes, their_pid_bytes)` — order-independence guarantees both sides print the same string.

Displayed as 40 hex characters in 8 space-separated groups of 5: `1a2b3 c4d5e f6789 ...`.

**File:** `src/main.rs` (safety handler closure)

## 10. At-rest encryption

### 10.1 Data-Encryption Key (DEK)

- **Algorithm:** ChaCha20-Poly1305 with a random per-blob nonce.
- **Key:** 32-byte random, generated on first run via `OsRng`. Stored in the OS keyring under `service="zerocenter-messenger"`, `account=<profile>`. Encoded as 64 hex chars for the keyring API.
- **Fallback:** if the keyring is unreachable, an ephemeral DEK is used with a loud `warn!`. Documented as fail-loud (don't silently fall back to plaintext on disk).
- **File:** `src/crypto/keyring.rs`

### 10.2 At-rest blob format

```
blob = u8(AT_REST_VERSION = 1)
    || nonce(12 random bytes)
    || ChaCha20Poly1305_encrypt(
           key   = DEK,
           nonce = nonce,
           ad    = "",      // no application AAD; integrity is internal-only
           pt    = plaintext)
```

`ad = ""` is deliberate: blob context (which table, which column, which peer) is provided by the SQL row, and we don't try to bind that into the AEAD. This means a row swap (`UPDATE ratchet_sessions SET state_blob = (SELECT state_blob FROM ratchet_sessions WHERE peer_id = OTHER)`) is not detected by AEAD — but it requires write access to the DB. Reviewer should consider: is this an acceptable scope reduction?

**File:** `src/storage/store.rs::encrypt_at_rest` / `decrypt_at_rest`

### 10.3 What's encrypted at rest

- `messages.ciphertext` — local plaintext of conversation history.
- `ratchet_sessions.state_blob` — serialized RatchetState (contains current chain keys + root key + skipped MKs).
- `my_otpks.x25519_priv` — one-time prekey private bytes.
- `outbox.ciphertext` — queued outgoing plaintexts.

### 10.4 What's NOT encrypted at rest

- `identity.json` (Ed25519 + X25519 prekey private bytes). Chicken-and-egg: encrypting it requires another secret. Acceptable for "user-account boundary" threat model; not acceptable for "stolen disk" threat model.
- All `peer_id` columns (used as query indices).
- `contacts.public_key` (public by definition).
- `prekeys_seen.x25519_pub` / `.signature` (public).
- Timestamps and TTLs.

## 11. Obfuscation transport (Phase 4b / 4c.1 / 4c.2 / 4c.2′ — shipped)

`src/network/scramble.rs::ScrambleStream<S>` wraps any `futures::io::AsyncRead + AsyncWrite + Unpin` (libp2p 0.53's transport flavour) with **two independent ChaCha20 keystreams**, one per direction, derived from an NTOR-style handshake at connection open. ScrambleStream is spliced into the libp2p `Transport` via `SwarmBuilder::with_other_transport(|kp| ...)` in `src/core/node.rs::P2PNode::start`, sitting between raw TCP and the Noise XX upgrade. Activation is gated on the `--obfs-key <HEX64>` CLI flag; without it traffic is vanilla libp2p (no obfs layer).

### 11.1 Per-connection key + nonce derivation (Phase 4c.1, NTOR-style)

On every new connection, both peers run a hidden-nonce handshake:

1. **Ephemeral keypair generation.** Each side picks a random X25519 private key whose public has an elligator2 representative under the `Randomized` variant of `curve25519-elligator2 = "0.1.0-alpha.2"`. Roughly 50% of keys have a representative; the generator retries up to 64 times (2⁻⁶⁴ failure under a healthy RNG).
2. **Wire exchange.** Both sides send their 32-byte elligator2 representative. To a passive observer those 32 bytes are computationally indistinguishable from uniform random — no plaintext nonce prefix to fingerprint.
3. **X25519 DH.** Each side decodes the peer's representative back to a Montgomery point and computes `shared_secret = X25519(my_priv, their_pub)`. The handshake refuses `shared_secret == 0` (low-order peer pubkey defence; audit F2).
4. **HKDF-SHA256 dual derivation.** From `IKM = shared_secret || obfs_key` with `salt = "zerocenter-ntor-v1"`, expand TWO 44-byte OKMs under role-distinguished `info` strings:
   - `"zc-chacha-d2l-v1"` → dialer→listener keystream `(key32 || nonce12)`.
   - `"zc-chacha-l2d-v1"` → listener→dialer keystream `(key32 || nonce12)`.
   Per-direction keying is load-bearing: with a single shared `(key, nonce)` for both directions, both peers' outbound ciphers would generate the same keystream — a textbook two-time-pad recoverable by XOR-ing the two directions of a wire capture (audit F1, fixed at commit 2273cf5).
5. **Cipher initialization.** The dialer's `out_cipher` is initialized from the d2l pair and its `in_cipher` from the l2d pair; the listener mirrors. Both ciphers start at counter 0.

The pre-shared `obfs_key` is the obfuscation envelope's authenticator: an MITM substituting their own ephemerals (without `obfs_key`) derives a different OKM-pair and can't decrypt either side's scrambled stream.

### 11.2 Framing (Phase 4c.2 — 256-byte quantum)

Above the byte-XOR layer sits a length-prefixed frame protocol:

```
[u16-be: payload_len] [payload_len bytes payload] [pad to next FRAME_QUANTUM-multiple]
```

with `FRAME_QUANTUM = 256`. The entire frame (header + payload + pad) is XOR'd with the keystream as a unit, so an observer can't separate header from payload from pad. Effect: every frame on the wire is a multiple of 256 bytes, hiding per-message size from statistical DPI. The frame size is further bounded at `MAX_PENDING_BYTES = 4 × FRAME_QUANTUM = 1024 bytes` via `MAX_PAYLOAD_PER_FRAME = MAX_PENDING_BYTES - 2 = 1022` (caps payload per frame; `write_all` naturally splits larger writes into multiple bounded frames) — this also bounds `ScrambleStream::pending` and tightens the wire-frame-size fingerprint to `{256, 512, 768, 1024}`.

### 11.3 Inter-arrival-time jitter (Phase 4c.2′ — opt-in)

When `--obfs-jitter-ms <MAX_MS>` is supplied alongside `--obfs-key`, every `poll_write` that's about to emit a NEW frame first waits a `uniform(0..=max)` ms delay (via `tokio::time::Sleep`). State machine: `pending_sleep: Option<Pin<Box<tokio::time::Sleep>>>` on the struct, polled to completion before each frame emission. Defeats off-the-shelf emission-timing fingerprinters. Cost: up to `max` ms of added per-frame latency. Default off — users who don't ask pay nothing. Distribution is uniform; future Pareto/Poisson variants are out of scope for v0.

### 11.4 Properties

- **Per-connection forward secrecy at the obfs layer.** Ephemerals are dropped at end of handshake; even a captured `obfs_key` cannot reconstruct the keystream of past captured sessions without the ephemeral privates.
- **Drain-first discipline.** `ScrambleStream::pending` is bounded at `MAX_PENDING_BYTES = 1024`; `poll_write` drains it before scrambling new caller bytes, so the keystream is never advanced past bytes that didn't reach the inner stream (`debug_assert!` enforces the bound).

### 11.5 What this is NOT

- **Not full Obfs4 parity.** Obfs4 packs server-identity authentication and time-bucketed replay defence into its handshake; we don't need either because `obfs_key` is our authenticator and Noise XX above us provides peer authentication.
- **Not privacy.** Recipients still know who they're talking to; network-layer metadata (IPs, frame timing without jitter) is visible.
- **Not authenticated at the obfs layer.** The pre-shared key provides a MAC-of-sorts via the HKDF binding (an attacker without the key derives a different keystream and Noise XX above fails to handshake), but Noise XX is what actually authenticates peers.

**Files:**
- module: `src/network/scramble.rs`
- transport wiring: `src/core/node.rs::P2PNode::start` (`with_other_transport` closure)
- invariants: `audit/INVARIANTS.md` §17

## 11A. Sealed sender (Phase 5 — shipped)

**Goal.** Hide the sender's PeerId from network-transport observers (relays, DHT-mailbox providers, on-path nodes). The recipient is the only party who can recover the sender.

### 11A.1 Sealing construction

Per-message ECIES variant. Sender:

1. Generate ephemeral X25519 `(e_priv, e_pub)`.
2. `shared = X25519(e_priv, recipient_x25519_prekey_pub)`. Refused if `shared == 0` (low-order pubkey defence).
3. `(aead_key, aead_nonce) = HKDF-SHA256(salt="zerocenter-sealed-sender-v1", ikm=shared, info="chacha-key-nonce")`, 44-byte expansion split as `(32, 12)`.
4. `sender_cert = len_be32(sender_pid) || sender_pid || len_be32(signature) || signature`, where `signature` is over the sealed-path signing bytes (CRYPTO §5.3) under the sender's Ed25519 key.
5. `aead_ct = ChaCha20-Poly1305-Encrypt(aead_key, aead_nonce, sender_cert, aad=empty)`.
6. Wire: `e_pub (32 bytes) || aead_ct`. This goes into `ProtocolMessage::sealed_sender`.

The ephemeral private key is dropped before the function returns.

### 11A.2 Unsealing construction

Recipient takes their long-term X25519 prekey private and the wire `sealed` bytes:

1. Split `sealed` into `e_pub` (first 32 bytes) and `aead_ct` (rest).
2. `shared = X25519(recipient_x25519_priv, e_pub)`. Refused if zero.
3. Same HKDF derivation as §11A.1 step 3.
4. `sender_cert = ChaCha20-Poly1305-Decrypt(aead_key, aead_nonce, aead_ct, aad=empty)`. AEAD failure → reject.
5. Parse cert: `sender_pid`, `signature`. Malformed → reject.
6. Extract sender's Ed25519 pubkey from `sender_pid` (multihash code 0).
7. `Verify(sender_pk, sealed_signing_bytes(sender_pid), signature)`. Mismatch → reject.

### 11A.3 Forward secrecy

Per-message ephemeral private = per-message keystream. A later compromise of the recipient's prekey does NOT let an attacker decrypt past sealed envelopes — they would also need the ephemeral private, which was generated fresh, used once, and dropped.

### 11A.4 What this layer does NOT hide

- **Recipient PeerId.** The outer `to` field of `ProtocolMessage` is required for libp2p routing and (when delivered via DHT mailbox) for `slot_kad_key` derivation. Hiding the recipient needs onion routing — Phase 6 or later.
- **First-contact fallback.** When the sender doesn't yet have the recipient's X25519 prekey cached (only happens on the very first send to a brand-new contact, before the prekey-fetch reply lands), the envelope falls back to the legacy direct path with a clear `from`. After the prekey is cached, all subsequent sends are sealed.
- **ACK records.** Phase-5 mailbox ACKs (commit 6df48ef) publish at a Kad key derived from `(recipient, sender, slot)` with the recipient's PeerId as the value — a separate metadata leak not protected by sealed sender.

**Files:**
- module: `src/crypto/sealed.rs`
- envelope: `src/protocol/message.rs::ProtocolMessage::{new_sealed, verify_sealed, sealed_signing_bytes}`
- send-path selector: `src/core/node.rs::ratchet_encrypt_and_wrap` — picks sealed when `cached_prekey(peer)` is Some
- recv-path router: `src/core/node.rs::process_incoming_dm` — routes by `is_sealed()`; skips §2 cross-check for sealed
- invariants: `audit/INVARIANTS.md` §22

## 12. Group chats — Megolm-style sender chains (Phase 5)

**Goal:** many-to-many group encryption that encrypts each plaintext exactly once on the sender side and lets each receiver decrypt independently against the sender's chain state, with per-message authenticity that resists cross-member impersonation.

The construction is layered on top of the existing 1:1 Double Ratchet (`§8`): bundles, control messages, and group ciphertexts all ride the existing DR session between any two members. Group send fan-out is N-1 unicasts, not multicast.

### 12.1. Group identifier

- 32 random bytes generated via `OsRng::fill_bytes` at create time. Unlinkable (no founder bits leaked into the value). Rendered as 64-char lowercase hex when surfaced to a UI.
- File: `src/protocol/group.rs::GroupId = [u8; 32]`.

### 12.2. Wire envelope discrimination

`EncryptedPayload` (the §6 DR ciphertext wrapper) gained a `kind: u8` field in Phase 5:

```
kind = 0  — text DM (default; backward-compatible — pre-Phase-5 senders omit the field, recipients default it to 0).
kind = 1  — GroupControl  (cbor-or-json — currently json; see §12.4).
kind = 2  — GroupMessageEnvelope (§12.5).
```

`#[serde(default)]` + `skip_serializing_if = "is_zero_u8"` keeps the wire bytes byte-identical for kind=0, so a non-Phase-5 peer still parses our text DMs and we still parse theirs. The discriminator is read AFTER ratchet-decrypt and routed in `src/core/node.rs::dispatch_decrypted_content`.

### 12.3. Megolm sender-chain primitives

Per-group, per-sender state. One `SenderChain` per group I belong to; one `ReceiverChain` per `(group_id, peer)` pair for every other member of every group.

**Chain advance** (mirrors §8.3 KDF_CK with the same constants):
```
message_key   = HMAC-SHA256(chain_key, 0x01)
next_chain_key= HMAC-SHA256(chain_key, 0x02)
```

**Per-message AEAD:** ChaCha20-Poly1305 with `key = message_key`, `nonce = [0u8; 12]`. Each `message_key` is used exactly once (the chain advances unconditionally on every `encrypt`), matching the §8 safety argument for zero-nonce.

**AEAD AD layout:**
```
build_group_ad(group_id, sender_pid)
  = group_id (32) || sender_pid_len_be (4) || sender_pid
```

**Per-message Ed25519 signature** binds the ciphertext to the chain owner. Each `SenderChain` is born with its own Ed25519 keypair; the public half is included in the `SenderKeyBundle` (§12.4) so receivers can verify. Canonical signing bytes:
```
GROUP_MSG_DOMAIN_SEPARATOR = b"zerocenter-group-msg-v1"
canonical = DOMAIN
          || index_be (4)
          || ad_len_be (4) || ad
          || ct_len_be (4) || ct
```
Length-prefixed, so byte-unambiguous. The verifier runs `verify(canonical, sig)` BEFORE any chain-state mutation — a bad signature is a no-op on the receiver's chain.

**Skipped-keys cache.** Bounded `VecDeque<SkippedKey>` with `MAX_SKIP = 1000`, mirroring §8's policy (oldest-first eviction). Out-of-order delivery within the window decrypts cleanly; replay of an already-consumed index returns `MegolmError::MessageKeyMissing(index)`.

**Wire types** (json-serialised, ride inside the DR ciphertext as `EncryptedPayload.kind=2`):
```
SenderKeyBundle    { chain_key: [u8;32], index: u32, verify_pub: [u8;32] }
EncryptedGroupMessage { index: u32, ciphertext: Vec<u8>, signature: Vec<u8> }
GroupMessageEnvelope { group_id: GroupId, msg: EncryptedGroupMessage }
```

The `signature` field is `Vec<u8>` (not `[u8;64]`) because serde's blanket Deserialize impls don't cover arbitrary-size byte arrays; bad-length signature blobs surface as `BadSignature` on decrypt.

Files:
- `src/crypto/megolm.rs` — `SenderChain`, `ReceiverChain`, primitives, MAX_SKIP, AEAD, sign/verify.
- `src/protocol/group.rs::GroupMessageEnvelope` + `build_group_ad`.

### 12.4. Group control envelope (kind=1)

Bootstrap and membership-change protocol. Travels as the kind=1 plaintext inside the DR ciphertext (so authentication of "who sent this control message" inherits from the 1:1 DR session). Four variants, distinguished by serde tag `op`:

```
GroupControl = CreateGroup
             | MembershipUpdate
             | SenderKeyDistribution
             | Leave

GROUP_CTRL_DOMAIN_SEPARATOR = b"zerocenter-group-ctrl-v1"
```

Distinct domain separator from §1's DM/sealed paths so a captured DM signature can't be replayed as group control authorization (and vice versa).

**CreateGroup.** Founder-signed. Fields: `group_id`, `name`, `founder_pid`, `members: Vec<Vec<u8>>`, `epoch=0`, `founder_sig`. Canonical signing bytes:
```
DOMAIN || "create" || group_id (32)
       || name_lp || founder_pid_lp
       || epoch_be (8)
       || count_be (4) || sorted_member_lp*
```
where `_lp` means length-prefixed (u32-be) and `sorted_member_lp*` is the member set sorted lex byte-order and length-prefixed. Sorting before encoding means semantically-equal member sets produce byte-identical signatures.

Recipient checks: (a) `founder_sig` verifies against `founder_pid`'s embedded Ed25519 pubkey; (b) the DR transport sender PID equals `founder_pid` (a stranger can't spoof the founder field); (c) the recipient is in `members` (silent ignore otherwise).

**MembershipUpdate.** Founder-signed. Fields: `group_id`, `added: Vec<Vec<u8>>`, `removed: Vec<Vec<u8>>`, `epoch`, `founder_sig`. Canonical bytes:
```
DOMAIN || "update" || group_id (32) || epoch_be (8)
       || added_count_be || sorted_added_lp*
       || removed_count_be || sorted_removed_lp*
```

Founder PID is NOT carried inside the variant — receivers re-attach the locally-stored `groups.founder_pid` at verify time via `verify_membership_update(founder_pid)`. The plain `verify_signature` deliberately returns `BadSignature` for MembershipUpdate so a careless caller can't accept an unverified update. Recipients additionally enforce `epoch > stored_epoch` (replay-protect against stale captured updates).

**SenderKeyDistribution.** Carries a `SenderKeyBundle` (§12.3). NO inner signature — the outer 1:1 DR session already authenticates the sender. Recipients additionally check that the DR-verified sender is in the local `group_members` list before installing the bundle (defence-in-depth against stale group state).

**Leave.** Self-signed by the leaver's Ed25519 identity. Fields: `group_id`, `leaver_pid`, `epoch` (current at the time of leave), `leaver_sig`. Canonical bytes:
```
DOMAIN || "leave" || group_id (32) || leaver_pid_lp || epoch_be (8)
```
Self-signing lets other members verify the announcement even if a relay forwarded it from a peer who isn't currently a peer of theirs at the moment they see it.

Files:
- `src/protocol/group.rs::GroupControl` + `canonical_*_bytes` helpers + `GroupControl::verify_signature` / `verify_membership_update`.
- `src/core/node.rs::process_group_control` — recipient state mutation (apply add/remove diffs, install bundles, etc.).

### 12.5. Group send / receive flow

**Send** (`src/core/node.rs::group_send`):
1. Load (or create) my `SenderChain` for the group. If it's fresh, broadcast a `SenderKeyDistribution` to every other member FIRST so they can install the chain at index 0.
2. Compute `ad = build_group_ad(group_id, my_pid)`.
3. `encrypted = my_chain.encrypt(plaintext, ad)` — produces `EncryptedGroupMessage { index, ciphertext, signature }` and advances my chain by one step.
4. Persist advanced chain state (`my_sender_keys.state_blob`) + local plaintext copy (`group_messages`).
5. Wrap as `GroupMessageEnvelope { group_id, msg: encrypted }`, serialise.
6. For each member except self: ratchet-encrypt the envelope bytes through the 1:1 DR (`ratchet_encrypt_and_wrap_bytes(peer, envelope, kind=2)`) and `send_request`.

**Receive** (`src/core/node.rs::process_group_message`, called from `dispatch_decrypted_content` kind=2 arm):
1. Cross-check that the DR-verified `sender` is in local `group_members` (otherwise drop).
2. Load `their_sender_keys[(group_id, sender)].state_blob` → deserialise `ReceiverChain`. If absent, the SenderKeyDistribution hasn't arrived yet → warn-and-drop.
3. Compute `ad = build_group_ad(group_id, sender)`.
4. `receiver.decrypt(envelope.msg, ad)` — verifies the Ed25519 signature, fast-forwards the chain (cachings skipped keys), or pulls from skipped cache for past indices.
5. Persist advanced chain state + plaintext copy.
6. Print + emit `GuiEvent::GroupMessageReceived { group_id (hex), sender (base58) }`.

### 12.6. Membership rotation — forward secrecy (Phase 5)

Triggered on remove or leave. Every remaining member generates a fresh `SenderChain` and broadcasts a new `SenderKeyDistribution` to every other remaining member. The old chain key (now cached in the departed peer's `their_sender_keys`) is useless for any post-rotation ciphertext because the chain key is replaced wholesale.

**Founder side** (`handle_group_remove`): bumps `groups.epoch`, applies the diff locally, builds + sends `MembershipUpdate` to remaining members, then calls `rotate_my_sender_chain_and_broadcast`.

**Recipient side** (`process_group_control`):
- `MembershipUpdate` with `removed.len() > 0`: after applying, rotate own chain.
- `MembershipUpdate` with `added.len() > 0`: for each added peer, forward my CURRENT bundle (no rotation — adds don't compromise existing chains).
- `Leave`: after removing the leaver, rotate own chain.

Caveat: rotation is event-driven, not per-message. Messages already in flight at the moment of the rotation event remain decryptable by the departed peer with their cached old chain key — see `audit/INVARIANTS.md` §26 for the exact PFS-best-effort semantics.

Files:
- `src/core/node.rs::rotate_my_sender_chain_and_broadcast`
- `src/core/node.rs::send_my_bundle_to`
- `src/core/node.rs::handle_group_remove` / `handle_group_add` / `process_group_control`

### 12.7. Storage (at-rest)

Five new SQLite tables; sender-chain blobs and group-message plaintext are AEAD-wrapped under the §10 DEK.

```
groups            (group_id PK, name, founder_pid, epoch, created_at)        -- public metadata
group_members     ((group_id, peer_id) PK, joined_at)                        -- public metadata
my_sender_keys    (group_id PK, state_blob AEAD, updated_at)                 -- SECRET — chain state
their_sender_keys ((group_id, peer_id) PK, state_blob AEAD, updated_at)      -- SECRET — chain state
group_messages    (id PK, group_id, sender, ciphertext AEAD, ts, ttl)        -- decrypted plaintext history
```

PeerId columns stay in clear (same query-efficiency-over-metadata-privacy trade-off as §6 / §10). The chain state blobs use the same `encrypt_at_rest` AEAD as `ratchet_sessions.state_blob`.

File: `src/storage/store.rs` — `group_*`, `my_sender_key_*`, `their_sender_key_*`, `group_message_*` methods.

### 12.8. Threat model summary

| Property | Status | Notes |
|---|---|---|
| Confidentiality against non-members | ✅ | Group chain key never leaks outside; outer 1:1 DR adds a second layer. |
| Authenticity against group OUTSIDERS | ✅ | Per-message Ed25519 sig with chain-bound key; canonical bytes domain-separated. |
| Authenticity against group INSIDERS | ⚠️ partial | Chain key is shared via SenderKeyBundle; a malicious member can forge for THEMSELVES (signing key is bound to chain) but NOT for another member (need that member's Ed25519 private). |
| Forward secrecy across removes/leaves | ✅ best-effort | Sender-chain rotation on event. Pre-rotation in-flight messages are still decryptable by the departed peer if they receive them — INVARIANTS §26. |
| Replay resistance | ✅ | Single-use message keys; replay returns `MessageKeyMissing`. Out-of-order within MAX_SKIP=1000 works; outside MAX_SKIP returns `TooManySkipped`. |
| Membership integrity | ✅ | Founder-signed CreateGroup + MembershipUpdate; epoch monotonic. |
| Metadata privacy (group membership visible on disk) | ❌ | `group_members.peer_id` is in clear. Same trade-off as DM contacts. |

## 13. Random number generation

All cryptographic randomness comes from `rand::rngs::OsRng`, which on:
- **Windows:** calls `BCryptGenRandom`.
- **Linux:** reads `/dev/urandom` (or `getrandom(2)` where available).
- **macOS:** uses `SecRandomCopyBytes`.

`OsRng` is documented in the `rand` crate as a `CryptoRng`. We do not maintain our own PRNG state.

## 14. Dependencies snapshot

| Crate | Version | Used for |
|---|---|---|
| libp2p | 0.53 | Transport, Noise, Yamux, Kad, Gossipsub, mDNS, request-response |
| ed25519-dalek | 2.1 | Identity signing, envelope signing, prekey signing |
| x25519-dalek | 2.0 (`static_secrets` feature) | DH for X3DH, DH ratchet step |
| chacha20poly1305 | 0.10 | AEAD for ratchet + at-rest |
| chacha20 | 0.9 | Stream cipher for ScrambleStream |
| hkdf | 0.12 | Root-key derivation |
| hmac | 0.12 | Chain-key derivation |
| sha2 | 0.10 | HKDF/HMAC hash, safety number |
| zeroize | 1 | Drop-time zeroization of secrets |
| keyring | 3 | OS-native DEK storage |
| rusqlite | 0.30 (bundled) | Local store |
| serde / serde_json | 1.0 | DTOs and JSON wire format |
| anyhow / thiserror | 1.0 | Error types |
| tracing | 0.1 | Structured logging |
| tokio | 1.35 | Async runtime |
| rand | 0.8 | `OsRng` |
| hex | 0.4 | DEK encoding for keyring |
| clap | 4.4 | CLI parser |
| dirs | 5.0 | Platform-specific data paths |
| bs58 | 0.5 | (carry-over from earlier; PeerId base58 used implicitly via libp2p) |

No supply-chain pinning beyond `Cargo.lock`. Updates intentionally manual.
