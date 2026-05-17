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
    pub to:        Vec<u8>,   // recipient PeerId bytes
    pub from:      Vec<u8>,   // sender PeerId bytes
    pub payload:   Vec<u8>,   // serialized EncryptedPayload (Phase 3+) or raw bytes
    pub timestamp: i64,       // unix seconds
    pub ttl:       i64,       // seconds
    pub msg_type:  MessageType,
    pub signature: Vec<u8>,   // Ed25519 sig over signing_bytes()
}
```

### 5.2 Canonical signing bytes
```
signing_bytes() =
    "zerocenter-dm-v1"          // 16 bytes domain separator
 || len_be32(to)    || to
 || len_be32(from)  || from
 || len_be32(payload) || payload
 || i64_be(timestamp)
 || i64_be(ttl)
 || u8(msg_type)
```
Length-prefixed; deterministic; excludes `signature` itself.

### 5.3 Verification (`ProtocolMessage::verify`)
1. Reject if signature is empty (MissingSignature).
2. Parse `from` as PeerId.
3. Reject if multihash code ≠ 0 (no inline public key).
4. Decode protobuf public key from multihash digest.
5. `Verify(pk, signing_bytes(), signature)` — if false, reject (BadSignature).
6. Return the parsed PeerId.

### 5.4 Cross-check at receive
After `verify` returns the *signed* sender PeerId, the receiver also checks:
- `transport_peer == verified_sender`. Reject otherwise. Prevents a connected peer relaying captured messages.
- **Enforced at:** `src/core/node.rs::process_incoming_dm` (step 3).

### 5.5 Domain separator
`zerocenter-dm-v1`. Kept at v1 across Phase 3 because the *signed-bytes layout* is unchanged — only the *contents* of `payload` migrated from plaintext to ciphertext. Bump only on layout change.

**Files:** `src/protocol/message.rs:35-200`

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

## 11. Obfuscation transport (Phase 4a — stub)

`src/network/scramble.rs::ScrambleStream<S>` wraps any `AsyncRead + AsyncWrite + Unpin` with two independent ChaCha20 keystreams (one per direction). Reads XOR with the inbound stream; writes XOR with the outbound stream.

- **Key:** 32-byte shared secret, distributed out of band via `--obfs-key <HEX64>`.
- **Nonce:** currently passed as a constructor argument (the in-band nonce-exchange handshake is Phase 4b).
- **Not wired into libp2p yet** — the module exists and has unit tests; the actual `Transport::and_then` wrapping is deferred.
- **NOT real Obfs4** — no NTOR, no IAT, no padding. Defeats naive DPI signatures; does not defeat statistical analysis or active probing.

**Files:**
- module: `src/network/scramble.rs`
- design: `plans/phase4-obfs4.md`

## 12. Random number generation

All cryptographic randomness comes from `rand::rngs::OsRng`, which on:
- **Windows:** calls `BCryptGenRandom`.
- **Linux:** reads `/dev/urandom` (or `getrandom(2)` where available).
- **macOS:** uses `SecRandomCopyBytes`.

`OsRng` is documented in the `rand` crate as a `CryptoRng`. We do not maintain our own PRNG state.

## 13. Dependencies snapshot

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
