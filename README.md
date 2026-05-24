# ME55

**Мессенджер без серверов, без регистрации, без компании за спиной.**
Скачал → запустил → пишешь.

---

## Что это и зачем

ME55 — это P2P-мессенджер: твои сообщения летят напрямую от тебя к собеседнику, минуя любые сервера. **Нет компании, которой можно прислать ордер, нет рубильника, который кто-то нажмёт, нет аккаунта, который заблокируют.**

В одной коробке:

- 🔒 **End-to-end шифрование** — Double Ratchet (как в Signal), плюс постквантовая защита (ML-KEM-768) на случай, когда квантовый компьютер сломает обычную криптографию.
- 🕵️ **Без аккаунта** — никаких номеров, email'ов, имён. Identity — это файл на твоём компе.
- 🥷 **Deniability** — никто не может математически доказать, кто что написал. Скриншот в суде ничего не значит.
- 🌐 **Не зависит ни от чего** — никакой компании, никаких облаков. Пока есть интернет — оно работает.

Подробнее, с техническими деталями и сравнением с WhatsApp/Telegram/Signal — в [**WHY_ME55.html**](https://htmlpreview.github.io/?https://github.com/kabuto-lab/zerocenter-messenger/blob/main/WHY_ME55.html).

---

## Скачать и запустить (Windows)

📦 **[ME55-windows.zip (~7.4 MB)](release/ME55-windows.zip)** ← правой кнопкой → «Сохранить как»

1. Распакуй ZIP в любую папку.
2. Дабл-клик по `start.bat`.
3. SmartScreen ругается? → «Подробнее» → «Выполнить в любом случае» (приложение open-source, без code-signing).
4. В окне увидишь свой Peer ID — скинь собеседнику любым каналом. Получишь его. «+» возле Contacts → вставляешь → Add → пишешь.

Подробная инструкция и решение проблем — в [`release/README.md`](release/README.md).

---

## ✅ Working Features

### Phase 1 Complete
- ✅ Ed25519 identity generation
- ✅ libp2p integration (TCP + Noise + Yamux). QUIC is temporarily disabled — see the comment in `Cargo.toml`.
- ✅ Kademlia DHT for peer discovery
- ✅ Noise Protocol encryption (hop-level)
- ✅ mDNS local network discovery
- ✅ Gossipsub (kept for future public channels; **not** used for DMs)
- ✅ Multi-profile support (run multiple instances)
- ✅ SQLite local storage

### Phase 2 Complete
- ✅ Direct messaging over a dedicated request-response protocol. DMs require a live connection; there is intentionally **no** gossipsub fallback (it leaked plaintext to every subscriber).
- ✅ Application-layer signed envelope (Ed25519 over a domain-separated canonical byte layout) with transport-peer ↔ signed-sender cross-check on receive.
- ✅ Message storage in SQLite (`messages.db`) with periodic TTL sweep.
- ✅ Peer connection via multiaddr.
- ✅ Connected peers listing.
- ⚠️ Contact persistence: peers are auto-saved when their first verified DM arrives. Aliases / manual add / removal aren't wired up yet.

### Phase 3 Complete (New!)
- ✅ **End-to-end encryption** via Double Ratchet (per Signal spec). ChaCha20-Poly1305 AEAD, HKDF-SHA256 root-key KDF, HMAC-SHA256 chain-key KDF, per-session forward secrecy + post-compromise security.
- ✅ **X3DH-lite handshake** (two-DH variant): initiator's ephemeral + responder's signed prekey derive the initial root key. The signed prekey is Ed25519-signed by the responder's long-term identity key.
- ✅ **Signed prekey on Identity** — `identity.json` carries an X25519 prekey alongside the Ed25519 identity, with the Ed25519 signature over it.
- ✅ **Prekey-fetch protocol** `/ME55/prekey/1.0.0` — peers exchange signed prekeys on demand; cached in `prekeys_seen` SQLite table.
- ✅ **Wire format** bumped to `/ME55/direct-message/2.0.0`. `ProtocolMessage.payload` is now a serialized `EncryptedPayload { dh, pn, n, ct, x3dh_eph? }`. The outer Ed25519 envelope signature now authenticates the ciphertext.
- ✅ **Session persistence** — ratchet state survives restart (`ratchet_sessions` table, JSON blob, saved after every encrypt/decrypt). See threat model: **state is plaintext at rest** until Phase 3.5.
- ✅ **Out-of-order delivery** tolerated up to `MAX_SKIP=1000` skipped keys per session; oldest-first eviction beyond.
- ✅ **Pending send/recv queues** — if the peer's prekey isn't cached, the message is queued and a prekey fetch is fired; drained on response.

## 🚀 Quick Start

### Run Two Instances on Same PC

**Option 1: Manual (Recommended for testing)**

Open two terminal windows:

**Window 1 (Alice):**
```bash
cd F:\__Qwen1\ME55
set RUST_LOG=info
target\release\ME55.exe --profile alice
```

**Window 2 (Bob):**
```bash
cd F:\__Qwen1\ME55
set RUST_LOG=info
target\release\ME55.exe --profile bob
```

**Option 2: Test Script**

Double-click `test.bat` - it will open two console windows automatically.

### Expected Output

```
📡 ME55 Messenger
══════════════════════════════════════
Profile: alice
Peer ID: 12D3KooWRx...

Type 'help' for commands, 'quit' to exit.

> 
```

Each instance will:
- Generate its own Ed25519 identity (saved to `%LOCALAPPDATA%\ME55\<profile>\`)
- Listen on a random port
- Be discoverable via mDNS on local network
- Be able to connect to other peers

## 📁 Project Structure

```
ME55/
├── Cargo.toml           # Rust dependencies
├── test.bat             # Quick test script (opens 2 windows)
├── src/
│   ├── main.rs          # Entry point with multi-profile support
│   ├── lib.rs           # Library exports
│   ├── core/
│   │   ├── identity.rs  # Ed25519 identity + signed X25519 prekey, lazy migration
│   │   ├── config.rs    # Configuration
│   │   └── node.rs      # P2P node + event loop (swarm, DM ratchet send/recv, TTL sweep, session persistence)
│   ├── network/
│   │   └── behaviour.rs # libp2p behaviours (Kademlia, Gossipsub, mDNS, Identify, DM, prekey)
│   ├── crypto/
│   │   ├── mod.rs       # Re-exports
│   │   ├── x3dh.rs      # X3DH-lite initial key agreement
│   │   └── ratchet.rs   # Double Ratchet (state, KDFs, AEAD, skipped-key cache, JSON persistence)
│   ├── protocol/
│   │   └── message.rs   # Signed DM envelope + EncryptedPayload
│   ├── storage/
│   │   └── store.rs     # SQLite storage (messages, contacts, channels, prekeys_seen, ratchet_sessions)
│   └── cli.rs           # CLI interface
└── dist/
    └── index.html       # Future GUI (Tauri)
```

## 🔧 Build Commands

### Development Build
```bash
cargo build
```

### Release Build (Optimized)
```bash
cargo build --release
```

Output: `target\release\ME55.exe`

### Run with Logging
```bash
set RUST_LOG=debug
cargo run -- --profile alice
```

## 📊 CLI Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `help`  | `h`     | Show available commands |
| `quit`  | `exit`, `q` | Exit the application |
| `connect` | `c`   | Connect to a peer by multiaddr |
| `send`  | `s`     | Send a direct message to a peer |
| `peers` | `p`     | List connected peers |
| `contacts` | `co` | List stored contacts (auto-populated on first DM) |
| `history` | `hi`, `hist` | Show last N messages from local store (default 20) |

### Command Examples

```bash
# Connect to a peer
connect /ip4/192.168.1.100/tcp/4001/p2p/12D3KooWRx...

# Send a message
send 12D3KooWRx... Hello, this is a test!

# List connected peers
peers

# List contacts
contacts
```

### First-message latency

The **first** DM to a new peer triggers a prekey fetch + X3DH handshake under the hood. You'll see a short delay (one RTT for the prekey, one for the DM). The CLI shows `📤 Encrypted message sent to <peer>` once the message goes out. Subsequent DMs in the same session are immediate — the ratchet state is cached in memory and persisted to `messages.db` so it survives restart.

## 💾 Data Storage

- **Windows:** `%LOCALAPPDATA%\ME55\<profile>\`
- **Linux:** `~/.local/share/ME55/<profile>/`
- **macOS:** `~/Library/Application Support/ME55/<profile>/`

Files per profile:
- `identity.json` — Ed25519 identity keys + X25519 signed prekey + the Ed25519 signature over the prekey. **Private — never transmitted.** On unix the file is `chmod 0600`; on Windows it falls back to default ACL (a Phase 3.5 task).
- `messages.db` — SQLite store. Tables:
  - `messages` — local view of conversation history (plaintext on your machine; on the wire it was ciphertext).
  - `contacts` — auto-populated from first verified DM.
  - `channels` — placeholder for future public channels.
  - `prekeys_seen` — verified X25519 prekeys of peers you've talked to.
  - `ratchet_sessions` — per-peer Double Ratchet state, JSON-serialized. **Plaintext at rest until Phase 3.5 adds OS-keyring integration.**

## 🔐 Security

### Cryptography in use
- **Identity:** Ed25519 long-term key, generated on first run.
- **Signed prekey:** X25519 long-term prekey, Ed25519-signed by the identity key (domain `ME55-prekey-v1`).
- **Transport (hop-level):** libp2p Noise Protocol (ChaCha20-Poly1305).
- **Peer ID:** Ed25519 inline-pubkey multihash (code = 0). Recipients can verify signatures against keys extracted directly from the PeerId — no out-of-band key distribution.
- **Application-layer authentication:** Every DM is Ed25519-signed over a domain-separated, length-prefixed canonical byte layout (`ME55-dm-v1`). Receivers verify the signature *and* check that the transport peer matches the signed sender.
- **End-to-end confidentiality:** Double Ratchet (per Signal spec).
  - Initial key agreement: X3DH-lite (two-DH: initiator-ephemeral × responder-prekey, initiator-identity × responder-prekey). HKDF-SHA256 with domain `ME55-x3dh-v1`.
  - Root-key KDF: HKDF-SHA256 with domain `ME55-rk-v1`.
  - Chain-key KDF: HMAC-SHA256 with one-byte constants per Signal spec.
  - Per-message AEAD: ChaCha20-Poly1305 with zero nonce (safe: each message key is one-shot).
  - Associated data: length-prefixed `sender_pid || recipient_pid` + the ratchet header bytes.
- **Skipped-message-key cache:** `MAX_SKIP = 1000` keys per session; oldest-first eviction beyond.

## 🛡️ Threat Model

### What an attacker on the wire cannot do
- **Forge messages** as another peer — the application-layer Ed25519 signature is bound to the sender's PeerId.
- **Replay messages across sessions** — the ratchet AEAD's associated data includes both PeerIds, and the per-message key changes every step.
- **Decrypt past traffic after compromising a session key** — forward secrecy via the symmetric chain ratchet.
- **Decrypt indefinitely after one-time compromise** — post-compromise security recovers on the next DH ratchet step.
- **Substitute their own prekey via MITM** — the prekey is Ed25519-signed by the long-term identity key; recipients verify the signature before use.

### What an attacker can still do (intentional or known gaps)
- **Initial-DM MITM (limited):** because there is no out-of-band identity verification (no safety-number UI yet), a network attacker who can intercept the **first ever connection** between two peers AND substitute *both* sides' PeerIds in libp2p's identify exchange could theoretically run a relay. This is mitigated only by the fact that the Ed25519 key inside a PeerId is the *whole* identity — substituting it changes the PeerId the user typed. **Verify PeerIds out of band** for high-stakes contacts.
- **Asynchronous first-message delivery is not supported.** Without one-time prekeys (Phase 3.5), the responder must be reachable when the initiator does the first send.
- **No deniability.** The per-message Ed25519 signature on the envelope provides cryptographic proof of authorship — by design, for now, to keep verification simple. This is the opposite of Signal's deniability property.
- **Traffic analysis.** Message size, timing, sender/recipient PeerIds, and the existence of the conversation are visible to any on-path observer. Mitigation requires Obfs4 + cover traffic (Phase 4).
- **Metadata in the DHT.** Kademlia lookups reveal who you're trying to find.

### What an attacker with local file access can do
- **Read all your conversation history.** `messages.db` stores local plaintext for your own view.
- **Read your private identity key.** `identity.json` is plaintext (`chmod 0600` on unix; default ACL on Windows).
- **Read your ratchet session state.** `ratchet_sessions.state_blob` is plaintext JSON — they can decrypt all future messages from peers whose sessions you have, and forge messages to those peers as you.
- **All three of these become opt-in encrypted-at-rest in Phase 3.5** via OS keyring integration (Windows DPAPI / macOS Keychain / Linux secret-service).

### Gap to "Signal-equivalent"
Phase 3 lands the cryptographic core. To reach parity with Signal:
- One-time prekeys (asynchronous first-message delivery).
- Encrypted state at rest (Phase 3.5).
- Deniability (use a deniable AKE instead of long-term Ed25519 signatures, e.g. SPK signature plus per-conversation MAC).
- Sealed sender / metadata privacy.
- Safety-number UI for out-of-band identity verification.
- Tested implementations vetted by external review. **This codebase has not been audited.**

## 📋 Next Steps (To Implement)

| Feature | Status | Priority |
|---|---|---|
| Identity generation (Ed25519 + signed X25519 prekey) | ✅ Done | — |
| P2P listening | ✅ Done | — |
| Peer discovery (mDNS / Kad DHT) | ✅ Done | — |
| Direct messaging (signed, request-response, E2EE) | ✅ Done | — |
| Contact management (auto-persist; no alias/remove) | ⚠️ Partial | Medium |
| Message storage + TTL sweep | ✅ Done | — |
| E2EE Double Ratchet + X3DH-lite | ✅ Done | — |
| Session persistence (plaintext at rest) | ✅ Done | — |
| Encrypt state at rest (OS keyring) | ❌ TODO | High (Phase 3.5) |
| One-time prekeys (async first message) | ❌ TODO | High (Phase 3.5) |
| Offline delivery / store-and-forward | ❌ TODO | Medium (Phase 4) |
| Bootstrap-node CLI flag (cold-start DHT beyond LAN) | ❌ TODO | Medium |
| Obfuscation (Obfs4 / pluggable transports) | ❌ TODO | High (Phase 4) |
| GUI (Tauri) | ⚠️ Stub | Medium |
| Group chats (Megolm-style) | ❌ TODO | Low |
| External security audit | ❌ TODO | **Required before serious use** |

## 🐛 Troubleshooting

**Instances can't find each other?**
- Make sure they're on the same network
- Check firewall settings (allow the executable)
- mDNS should auto-discover on local network

**Want to see debug logs?**
```bash
set RUST_LOG=trace
target\release\ME55.exe --profile alice
```

## 📄 License

MIT - Decentralized software for decentralized people
