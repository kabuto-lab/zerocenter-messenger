# ZeroCenter Messenger

Censorship-Resistant, Zero-Trust, Leaderless P2P Communication Platform

## ✅ Working Features

### Phase 1 Complete
- ✅ Ed25519 identity generation
- ✅ libp2p integration (TCP, QUIC)
- ✅ Kademlia DHT for peer discovery
- ✅ Noise Protocol encryption
- ✅ mDNS local network discovery
- ✅ Gossipsub pubsub messaging
- ✅ Multi-profile support (run multiple instances)
- ✅ SQLite local storage

### Phase 2 Complete (New!)
- ✅ Direct messaging via gossipsub
- ✅ Message storage in SQLite
- ✅ Peer connection via multiaddr
- ✅ Connected peers listing
- ✅ Contact listing

## 🚀 Quick Start

### Run Two Instances on Same PC

**Option 1: Manual (Recommended for testing)**

Open two terminal windows:

**Window 1 (Alice):**
```bash
cd C:\__Qwen1\ME55
set RUST_LOG=info
target\release\zerocenter.exe --profile alice
```

**Window 2 (Bob):**
```bash
cd C:\__Qwen1\ME55
set RUST_LOG=info
target\release\zerocenter.exe --profile bob
```

**Option 2: Test Script**

Double-click `test.bat` - it will open two console windows automatically.

### Expected Output

```
📡 ZeroCenter Messenger
══════════════════════════════════════
Profile: alice
Peer ID: 12D3KooWRx...

Type 'help' for commands, 'quit' to exit.

> 
```

Each instance will:
- Generate its own Ed25519 identity (saved to `%LOCALAPPDATA%\ZeroCenter\<profile>\`)
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
│   │   ├── identity.rs  # Ed25519 identity management
│   │   ├── config.rs    # Configuration
│   │   └── node.rs      # P2P node (libp2p)
│   ├── network/
│   │   └── behaviour.rs # libp2p behaviours (Kademlia, Gossipsub, mDNS)
│   ├── crypto/
│   │   └── mod.rs       # Cryptographic utilities
│   ├── protocol/
│   │   └── message.rs   # Protocol message format
│   ├── storage/
│   │   └── store.rs     # SQLite storage
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

Output: `target\release\zerocenter.exe`

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
| `contacts` | `co` | List contacts |

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

## 💾 Data Storage

- **Windows:** `%LOCALAPPDATA%\ZeroCenter\<profile>\`
- **Linux:** `~/.local/share/ZeroCenter/<profile>/`
- **macOS:** `~/Library/Application Support/ZeroCenter/<profile>/`

Files per profile:
- `identity.json` - Ed25519 keys (private)
- `messages.db` - SQLite message store (future)

## 🔐 Security

- **Identity:** Ed25519 keys generated on first run
- **Transport:** Noise Protocol (ChaCha20-Poly1305)
- **Peer ID:** Derived from public key (cryptographic hash)

## 📋 Next Steps (To Implement)

| Feature | Status | Priority |
|---------|--------|----------|
| Identity generation | ✅ Done | — |
| P2P listening | ✅ Done | — |
| Peer discovery (mDNS/DHT) | ✅ Done | — |
| Direct messaging | ✅ Done | — |
| Contact management | ✅ Done | — |
| Message storage | ✅ Done | — |
| E2EE (Double Ratchet) | ❌ TODO | Critical |
| GUI (Tauri) | ⚠️ Stub | Medium |
| Obfuscation (Obfs4) | ❌ TODO | High |

## 🐛 Troubleshooting

**Instances can't find each other?**
- Make sure they're on the same network
- Check firewall settings (allow the executable)
- mDNS should auto-discover on local network

**Want to see debug logs?**
```bash
set RUST_LOG=trace
target\release\zerocenter.exe --profile alice
```

## 📄 License

MIT - Decentralized software for decentralized people
