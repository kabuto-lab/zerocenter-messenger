# ZeroCenter Messenger - Development Context
**Date:** March 3, 2026
**Status:** Phase 1 Complete - P2P Foundation Working

---

## ✅ What's Completed

### Core Infrastructure
- [x] Rust project scaffold with Cargo.toml
- [x] Multi-profile support (--profile alice, --profile bob)
- [x] Ed25519 identity generation and persistence
- [x] libp2p integration (TCP, QUIC, Noise, Yamux)
- [x] Kademlia DHT for peer discovery
- [x] Gossipsub for pubsub messaging
- [x] mDNS for local network discovery
- [x] Identify protocol for peer info exchange
- [x] SQLite storage layer (ready for messages)
- [x] CLI interface with basic commands

### File Structure
```
C:\__Qwen1\ME55\
├── Cargo.toml              # Dependencies (libp2p 0.53, tokio, ed25519-dalek, etc.)
├── Cargo.lock              # Locked dependency versions
├── README.md               # Updated with working instructions
├── test.bat                # Quick test script (opens 2 windows)
├── tauri.conf.json         # Future GUI config
├── ME55AG.html             # Project roadmap/requirements
├── src/
│   ├── main.rs             # Entry point (multi-profile, async)
│   ├── lib.rs              # Library exports
│   ├── cli.rs              # CLI commands (help, quit)
│   ├── core/
│   │   ├── mod.rs
│   │   ├── identity.rs     # Ed25519 keys, save/load from disk
│   │   ├── config.rs       # Node configuration
│   │   └── node.rs         # P2P node (Swarm, event loop)
│   ├── network/
│   │   ├── mod.rs
│   │   └── behaviour.rs    # Combined NetworkBehaviour
│   ├── crypto/
│   │   └── mod.rs          # Key conversion utilities
│   ├── protocol/
│   │   ├── mod.rs
│   │   └── message.rs      # ProtocolMessage struct
│   ├── storage/
│   │   ├── mod.rs
│   │   └── store.rs        # SQLite (MessageStore)
│   └── gui/
│       ├── mod.rs
│       └── app.rs          # Tauri stub (future)
├── dist/
│   └── index.html          # Frontend UI mockup
└── target/
    └── release/
        └── zerocenter.exe  # Built executable
```

### Working Commands
```bash
# Build release
cargo build --release

# Run two instances
target\release\zerocenter.exe --profile alice
target\release\zerocenter.exe --profile bob

# With logging
set RUST_LOG=info
target\release\zerocenter.exe --profile alice
```

### Data Locations
- **Identity:** `%LOCALAPPDATA%\ZeroCenter\<profile>\identity.json`
- **Messages:** `%LOCALAPPDATA%\ZeroCenter\<profile>\messages.db`

---

## ❌ What's NOT Yet Implemented

### High Priority (Next Session)
1. **Direct Messaging** - Send/receive messages between peers
2. **Contact Management** - Add contacts by Peer ID
3. **Message Storage** - Save/load messages from SQLite
4. **Peer Connection** - Manually connect to specific peer

### Medium Priority
5. **E2EE** - Double Ratchet encryption for messages
6. **GUI** - Tauri frontend integration
7. **Obfuscation** - Obfs4/Snowflake transport

### Future
8. **Voice/Video** - WebRTC integration
9. **Group Chat** - MLS protocol
10. **File Sharing** - IPFS integration

---

## 🔧 Technical Details

### Dependencies (Key)
```toml
libp2p = "0.53"  # P2P networking
tokio = "1.35"   # Async runtime
ed25519-dalek = "2.1"  # Identity
rusqlite = "0.30"  # Storage
clap = "4.4"     # CLI
```

### NetworkBehaviour Components
```rust
pub struct Behaviour {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
}
```

### Identity Structure
```rust
pub struct Identity {
    signing_key: SigningKey,      // Ed25519 private key
    verifying_key: VerifyingKey,  // Ed25519 public key
    peer_id: PeerId,              // libp2p peer ID
    keypair: Keypair,             // libp2p keypair
}
```

### Protocol Message (Ready to use)
```rust
pub struct ProtocolMessage {
    pub to: Vec<u8>,
    pub from: Vec<u8>,
    pub payload: Vec<u8>,
    pub timestamp: i64,
    pub ttl: i64,
    pub msg_type: MessageType,
}
```

---

## 📋 Next Session - Action Plan

### Step 1: Implement Peer Connection
```rust
// Add to cli.rs
async fn connect_to_peer(node: &mut P2PNode, peer_id: &str, address: &str) {
    // Parse multiaddr
    // Dial peer
    // Wait for connection
}
```

### Step 2: Implement Message Sending
```rust
// Add to core/node.rs
pub async fn send_message(&mut self, recipient: PeerId, content: &str) {
    // Encrypt payload (plaintext for now, E2EE later)
    // Create ProtocolMessage
    // Send via gossipsub or direct connection
}
```

### Step 3: Implement Message Reception
```rust
// In handle_behaviour_event()
BehaviourEvent::Gossipsub(GossipsubEvent::Message { message }) => {
    // Decrypt
    // Store in SQLite
    // Display to user
}
```

### Step 4: Add CLI Commands
```
> connect <peer_id> <address>
> send <peer_id> <message>
> list <peer_id>
> contacts
```

---

## 🐛 Known Issues

1. **CLI stdin handling** - Works in interactive mode, not with pipes
2. **No bootstrap nodes** - Peers can only find each other via mDNS (local network)
3. **No message encryption yet** - Payloads are plaintext

---

## 📚 Reference Files

- **Roadmap:** `ME55AG.html` - Full project requirements
- **Architecture:** See `ME55AG.html` tabs for stack details
- **libp2p docs:** https://docs.rs/libp2p/0.53.2/libp2p/

---

## 🎯 Tomorrow's Goal

**Minimum Viable Demo:**
1. Start two instances (alice, bob)
2. Alice connects to Bob
3. Alice sends "Hello!"
4. Bob receives and displays it
5. Bob replies
6. Messages persist in SQLite

---

**Last Build:** `cargo build --release` succeeded
**Executable:** `target\release\zerocenter.exe` (working)
**Tested:** Multiple instances run simultaneously ✓
