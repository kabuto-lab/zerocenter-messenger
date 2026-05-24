use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for a ME55 node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Profile name (e.g., "alice", "bob")
    pub profile: String,

    /// Data directory for this profile
    pub data_dir: PathBuf,

    /// Port to listen on (0 = random)
    pub listen_port: u16,

    /// Bootstrap nodes to connect to
    pub bootstrap_nodes: Vec<String>,

    /// Optional 32-byte obfuscation key. When set, the TCP transport
    /// will be wrapped with `ScrambleStream` (Phase 4b — wiring pending).
    /// Both peers in a conversation must share this key out of band.
    pub obfs_key: Option<[u8; 32]>,

    /// Optional inter-arrival-time jitter cap, in milliseconds. Only
    /// effective when `obfs_key` is also set; the ScrambleStream waits
    /// `uniform(0..=obfs_jitter_ms)` ms before emitting each new frame.
    pub obfs_jitter_ms: Option<u32>,

    /// Circuit-relay multiaddrs to dial on startup. Each address must
    /// include a `/p2p/<PeerId>` suffix — the relay-server's PeerId.
    /// After a successful dial the node will `listen_on(addr/p2p-circuit)`
    /// so peers behind NAT can reach it through the relay. Combine with
    /// `bootstrap_nodes` so the same VPS-hosted node can serve both
    /// roles (DHT bootstrap + circuit relay).
    pub relay_addrs: Vec<String>,

    /// Run this node as a relay server. Public-IP / port-forwarded nodes
    /// set this to `true` so NAT'd peers can use them as relays for
    /// reaching each other. NAT'd peers themselves leave this `false`
    /// (they'd just be advertising a relay they can't actually serve).
    pub enable_relay_server: bool,

    /// Whether to merge the hardcoded fallback bootstrap list
    /// ([`crate::network::bootstrap::DEFAULT_BOOTSTRAPS`]) into the
    /// effective bootstrap set on startup. On by default — this is the
    /// "install and works" path. Off when the user passed
    /// `--no-default-bootstrap` (e.g. private deployments, isolated
    /// test networks, or distrust of the shipped defaults).
    pub use_default_bootstraps: bool,

    /// Phase 3 deniable DMs. When true, outgoing 1:1 DMs use
    /// `new_direct_deniable` / `new_sealed_deniable` — empty
    /// per-message Ed25519 signature, authenticity carried by the
    /// downstream ratchet AEAD. Off by default for wire-compatibility
    /// with peers still on the legacy signed path.
    pub deniable_dm: bool,

    /// Disable mDNS loopback/LAN discovery. Off (mDNS enabled) by
    /// default. Useful for testing the public-bootstrap path with two
    /// instances on the same machine — otherwise they'd find each
    /// other instantly via 224.0.0.251 multicast and the bootstrap
    /// path would never be exercised.
    pub disable_mdns: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            data_dir: PathBuf::from("./data"),
            listen_port: 0, // Random port
            bootstrap_nodes: vec![],
            obfs_key: None,
            obfs_jitter_ms: None,
            relay_addrs: vec![],
            enable_relay_server: false,
            use_default_bootstraps: true,
            deniable_dm: false,
            disable_mdns: false,
        }
    }
}

impl Config {
    /// Create a new config with the given profile
    pub fn with_profile(profile: impl Into<String>) -> Self {
        Self {
            profile: profile.into(),
            ..Default::default()
        }
    }

    /// Set the data directory
    pub fn with_data_dir(mut self, dir: PathBuf) -> Self {
        self.data_dir = dir;
        self
    }

    /// Set the listen port
    pub fn with_port(mut self, port: u16) -> Self {
        self.listen_port = port;
        self
    }

    /// Add a bootstrap node
    pub fn with_bootstrap(mut self, node: impl Into<String>) -> Self {
        self.bootstrap_nodes.push(node.into());
        self
    }
}
