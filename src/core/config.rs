use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for a ZeroCenter node
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
