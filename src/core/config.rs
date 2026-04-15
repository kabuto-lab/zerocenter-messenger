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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            data_dir: PathBuf::from("./data"),
            listen_port: 0, // Random port
            bootstrap_nodes: vec![],
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
