pub mod core;
pub mod crypto;
pub mod network;
pub mod storage;
pub mod protocol;
pub mod cli;

// The `gui` module is a Tauri stub that will be wired up in Phase 4.
// Until then it is disabled unconditionally — reintroduce it behind a real
// `gui` feature in Cargo.toml when we start integrating the desktop shell.

pub use core::{Config, P2PNode, Identity, NodeCommand};
pub use cli::CommandHandler;
