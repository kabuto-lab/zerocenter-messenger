pub mod core;
pub mod crypto;
pub mod network;
pub mod storage;
pub mod protocol;
pub mod cli;
pub mod entry;
pub(crate) mod serde_helpers;

// Tauri webview frontend. Gated on the `gui` Cargo feature; see
// `plans/phase4-gui.md` for the integration plan. The default CLI
// build does not pull Tauri.
#[cfg(feature = "gui")]
pub mod gui;

pub use core::{Config, P2PNode, Identity, NodeCommand};
pub use cli::CommandHandler;
