//! `ME55AGUI` — GUI-defaulting binary entry point.
//!
//! Windows GUI subsystem on Windows so launching the exe (via
//! double-click or a `.bat`/`.lnk` shortcut) does NOT spawn an extra
//! console window alongside the Tauri webview. The trade-off: stdout
//! / stderr are not attached, so `println!` and `tracing` output goes
//! to /dev/null. Use the `ME55.exe` binary if you need console logs.
//!
//! Delegates straight to [`ME55_messenger::entry::run`], the same
//! body shared with `src/main.rs`. Only the subsystem attribute
//! differs.

#![cfg_attr(windows, windows_subsystem = "windows")]

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    ME55_messenger::entry::run().await
}
