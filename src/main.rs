//! `ME55` — CLI-defaulting binary entry point.
//!
//! Windows CONSOLE subsystem (default for Rust binaries). The actual
//! work lives in [`ME55_messenger::entry::run`], which is shared
//! verbatim with the `ME55AGUI` binary (`src/bin/me55agui.rs`).

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    ME55_messenger::entry::run().await
}
