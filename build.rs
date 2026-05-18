// Build script. Default builds (no `gui` feature) are a complete
// no-op — the script returns immediately and the produced binary
// contains no Tauri code.
//
// With `--features gui`, `tauri_build::build()` parses
// `tauri.conf.json`, generates the embedded `tauri::Context` used by
// `tauri::generate_context!()` in `src/gui/app.rs`, and runs
// capability validation. The function panics on configuration error,
// which surfaces as a cargo build failure with a clear message.
fn main() {
    #[cfg(feature = "gui")]
    tauri_build::build();
}
