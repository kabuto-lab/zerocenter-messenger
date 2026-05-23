# bats/ — node launch helpers

Double-click any of these to start a ME55 node in its own
console window:

| Script      | Profile | Surface | Use                                       |
|-------------|---------|---------|-------------------------------------------|
| `gui.bat`   | alice   | GUI     | Tauri webview client — the normal client  |
| `alice.bat` | alice   | CLI     | Node A — DM + group-chat tests (REPL)     |
| `bob.bat`   | bob     | CLI     | Node B — DM + group-chat tests (REPL)     |
| `carol.bat` | carol   | CLI     | Optional 3rd node (founder-only group)    |

## GUI vs CLI

On a binary built with `cargo build --release --features gui`, the
**GUI is the default** — `ME55.exe` with no flag opens the
webview window. `gui.bat` just runs that.

The `--cli` flag forces the headless line-based REPL. The test
launchers (`alice.bat` / `bob.bat` / `carol.bat`) pass `--cli`
because the TEST_GUIDE flow drives the REPL (`send`, `peers`,
`group …`).

A binary built **without** `--features gui` is CLI-only; it ignores
the default and runs the REPL regardless.

## What each script does

1. `cd`s to the repo root (`%~dp0..`), so it works wherever the repo lives.
2. Sets `RUST_LOG=info` — makes `warn!`/`info!` logs visible. Without it
   only `error!` shows, so dropped-message reasons stay invisible.
   Lower it to `warn` for less noise, or `debug` for more.
3. Runs `target\release\ME55.exe --profile <name>` (the CLI
   scripts add `--cli`).
4. `pause`s on exit so a startup crash stays readable.

Build first:

```
cargo build --release --features gui   # GUI + CLI
cargo build --release                  # CLI only, smaller binary
```
