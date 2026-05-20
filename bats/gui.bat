@echo off
REM Launch the ZeroCenter GUI client (Tauri webview).
REM The GUI is the default surface on a binary built with
REM `cargo build --release --features gui`, so no flag is needed.
REM Uses the "alice" profile so contacts/history from CLI testing
REM show up — change --profile for a clean identity.
title ZeroCenter - GUI
cd /d "%~dp0.."
set RUST_LOG=info
REM WebView2 Fixed Version Runtime (this machine has no Edge/EdgeUpdate,
REM so the Evergreen runtime cannot install). Also set as a persistent
REM user env var, so a raw double-click of the exe works too.
set WEBVIEW2_BROWSER_EXECUTABLE_FOLDER=C:\Users\a3\AppData\Local\WebView2Runtime\Microsoft.WebView2.FixedVersionRuntime.148.0.3967.70.x64
target\release\zerocenter.exe --profile alice
echo.
echo === zerocenter GUI exited ===
pause
