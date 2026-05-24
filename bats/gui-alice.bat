@echo off
REM Launch ME55AGUI.exe under the "alice" profile and exit the
REM launcher immediately so only the Tauri webview window remains.
REM ME55AGUI.exe is built with windows_subsystem = "windows", so
REM it does not spawn its own console window either.
cd /d "%~dp0.."
set RUST_LOG=info
REM WebView2 Fixed Version Runtime (this machine has no Edge/EdgeUpdate,
REM so the Evergreen runtime cannot install). Also set as a persistent
REM user env var, so a raw double-click of the exe works too.
set WEBVIEW2_BROWSER_EXECUTABLE_FOLDER=C:\Users\a3\AppData\Local\WebView2Runtime\Microsoft.WebView2.FixedVersionRuntime.148.0.3967.70.x64
start "" "ME55AGUI.exe" --profile alice
