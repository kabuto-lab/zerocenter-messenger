@echo off
REM Launch ME55AGUI.exe under the "bob" profile and exit the
REM launcher immediately so only the Tauri webview window remains.
REM ME55AGUI.exe is built with windows_subsystem = "windows", so
REM it does not spawn its own console window either.
cd /d "%~dp0.."
set RUST_LOG=info
set WEBVIEW2_BROWSER_EXECUTABLE_FOLDER=C:\Users\a3\AppData\Local\WebView2Runtime\Microsoft.WebView2.FixedVersionRuntime.148.0.3967.70.x64
start "" "ME55AGUI.exe" --profile bob
