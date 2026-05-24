@echo off
REM Launch bob via the local relay-server (127.0.0.1:4001).
REM See gui-alice-via-relay.bat for the relay-server startup command.
cd /d "%~dp0.."
set RUST_LOG=info
set WEBVIEW2_BROWSER_EXECUTABLE_FOLDER=C:\Users\a3\AppData\Local\WebView2Runtime\Microsoft.WebView2.FixedVersionRuntime.148.0.3967.70.x64
start "" "ME55AGUI.exe" --profile bob ^
    --bootstrap /ip4/127.0.0.1/tcp/4001/p2p/12D3KooWPUW49HfHEpX8VzfJCL7vEZ2YfuRF1bMGGLmPdN7kqEn2 ^
    --relay     /ip4/127.0.0.1/tcp/4001/p2p/12D3KooWPUW49HfHEpX8VzfJCL7vEZ2YfuRF1bMGGLmPdN7kqEn2
