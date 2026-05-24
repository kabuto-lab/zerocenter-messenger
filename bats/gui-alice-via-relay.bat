@echo off
REM Launch alice via the local relay-server (127.0.0.1:4001).
REM The relay must be running first — start it with:
REM   .\ME55.exe --profile relayhost --port 4001 --relay-server --daemon
REM Pair this with gui-bob-via-relay.bat to exchange messages through
REM the relay rather than through mDNS direct.
cd /d "%~dp0.."
set RUST_LOG=info
set WEBVIEW2_BROWSER_EXECUTABLE_FOLDER=C:\Users\a3\AppData\Local\WebView2Runtime\Microsoft.WebView2.FixedVersionRuntime.148.0.3967.70.x64
start "" "ME55AGUI.exe" --profile alice ^
    --bootstrap /ip4/127.0.0.1/tcp/4001/p2p/12D3KooWPUW49HfHEpX8VzfJCL7vEZ2YfuRF1bMGGLmPdN7kqEn2 ^
    --relay     /ip4/127.0.0.1/tcp/4001/p2p/12D3KooWPUW49HfHEpX8VzfJCL7vEZ2YfuRF1bMGGLmPdN7kqEn2
