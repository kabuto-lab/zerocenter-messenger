@echo off
REM ME55 Messenger — launch under "me" profile, connected to the public
REM bootstrap+relay node on Beget VPS (45.9.40.37). This is what you run
REM on YOUR machine for the first end-to-end smoke test with a friend.
REM
REM --relay tells our node to listen on /p2p-circuit so the friend can
REM reach us even when both of us are behind NAT. Bootstrap discovery
REM is automatic — DEFAULT_BOOTSTRAPS in src/network/bootstrap.rs is
REM populated since commit b3afa72, so no --bootstrap flag needed.
cd /d "%~dp0.."
set RUST_LOG=info
set WEBVIEW2_BROWSER_EXECUTABLE_FOLDER=C:\Users\a3\AppData\Local\WebView2Runtime\Microsoft.WebView2.FixedVersionRuntime.148.0.3967.70.x64
start "" "ME55AGUI.exe" --profile me --relay /ip4/45.9.40.37/tcp/4001/p2p/12D3KooWQ643AEmTK2CHDmhLAgXQ1oCZ12pNZHVvGgrrUTEVcPD9
