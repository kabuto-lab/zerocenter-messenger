@echo off
REM ME55 Messenger — alice via the PUBLIC bootstrap+relay node.
REM
REM Pair with gui-bob-public.bat to test the full bootstrap+relay
REM path on a single machine. --no-mdns disables loopback multicast
REM so the two instances DON'T find each other instantly via mDNS —
REM they have to go through bootstrap-1 at 45.9.40.37.
REM
REM Use --profile alice-public (distinct from --profile alice which
REM is the local-mDNS test) so the two test scenarios don't share an
REM identity / message DB and confuse you about which one you're in.
cd /d "%~dp0.."
set RUST_LOG=info
set WEBVIEW2_BROWSER_EXECUTABLE_FOLDER=C:\Users\a3\AppData\Local\WebView2Runtime\Microsoft.WebView2.FixedVersionRuntime.148.0.3967.70.x64
start "" "ME55AGUI.exe" --profile alice-public --no-mdns --relay /ip4/45.9.40.37/tcp/4001/p2p/12D3KooWQ643AEmTK2CHDmhLAgXQ1oCZ12pNZHVvGgrrUTEVcPD9
