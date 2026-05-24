@echo off
REM ME55 Messenger — bob via the PUBLIC bootstrap+relay node.
REM Sibling of gui-alice-public.bat — see that file for the full
REM rationale. Together these two .bat launchers let you smoke-test
REM the entire bootstrap+relay flow on one machine, without involving
REM a friend yet.
cd /d "%~dp0.."
set RUST_LOG=info
set WEBVIEW2_BROWSER_EXECUTABLE_FOLDER=C:\Users\a3\AppData\Local\WebView2Runtime\Microsoft.WebView2.FixedVersionRuntime.148.0.3967.70.x64
start "" "ME55AGUI.exe" --profile bob-public --no-mdns --relay /ip4/45.9.40.37/tcp/4001/p2p/12D3KooWQ643AEmTK2CHDmhLAgXQ1oCZ12pNZHVvGgrrUTEVcPD9
