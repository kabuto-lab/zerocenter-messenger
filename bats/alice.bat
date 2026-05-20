@echo off
REM Launch a ZeroCenter node under the "alice" profile (headless REPL).
REM --cli forces the line-based REPL — the GUI is the default surface
REM on a --features gui build, and the TEST_GUIDE flow needs the REPL.
title ZeroCenter - alice
cd /d "%~dp0.."
set RUST_LOG=info
target\release\zerocenter.exe --profile alice --cli
echo.
echo === zerocenter (alice) exited ===
pause
