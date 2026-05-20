@echo off
REM Launch a ZeroCenter node under the "bob" profile (headless REPL).
REM --cli forces the line-based REPL — the GUI is the default surface
REM on a --features gui build, and the TEST_GUIDE flow needs the REPL.
title ZeroCenter - bob
cd /d "%~dp0.."
set RUST_LOG=info
target\release\zerocenter.exe --profile bob --cli
echo.
echo === zerocenter (bob) exited ===
pause
