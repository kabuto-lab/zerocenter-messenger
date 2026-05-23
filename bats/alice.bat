@echo off
REM Launch a ME55 node under the "alice" profile (headless REPL).
REM --cli forces the line-based REPL — the GUI is the default surface
REM on a --features gui build, and the TEST_GUIDE flow needs the REPL.
title ME55 - alice
cd /d "%~dp0.."
set RUST_LOG=info
target\release\ME55.exe --profile alice --cli
echo.
echo === ME55 (alice) exited ===
pause
