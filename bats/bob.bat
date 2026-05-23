@echo off
REM Launch a ME55 node under the "bob" profile (headless REPL).
REM --cli forces the line-based REPL — the GUI is the default surface
REM on a --features gui build, and the TEST_GUIDE flow needs the REPL.
title ME55 - bob
cd /d "%~dp0.."
set RUST_LOG=info
target\release\ME55.exe --profile bob --cli
echo.
echo === ME55 (bob) exited ===
pause
