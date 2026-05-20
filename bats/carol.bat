@echo off
REM Launch a ZeroCenter node under the "carol" profile (headless REPL).
REM Optional 3rd node — used for the founder-only group-chat test
REM (TEST_GUIDE section 5). --cli forces the REPL over the default GUI.
title ZeroCenter - carol
cd /d "%~dp0.."
set RUST_LOG=info
target\release\zerocenter.exe --profile carol --cli
echo.
echo === zerocenter (carol) exited ===
pause
