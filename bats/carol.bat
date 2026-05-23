@echo off
REM Launch a ME55 node under the "carol" profile (headless REPL).
REM Optional 3rd node — used for the founder-only group-chat test
REM (TEST_GUIDE section 5). --cli forces the REPL over the default GUI.
title ME55 - carol
cd /d "%~dp0.."
set RUST_LOG=info
target\release\ME55.exe --profile carol --cli
echo.
echo === ME55 (carol) exited ===
pause
