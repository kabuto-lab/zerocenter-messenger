@echo off
echo Starting ZeroCenter Messenger Test
echo.
echo === Starting Alice ===
start "Alice" cmd /k "cd /d C:\__Qwen1\ME55 && set RUST_LOG=info && target\release\zerocenter.exe --profile alice"
timeout /t 3
echo.
echo === Starting Bob ===
start "Bob" cmd /k "cd /d C:\__Qwen1\ME55 && set RUST_LOG=info && target\release\zerocenter.exe --profile bob"
echo.
echo Both instances started in separate windows!
echo Close them by typing 'quit' in each window.
pause
