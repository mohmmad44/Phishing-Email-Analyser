@echo off
setlocal
cd /d "%~dp0"
echo Installing verified local QR decoder for Cybersteps...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\install-qr-decoder.ps1"
if errorlevel 1 (
  echo.
  echo Installation failed. Check your internet connection or security settings.
  echo No unverified library should be used.
  pause
  exit /b 1
)
echo.
echo Done! Close and reopen Cybersteps index.html in your browser.
pause
