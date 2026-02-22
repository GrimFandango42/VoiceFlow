@echo off
:: One-click setup for first-time users (Windows)
:: Creates venv, installs dependencies, runs smoke check.

cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\setup\bootstrap_windows.ps1"
if errorlevel 1 (
    echo.
    echo Setup failed. Review the output above.
    exit /b 1
)

echo.
echo Setup complete. Launching VoiceFlow...
call ".\VoiceFlow_Quick.bat"
