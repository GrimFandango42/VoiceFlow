@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\setup\bootstrap_windows.ps1" %*
if errorlevel 1 (
    echo.
    echo Bootstrap failed.
    pause
    exit /b 1
)
echo.
echo Bootstrap completed successfully.
