@echo off
echo ==========================================
echo VoiceFlow - Quick Launch
echo ==========================================
echo.
echo Choose your preferred launch mode:
echo.
echo [1] Tray Mode (Recommended) - Visual indicators + System tray
echo [2] Terminal Mode - Console only, no tray
echo [3] Control Center - Unified GUI launcher
echo.
set /p choice="Enter choice (1-3): "

if "%choice%"=="1" (
    call "tools\launchers\LAUNCH_TRAY.bat"
) else if "%choice%"=="2" (
    call "tools\launchers\LAUNCH_TERMINAL.bat"
) else if "%choice%"=="3" (
    call "tools\launchers\LAUNCH_CONTROL_CENTER.bat"
) else (
    echo Invalid choice. Launching tray mode by default...
    call "tools\launchers\LAUNCH_TRAY.bat"
)