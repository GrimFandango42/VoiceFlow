@echo off
cd /d %~dp0\..\..
echo ========================================
echo VoiceFlow - Terminal Mode (No Visuals)
echo ========================================
echo.
echo - Terminal output only
echo - No system tray icon
echo - No visual indicators
echo.
echo Press Ctrl+C to exit
echo.

set PYTHONPATH=src
python -m voiceflow.ui.cli_enhanced --no-tray

pause