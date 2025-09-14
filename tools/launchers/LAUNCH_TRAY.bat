@echo off
cd /d %~dp0\..\..
echo ==========================================
echo VoiceFlow - Tray Mode (With Visuals)
echo ==========================================
echo.
echo Features:
echo - System tray icon with status colors
echo - Bottom-screen overlay (like Wispr Flow)
echo - Visual feedback for all transcription states
echo - Background operation (can close terminal)
echo.
echo Press Ctrl+C to exit or close from tray menu
echo.

python -m src.voiceflow.ui.cli_enhanced

pause