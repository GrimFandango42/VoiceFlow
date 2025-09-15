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

set PYTHONPATH=%cd%\src
python -c "import sys; sys.path.insert(0, 'src'); exec(open('src/voiceflow/ui/cli_enhanced.py').read())"

pause