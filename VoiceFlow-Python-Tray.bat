@echo off
echo ========================================
echo VoiceFlow - Python System Tray Launcher
echo ========================================
echo.
echo This version uses Python for the system tray (more reliable)
echo.

cd /d "C:\AI_Projects\VoiceFlow"

echo [1] Installing system tray dependencies...
python\venv\Scripts\pip install pystray pillow

echo.
echo [2] Starting VoiceFlow with Python system tray...
echo.
echo VoiceFlow is starting...
echo - Python STT server will start automatically
echo - System tray icon will appear (microphone icon)
echo - Press Ctrl+Alt anywhere to use voice transcription
echo.

python\venv\Scripts\python.exe python\simple_tray.py

echo.
echo VoiceFlow has exited.
pause
