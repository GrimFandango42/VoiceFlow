@echo off
echo ========================================
echo VoiceFlow - Clean Restart
echo ========================================
echo.
echo Cleaning up existing VoiceFlow processes...

:: Kill existing VoiceFlow Python processes
echo Stopping VoiceFlow processes...
taskkill /F /IM python.exe /FI "MEMUSAGE gt 100000" >nul 2>&1
taskkill /F /IM powershell.exe /FI "WINDOWTITLE eq VoiceFlow*" >nul 2>&1

echo Waiting for cleanup...
timeout /t 3 /nobreak >nul

echo.
echo ========================================
echo Starting VoiceFlow with Python Tray
echo ========================================
echo.

cd /d "C:\AI_Projects\VoiceFlow"

echo [1] Installing tray dependencies...
python\venv\Scripts\pip install --quiet pystray pillow

echo [2] Starting VoiceFlow...
echo.
echo Look for microphone icon in system tray!
echo Press Ctrl+Alt anywhere to use voice transcription.
echo.

python\venv\Scripts\python.exe python\simple_tray.py

echo.
echo VoiceFlow stopped.
pause
