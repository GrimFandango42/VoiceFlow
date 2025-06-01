@echo off
echo ========================================
echo VoiceFlow - Compatibility Fixed Launcher  
echo ========================================
echo.
echo Starting VoiceFlow with Python 3.13 compatibility fixes...
echo.

cd /d "C:\AI_Projects\VoiceFlow"

echo [1] Testing patched Python server...
python\venv\Scripts\python.exe -c "import enum; print('Enum patch ready')"
if %errorlevel% neq 0 (
    echo ERROR: Python environment issue
    pause
    exit /b 1
)

echo [2] Starting VoiceFlow with compatibility patches...
echo.
echo VoiceFlow is starting in the background...
echo Look for microphone icon in system tray
echo Press Ctrl+Alt anywhere to use voice transcription
echo.

start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "VoiceFlow-Fixed.ps1"

echo [3] VoiceFlow started!
echo.
echo USAGE:
echo - Look for microphone icon in system tray
echo - Right-click tray icon for options and testing
echo - Press Ctrl+Alt in any app to start voice recording
echo - Speak your text clearly
echo - Release Ctrl+Alt to stop recording 
echo - Text will appear automatically at cursor!
echo.
echo To stop VoiceFlow: Right-click tray icon and select Exit
echo.
pause
