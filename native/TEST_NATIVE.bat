@echo off
title VoiceFlow Native - Test Launcher
cd /d "C:\AI_Projects\VoiceFlow\native"

echo ================================================
echo VoiceFlow Native - Invisible Voice Transcription
echo ================================================
echo.

:: Check if Python environment exists
if not exist "..\python\venv\Scripts\python.exe" (
    echo ERROR: Python virtual environment not found
    echo Please run this from the main VoiceFlow directory
    pause
    exit /b 1
)

:: Install native requirements in the existing venv
echo Installing native application requirements...
..\python\venv\Scripts\pip.exe install -r requirements.txt

echo.
echo Starting VoiceFlow Native...
echo.
echo INSTRUCTIONS:
echo 1. System tray icon will appear
echo 2. Press and HOLD Ctrl+Alt to start recording
echo 3. Speak naturally
echo 4. Release Ctrl+Alt to stop and process
echo 5. Text will appear at your cursor
echo.
echo Right-click system tray icon for options
echo.

:: Run the native application
..\python\venv\Scripts\python.exe voiceflow_native.py

echo.
echo VoiceFlow Native has stopped.
pause
