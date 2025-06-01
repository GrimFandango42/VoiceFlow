@echo off
title VoiceFlow - Simple Global Voice Transcription
echo.
echo ================================================================
echo                     VoiceFlow - Simple & Clean
echo              Press and Hold Ctrl+Alt Anywhere to Record
echo ================================================================
echo.

cd /d "%~dp0"

echo [Setup] Checking Python environment...
if not exist "python\venv\Scripts\python.exe" (
    echo [Error] Python environment not found!
    echo [Fix] Run: INSTALL_ENHANCED_DEPS.bat
    pause
    exit /b 1
)

echo [Setup] Activating Python environment...
call python\venv\Scripts\activate.bat

echo [Setup] Checking dependencies...
python -c "import RealtimeSTT, keyboard, pyautogui, win32api" 2>nul
if errorlevel 1 (
    echo [Warning] Missing dependencies - installing...
    pip install RealtimeSTT keyboard pyautogui pywin32
)

echo.
echo [Starting] VoiceFlow Streamlined...
echo.
echo ✅ Simple Ctrl+Alt hotkey (press and hold)
echo ✅ Works in any Windows application
echo ✅ Instant text injection at cursor
echo ✅ AI enhancement via Ollama (if available)
echo ✅ Clean, focused functionality
echo.
echo Usage:
echo   1. Position cursor where you want text
echo   2. Press and HOLD Ctrl+Alt
echo   3. Speak clearly
echo   4. Release keys when done
echo   5. Text appears instantly!
echo.
echo Press Ctrl+C to stop
echo.

cd python
python voiceflow_streamlined.py

echo.
echo [Shutdown] VoiceFlow stopped
pause