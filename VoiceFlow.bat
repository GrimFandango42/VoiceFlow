@echo off
title VoiceFlow - Global Voice Transcription
echo.
echo ================================================================
echo                     VoiceFlow - Voice Transcription
echo              Press and Hold Ctrl+Alt Anywhere to Record
echo ================================================================
echo.

cd /d "%~dp0"

echo [Setup] Checking Python environment...
if not exist "python\venv\Scripts\python.exe" (
    echo [Error] Python environment not found!
    echo [Info] Installing Python environment...
    call INSTALL_ENHANCED_DEPS.bat
    if errorlevel 1 (
        echo [Error] Installation failed!
        pause
        exit /b 1
    )
)

echo [Setup] Activating Python environment...
call python\venv\Scripts\activate.bat

echo [Setup] Checking dependencies...
pip install RealtimeSTT keyboard pyautogui requests --quiet --disable-pip-version-check

echo.
echo [Starting] VoiceFlow Streamlined...
echo.
echo [OK] Simple Ctrl+Alt hotkey (press and hold)
echo [OK] Works in any Windows application
echo [OK] Instant text injection at cursor
echo [OK] AI enhancement via Ollama (if available)
echo [OK] Clean, focused functionality
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
python stt_server.py

echo.
echo [Shutdown] VoiceFlow stopped
pause