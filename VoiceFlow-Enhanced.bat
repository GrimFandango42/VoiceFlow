@echo off
title Enhanced VoiceFlow - Wispr Flow Compatible
echo.
echo ================================================================
echo             Enhanced VoiceFlow - Global Voice Transcription
echo                    Press Ctrl+Alt+Space Anywhere to Record
echo ================================================================
echo.

cd /d "%~dp0"

echo [SETUP] Checking Python environment...
if not exist "python\venv\Scripts\python.exe" (
    echo [ERROR] Python virtual environment not found!
    echo [FIX] Run: INSTALL_DEPS.bat
    pause
    exit /b 1
)

echo [SETUP] Activating Python environment...
call python\venv\Scripts\activate.bat

echo [SETUP] Checking dependencies...
python -c "import RealtimeSTT, keyboard, pyautogui, win32api" 2>nul
if errorlevel 1 (
    echo [ERROR] Missing dependencies!
    echo [FIX] Installing missing packages...
    pip install RealtimeSTT keyboard pyautogui pywin32
)

echo [STARTUP] Starting Enhanced VoiceFlow Server...
echo.
echo ✅ Global hotkey: Ctrl+Alt+Space
echo ✅ Works in any application
echo ✅ Instant text injection
echo ✅ AI enhancement via Ollama
echo.
echo Press Ctrl+C to stop
echo.

python python\enhanced_stt_server.py

echo.
echo [SHUTDOWN] Enhanced VoiceFlow stopped
pause