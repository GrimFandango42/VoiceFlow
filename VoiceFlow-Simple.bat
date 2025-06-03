@echo off
title VoiceFlow - Simple Global Voice Transcription
echo.
echo ================================================================
echo                     VoiceFlow - Simple and Clean
echo                    Press Ctrl+Alt Anywhere to Record
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

echo [Setup] Installing missing dependencies (this may take a moment)...
echo [Info] Installing RealtimeSTT...
pip install RealtimeSTT --quiet --disable-pip-version-check

echo [Info] Installing system integration...
pip install keyboard pyautogui --quiet --disable-pip-version-check

echo [Info] Installing AI enhancement...
pip install requests --quiet --disable-pip-version-check

echo.
echo [Starting] VoiceFlow Simple Server...
echo.
echo [OK] Simple Ctrl+Alt hotkey (tap, don't hold)
echo [OK] Works in any Windows application  
echo [OK] Instant text injection at cursor
echo [OK] AI enhancement via Ollama (if available)
echo [OK] Streamlined, reliable functionality
echo.
echo How to use:
echo   1. Position cursor where you want text
echo   2. Press Ctrl+Alt (tap once)
echo   3. Speak clearly
echo   4. Text appears instantly!
echo.
echo Press Ctrl+C to stop VoiceFlow
echo.

cd python
python simple_server.py

echo.
echo [Shutdown] VoiceFlow stopped
pause