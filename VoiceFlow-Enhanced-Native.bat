@echo off
title Enhanced VoiceFlow Native - Wispr Flow Alternative
echo.
echo ================================================================
echo          Enhanced VoiceFlow Native - True Global Transcription
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

echo [SETUP] Checking enhanced dependencies...
python -c "import RealtimeSTT, keyboard, pyautogui, win32api, pystray, PIL" 2>nul
if errorlevel 1 (
    echo [WARNING] Missing enhanced dependencies!
    echo [FIX] Installing enhanced packages...
    pip install RealtimeSTT keyboard pyautogui pywin32 pystray pillow requests
    echo [SETUP] Enhanced dependencies installed
)

echo [STARTUP] Starting Enhanced VoiceFlow Native...
echo.
echo ✅ Truly invisible operation
echo ✅ Global hotkey: Ctrl+Alt+Space  
echo ✅ Works in ANY Windows application
echo ✅ Instant text injection at cursor
echo ✅ AI enhancement via Ollama
echo ✅ System tray integration
echo ✅ Context-aware formatting
echo.
echo The application will run in the system tray.
echo Right-click the tray icon for options.
echo.

cd native
python enhanced_voiceflow_native.py

echo.
echo [SHUTDOWN] Enhanced VoiceFlow Native stopped
pause