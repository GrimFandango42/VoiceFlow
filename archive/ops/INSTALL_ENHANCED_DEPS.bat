@echo off
title Enhanced VoiceFlow - Dependency Installation
echo.
echo ================================================================
echo              Enhanced VoiceFlow - Dependency Installation
echo                    Installing All Required Packages
echo ================================================================
echo.

cd /d "%~dp0"

echo [CHECK] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Please install Python 3.8+ first.
    echo [INFO] Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

python --version
echo [OK] Python found

echo.
echo [SETUP] Creating Python virtual environment...
if not exist "python" mkdir python
cd python

if exist "venv" (
    echo [INFO] Virtual environment already exists, updating...
) else (
    echo [INFO] Creating new virtual environment...
    python -m venv venv
)

echo [SETUP] Activating virtual environment...
call venv\Scripts\activate.bat

echo.
echo [INSTALL] Installing core dependencies...
pip install --upgrade pip setuptools wheel

echo [INSTALL] Installing speech processing packages...
pip install RealtimeSTT>=0.1.16
pip install faster-whisper>=0.10.0
pip install torch torchaudio --index-url https://download.pytorch.org/whl/cu118

echo [INSTALL] Installing Windows integration packages...
pip install keyboard>=0.13.5
pip install pyautogui>=0.9.54
pip install pywin32>=306
pip install pystray>=0.19.4
pip install pillow>=9.5.0

echo [INSTALL] Installing audio and AI packages...
pip install pyaudio>=0.2.11
pip install requests>=2.31.0
pip install websockets>=11.0
pip install numpy>=1.24.0

echo [INSTALL] Installing additional utilities...
pip install aiosqlite>=0.19.0
pip install colorama>=0.4.6
pip install python-dotenv>=1.0.0

echo.
echo [VERIFY] Verifying installation...
python -c "
import RealtimeSTT
import keyboard
import pyautogui
import win32api
import pystray
import PIL
import requests
import websockets
import numpy
print('✅ All core packages imported successfully')
"

if errorlevel 1 (
    echo [ERROR] Package verification failed!
    echo [INFO] Some packages may need manual installation
    pause
    exit /b 1
)

echo.
echo [TEST] Testing GPU availability...
python -c "
import torch
if torch.cuda.is_available():
    print(f'✅ CUDA available: {torch.cuda.get_device_name(0)}')
    print(f'   CUDA version: {torch.version.cuda}')
else:
    print('⚠️ CUDA not available - will use CPU mode')
"

echo.
echo [SUCCESS] Enhanced VoiceFlow dependencies installed successfully!
echo.
echo ================================================================
echo                         INSTALLATION COMPLETE
echo ================================================================
echo.
echo You can now run Enhanced VoiceFlow using:
echo.
echo   • VoiceFlow-Enhanced.bat           (Console mode)
echo   • VoiceFlow-Enhanced-Native.bat    (System tray mode)
echo   • VoiceFlow-Enhanced-Invisible.bat (Invisible mode)
echo.
echo FEATURES READY:
echo   ✅ Global hotkey: Ctrl+Alt+Space
echo   ✅ Works in any Windows application  
echo   ✅ Instant text injection
echo   ✅ AI enhancement via Ollama
echo   ✅ GPU acceleration (if CUDA available)
echo   ✅ Context-aware formatting
echo   ✅ System tray integration
echo.
echo NEXT STEPS:
echo   1. Ensure Ollama is running for AI enhancement
echo   2. Run one of the launcher scripts above
echo   3. Press Ctrl+Alt+Space anywhere to test
echo.
echo ================================================================

cd ..
pause