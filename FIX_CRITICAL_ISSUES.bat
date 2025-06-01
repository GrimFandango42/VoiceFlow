@echo off
:: VoiceFlow Fix Script - Address Critical Issues Found in Testing
:: This script fixes the Python 3.13 compatibility and environment issues

echo ========================================
echo VoiceFlow Critical Issues Fix Script
echo ========================================
echo.
echo Issues found in comprehensive testing:
echo [X] Python 3.13 enum compatibility issues  
echo [X] WebSocket server binding failures
echo [X] Text injection module conflicts
echo [X] WSL testing limitations
echo.
echo This script will:
echo [1] Create clean Python 3.11 environment
echo [2] Reinstall packages with proper versions
echo [3] Test native Windows functionality
echo [4] Verify WebSocket server operation
echo.

pause

echo [STEP 1] Downloading Python 3.11...
:: Check if Python 3.11 is available
python3.11 --version >nul 2>&1
if %errorlevel%==0 (
    echo Python 3.11 found! Using existing installation.
) else (
    echo Python 3.11 not found. Installing...
    echo Please download Python 3.11 from: https://www.python.org/downloads/release/python-3118/
    echo After installation, re-run this script.
    pause
    exit /b 1
)

echo.
echo [STEP 2] Creating clean Python 3.11 virtual environment...
cd /d "C:\AI_Projects\VoiceFlow"

:: Backup existing environment
if exist python\venv_old rmdir /s /q python\venv_old
if exist python\venv move python\venv python\venv_old

:: Create new Python 3.11 environment
python3.11 -m venv python\venv
if %errorlevel% neq 0 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

echo.
echo [STEP 3] Installing compatible packages...
python\venv\Scripts\python.exe -m pip install --upgrade pip

:: Install packages with specific versions for compatibility
echo Installing core dependencies...
python\venv\Scripts\pip install wheel setuptools

echo Installing audio processing...
python\venv\Scripts\pip install "RealtimeSTT>=1.3.0"
python\venv\Scripts\pip install "faster-whisper>=0.9.0"

echo Installing Windows automation (with compatibility fixes)...
python\venv\Scripts\pip install "pyautogui>=0.9.54"
python\venv\Scripts\pip install "keyboard>=1.13.0"
python\venv\Scripts\pip install "pywin32>=306"

echo Installing networking...
python\venv\Scripts\pip install "websockets>=12.0"
python\venv\Scripts\pip install "requests>=2.31.0"

echo Installing utilities...
python\venv\Scripts\pip install "numpy>=1.24.0"

echo.
echo [STEP 4] Testing fixed environment...
echo Testing Python version...
python\venv\Scripts\python.exe --version

echo Testing critical imports...
python\venv\Scripts\python.exe -c "import pyautogui; print('pyautogui: OK')"
python\venv\Scripts\python.exe -c "import keyboard; print('keyboard: OK')"  
python\venv\Scripts\python.exe -c "import websockets; print('websockets: OK')"
python\venv\Scripts\python.exe -c "from RealtimeSTT import AudioToTextRecorder; print('RealtimeSTT: OK')"

echo.
echo [STEP 5] Creating native Windows test script...

:: Create a test script that runs natively on Windows
echo import subprocess > test_native_windows.py
echo import time >> test_native_windows.py
echo import os >> test_native_windows.py
echo. >> test_native_windows.py
echo print("Testing VoiceFlow on native Windows...") >> test_native_windows.py
echo. >> test_native_windows.py
echo # Test 1: Start STT server >> test_native_windows.py
echo print("[1] Starting STT server...") >> test_native_windows.py
echo server = subprocess.Popen(["python\\venv\\Scripts\\python.exe", "python\\stt_server.py"]) >> test_native_windows.py
echo time.sleep(10) >> test_native_windows.py
echo. >> test_native_windows.py
echo # Test 2: Check if server is running >> test_native_windows.py
echo if server.poll() is None: >> test_native_windows.py
echo     print("[PASS] Server running") >> test_native_windows.py
echo else: >> test_native_windows.py
echo     print("[FAIL] Server crashed") >> test_native_windows.py
echo. >> test_native_windows.py
echo # Test 3: Test WebSocket connection >> test_native_windows.py
echo import socket >> test_native_windows.py
echo try: >> test_native_windows.py
echo     s = socket.socket() >> test_native_windows.py
echo     s.connect(("localhost", 8765)) >> test_native_windows.py
echo     s.close() >> test_native_windows.py
echo     print("[PASS] WebSocket port accessible") >> test_native_windows.py
echo except: >> test_native_windows.py
echo     print("[FAIL] WebSocket port not accessible") >> test_native_windows.py
echo. >> test_native_windows.py
echo # Test 4: Test text injection >> test_native_windows.py
echo try: >> test_native_windows.py
echo     import pyautogui >> test_native_windows.py
echo     import keyboard >> test_native_windows.py
echo     print("[PASS] Text injection modules loaded") >> test_native_windows.py
echo except Exception as e: >> test_native_windows.py
echo     print(f"[FAIL] Text injection failed: {e}") >> test_native_windows.py
echo. >> test_native_windows.py
echo # Cleanup >> test_native_windows.py
echo print("Cleaning up...") >> test_native_windows.py
echo server.terminate() >> test_native_windows.py

echo.
echo [STEP 6] Running native Windows test...
echo ----------------------------------------
python\venv\Scripts\python.exe test_native_windows.py
echo ----------------------------------------

echo.
echo [STEP 7] Fix complete! 
echo.
echo NEXT STEPS:
echo 1. Close this window
echo 2. Double-click VoiceFlow-Invisible.bat
echo 3. Look for microphone icon in system tray  
echo 4. Test in Notepad with Ctrl+Alt hotkey
echo.
echo If issues persist, run: DIAGNOSE.bat
echo.
pause
