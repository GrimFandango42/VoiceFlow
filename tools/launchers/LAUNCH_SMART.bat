@echo off
cd /d %~dp0
echo ==========================================
echo VoiceFlow - Smart Launch System
echo ==========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Please install Python 3.9+ first.
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [OK] Python detected
echo.

REM Check dependencies and offer to install if missing
echo Checking system requirements...
python setup_voiceflow.py --no-install
if errorlevel 1 (
    echo.
    echo [WARNING] Some dependencies are missing.
    choice /C YN /M "Would you like to install missing dependencies now? (Y/N)"
    if !errorlevel!==1 (
        echo.
        echo Installing dependencies...
        python setup_voiceflow.py
        if errorlevel 1 (
            echo.
            echo [ERROR] Dependency installation failed!
            pause
            exit /b 1
        )
    ) else (
        echo.
        echo [WARNING] Launching with missing dependencies - some features may not work.
        timeout /t 3 /nobreak >nul
    )
)

echo.
echo ==========================================
echo Launching VoiceFlow (Visual Mode)
echo ==========================================
echo.
echo Features:
echo - System tray icon with status colors
echo - Bottom-screen overlay (Wispr Flow-style)
echo - Visual feedback for transcription states
echo - Configurable overlay positioning
echo - Background operation (can close terminal)
echo.
echo Press Ctrl+C to exit or close from tray menu
echo.

REM Launch VoiceFlow
python -m localflow.cli_enhanced

REM If we get here, the program exited
echo.
echo VoiceFlow has closed.
pause