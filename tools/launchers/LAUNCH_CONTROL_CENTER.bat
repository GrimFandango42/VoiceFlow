@echo off
cd /d %~dp0\..\..

echo ==========================================
echo VoiceFlow Control Center
echo ==========================================
echo.
echo Starting unified VoiceFlow launcher...
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Please install Python 3.9+ first.
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Launch Control Center
python tools\VoiceFlow_Control_Center.py

REM If we get here, the program exited
echo.
echo VoiceFlow Control Center has closed.
pause