@echo off
REM VoiceFlow Windows Installer
REM Automated installation and setup for Windows

echo =====================================
echo VoiceFlow Windows Installer
echo =====================================
echo.

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

echo [INFO] Python found
python --version

REM Check pip
pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip not found. Please install pip
    pause
    exit /b 1
)

echo [INFO] Installing VoiceFlow dependencies...
pip install -r requirements_windows.txt

if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [SUCCESS] VoiceFlow installed successfully!
echo.
echo Quick Start:
echo   Console Mode: python voiceflow_windows.py --console
echo   Tray Mode:    python voiceflow_windows.py --tray
echo.
echo Creating desktop shortcuts...

REM Create desktop shortcut for tray mode
echo Set oWS = WScript.CreateObject("WScript.Shell") > create_shortcut.vbs
echo sLinkFile = "%USERPROFILE%\Desktop\VoiceFlow.lnk" >> create_shortcut.vbs
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> create_shortcut.vbs
echo oLink.TargetPath = "python" >> create_shortcut.vbs
echo oLink.Arguments = "%cd%\voiceflow_windows.py --tray" >> create_shortcut.vbs
echo oLink.WorkingDirectory = "%cd%" >> create_shortcut.vbs
echo oLink.Description = "VoiceFlow - Local Voice Transcription" >> create_shortcut.vbs
echo oLink.Save >> create_shortcut.vbs

cscript create_shortcut.vbs >nul 2>&1
del create_shortcut.vbs >nul 2>&1

echo [INFO] Desktop shortcut created
echo.
echo Installation complete! Run VoiceFlow from:
echo   1. Desktop shortcut (VoiceFlow.lnk)
echo   2. Command: python voiceflow_windows.py
echo.
pause