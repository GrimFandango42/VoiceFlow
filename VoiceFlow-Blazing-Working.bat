@echo off
echo.
echo ========================================
echo    🚀 VoiceFlow - BLAZING FAST (WORKING)
echo    Based on confirmed working code
echo ========================================
echo.

cd /d "%~dp0"

REM Check for existing VoiceFlow processes
tasklist /FI "WINDOWTITLE eq VoiceFlow*" 2>nul | find /I "python.exe" >nul
if not errorlevel 1 (
    echo ⚠️  VoiceFlow is already running!
    echo.
    echo Choose an option:
    echo 1. Kill existing and start new
    echo 2. Exit without starting
    echo.
    choice /C 12 /N /M "Select (1 or 2): "
    if errorlevel 2 exit /b 0
    echo.
    echo Stopping existing VoiceFlow...
    call kill_voiceflow.bat
)

echo 🔧 Starting Blazing Fast VoiceFlow...
echo 📝 This version uses the EXACT working code
echo    with speed optimizations
echo.

REM Use silent version to prevent focus stealing
python python\blazing_fast_silent.py

if errorlevel 1 (
    echo.
    echo ❌ Error running VoiceFlow!
    echo.
    echo Try these fixes:
    echo 1. pip install -r python\requirements.txt
    echo 2. Run as Administrator
    echo 3. Check Windows Defender/Antivirus
    echo.
    pause
)