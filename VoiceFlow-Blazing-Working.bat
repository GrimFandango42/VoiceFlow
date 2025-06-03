@echo off
echo.
echo ========================================
echo    🚀 VoiceFlow - BLAZING FAST (WORKING)
echo    Based on confirmed working code
echo ========================================
echo.

cd /d "%~dp0"

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