@echo off
echo ================================================================
echo VoiceFlow BufferSafe System - PRODUCTION READY
echo ================================================================
echo.
echo This is the NEW system with:
echo - VAD completely DISABLED (no audio filtering)  
echo - Complete buffer isolation between recordings
echo - Enhanced thread management for long conversations
echo - Model reinitialization every 5 transcriptions
echo.
echo ================================================================

cd /d "%~dp0"

REM Kill any existing Python processes
taskkill /F /IM python.exe >NUL 2>&1

echo Starting BufferSafe VoiceFlow...
echo.

python -m localflow.cli_enhanced --no-tray

pause