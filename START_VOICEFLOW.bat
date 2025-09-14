@echo off
echo ==========================================
echo VoiceFlow - AI Voice Transcription System
echo ==========================================
echo.
echo Starting VoiceFlow with enhanced security and DeepSeek optimizations...
echo.

cd /d %~dp0
set PYTHONPATH=%cd%\src

echo [INFO] Environment configured
echo [INFO] Python path: %PYTHONPATH%
echo [INFO] Starting VoiceFlow Enhanced Tray Application...
echo.

python -c "import sys; sys.path.insert(0, 'src'); exec(open('src/voiceflow/ui/cli_enhanced.py').read())"

pause