@echo off
echo ========================================
echo VoiceFlow - Manual Testing Mode
echo ========================================
echo.
echo This runs VoiceFlow server with visible console for testing
echo.

cd /d "C:\AI_Projects\VoiceFlow"

echo Starting VoiceFlow STT server with visible output...
echo.
echo INSTRUCTIONS:
echo 1. Server will start and show status messages
echo 2. Press Ctrl+Alt anywhere to trigger voice recording
echo 3. Speak your text clearly
echo 4. Text should appear at cursor position
echo 5. Press Ctrl+C to stop when done testing
echo.
echo ==========================================

python\venv\Scripts\python.exe python\stt_server_patched.py

pause
