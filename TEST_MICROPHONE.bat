@echo off
echo ========================================
echo VoiceFlow Microphone and Speech Test
echo ========================================
echo.
echo This will test your microphone and speech recognition
echo Follow the prompts carefully
echo.
pause

cd /d "C:\AI_Projects\VoiceFlow"

python\venv\Scripts\python.exe simple_mic_test.py

pause
