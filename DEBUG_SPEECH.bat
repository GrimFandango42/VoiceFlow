@echo off
echo ========================================
echo VoiceFlow Speech Pipeline Debugger
echo ========================================
echo.
echo This will test each component of VoiceFlow to find the issue:
echo - Microphone access
echo - Speech recognition engine
echo - Text injection system
echo - Global hotkey detection
echo - AI enhancement (Ollama)
echo.
echo Please follow the prompts and report what fails.
echo.
pause

cd /d "C:\AI_Projects\VoiceFlow"

python\venv\Scripts\python.exe debug_speech_pipeline.py

pause
