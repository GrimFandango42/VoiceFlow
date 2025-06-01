@echo off
title VoiceFlow Launcher
cd /d "C:\AI_Projects\VoiceFlow\"

echo Starting VoiceFlow...

:: Start Python backend
start /min cmd /c "python\venv\Scripts\python.exe python\stt_server.py"

:: Wait for server to start
timeout /t 3 /nobreak >nul

:: Open frontend in browser
start http://localhost:8765

:: Keep window open
echo VoiceFlow is running. Close this window to stop.
pause >nul

:: Cleanup
taskkill /f /im python.exe 2>nul
