@echo off
title VoiceFlow Launcher
cd /d "C:\AI_Projects\VoiceFlow\"

echo ========================================
echo Starting VoiceFlow...
echo ========================================

:: Start Python backend
echo [1/3] Starting backend server...
start /min cmd /c "python\venv\Scripts\python.exe python\stt_server.py"

:: Wait for server to start
echo [2/3] Waiting for server startup...
timeout /t 5 /nobreak >nul

:: Open frontend HTML file directly
echo [3/3] Opening VoiceFlow interface...
start voiceflow_frontend.html

echo.
echo ========================================
echo VoiceFlow is now running!
echo ========================================
echo.
echo Global Hotkey: Ctrl+Alt (anywhere)
echo Web Interface: voiceflow_frontend.html
echo.
echo Keep this window open while using VoiceFlow.
echo Close this window to stop the application.
echo.
pause

:: Cleanup when user closes
echo Stopping VoiceFlow...
taskkill /f /im python.exe 2>nul
echo VoiceFlow stopped.
