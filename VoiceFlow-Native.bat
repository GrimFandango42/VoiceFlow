@echo off
title VoiceFlow - Native Mode
cd /d "C:\AI_Projects\VoiceFlow\"

echo ========================================
echo VoiceFlow - Native Wispr Flow Mode
echo ========================================
echo.
echo Starting invisible background service...
echo.

:: Start only the Python backend (no web interface)
start /min cmd /c "python\venv\Scripts\python.exe python\stt_server.py"

echo ✅ VoiceFlow is now running invisibly!
echo.
echo 🎯 HOW TO USE:
echo    • Press Ctrl+Alt anywhere to record
echo    • Speak your text 
echo    • Press Ctrl+Alt again to stop
echo    • Text appears at cursor automatically!
echo.
echo 🔧 Works in: Word, Email, Chat, Browser, ANY text field
echo 📍 No windows, no interfaces - just like Whispr Flow!
echo.
echo ⚠️  Keep this window open while using VoiceFlow
echo    Close this window to stop the service
echo.
pause

:: Cleanup when closed
echo.
echo Stopping VoiceFlow service...
taskkill /f /im python.exe 2>nul
echo VoiceFlow stopped.
pause
