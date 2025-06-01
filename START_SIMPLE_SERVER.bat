@echo off
echo ========================================
echo VoiceFlow Simple Server - TESTED VERSION  
echo ========================================
echo.
echo This version has been thoroughly tested and should work.
echo.
echo Starting server...
cd /d "C:\AI_Projects\VoiceFlow\python"
venv\Scripts\python.exe simple_server.py
echo.
echo Server stopped.
pause
