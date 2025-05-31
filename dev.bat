@echo off
echo ============================================
echo VoiceFlow Development Mode
echo ============================================
echo.

echo Starting Python STT Server in background...
start /B cmd /c "cd python && venv\Scripts\activate && python stt_server.py"

echo Waiting for STT server to start...
timeout /t 3 /nobreak > nul

echo.
echo Starting Tauri development server...
npm run tauri dev

echo.
echo ============================================
echo Shutting down...
echo ============================================
taskkill /F /IM python.exe > nul 2>&1
pause