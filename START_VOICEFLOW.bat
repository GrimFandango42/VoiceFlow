@echo off
cd /d C:\AI_Projects\VoiceFlow

echo ============================================
echo VoiceFlow Launcher
echo ============================================
echo.

:: Set up environment paths
set PATH=%USERPROFILE%\.cargo\bin;C:\home\nithin\.npm-global;%PATH%

:: Check if Python server is already running
tasklist /FI "IMAGENAME eq python.exe" 2>NUL | find /I /N "python.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo Python server already running
) else (
    echo Starting Python STT Server...
    start /B cmd /c "cd python && venv\Scripts\activate && python stt_server.py"
    timeout /t 3 /nobreak >nul
)

:: Start Tauri in dev mode
echo Starting VoiceFlow app...
echo.
tauri dev

:: If tauri not found, try npx
if %ERRORLEVEL% NEQ 0 (
    echo Trying with npx...
    npx @tauri-apps/cli dev
)

pause