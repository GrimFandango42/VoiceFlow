@echo off
:: VoiceFlow from source — matches the production VoiceFlow.bat exactly
cd /d "%~dp0"

:: Clean stale runtimes
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup\stop_voiceflow_processes.ps1" -Quiet >nul 2>&1
timeout /t 1 /nobreak >nul

set "PYTHON_EXE=%cd%\.venv-gpu\Scripts\python.exe"

echo.
echo ========================================
echo   VoiceFlow 3.0 - Running from Source
echo ========================================
echo   Hotkey: Ctrl+Shift (hold to record)
echo   Runtime: %PYTHON_EXE%
echo ========================================
echo.

:: Change to src directory and run — identical to VoiceFlow.bat
cd src
"%PYTHON_EXE%" -m voiceflow.ui.cli_enhanced
cd ..

if "%1"=="" pause
