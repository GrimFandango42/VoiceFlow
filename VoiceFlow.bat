@echo off
:: VoiceFlow 3.0 Launcher
:: Can be pinned to taskbar or placed on desktop

cd /d "%~dp0"

:: Clean stale VoiceFlow runtimes before relaunching.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup\stop_voiceflow_processes.ps1" -Quiet >nul 2>&1
timeout /t 1 /nobreak >nul

:: Python runtime selection:
:: 1) .venv-gpu (preferred for CUDA retest)
:: 2) venv
:: 3) system python
set "PYTHON_EXE=python"
if /I not "%VOICEFLOW_USE_GPU_VENV%"=="0" (
    if exist ".venv-gpu\Scripts\python.exe" (
        set "PYTHON_EXE=%cd%\.venv-gpu\Scripts\python.exe"
    ) else if exist "venv\Scripts\python.exe" (
        set "PYTHON_EXE=%cd%\venv\Scripts\python.exe"
    )
) else (
    if exist "venv\Scripts\python.exe" (
        set "PYTHON_EXE=%cd%\venv\Scripts\python.exe"
    )
)

:: Launch VoiceFlow
echo.
echo ========================================
echo   VoiceFlow 3.0 - Starting...
echo ========================================
echo.
echo   Hotkey: Ctrl+Shift (hold to record)
echo   Model: Distil-Whisper Large v3
echo   Features: Cold start elimination,
echo             Streaming preview,
echo             AI enhancement
echo   Runtime: %PYTHON_EXE%
echo.
echo ========================================
echo.

:: Launch via _app_entry.py to avoid false-positive duplicate-instance detection.
:: Launching with -m voiceflow.ui.cli_enhanced puts that string in the process cmdline,
:: which confuses the single-instance guard when py.exe spawns a real-python child.
"%PYTHON_EXE%" _app_entry.py

:: If launched by double-click, pause on exit
if "%1"=="" pause
