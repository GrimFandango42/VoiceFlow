@echo off
:: VoiceFlow 3.0 Launcher
:: Can be pinned to taskbar or placed on desktop

cd /d "%~dp0"

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

:: Change to src directory and run
cd src
"%PYTHON_EXE%" -m voiceflow.ui.cli_enhanced
cd ..

:: If launched by double-click, pause on exit
if "%1"=="" pause
