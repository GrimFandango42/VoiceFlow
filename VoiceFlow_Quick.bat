@echo off
:: VoiceFlow 3.0 Quick Launcher (no pause on exit)
:: Use this for taskbar pinning

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

:: Change to src directory and run
cd src
"%PYTHON_EXE%" -m voiceflow.ui.cli_enhanced
