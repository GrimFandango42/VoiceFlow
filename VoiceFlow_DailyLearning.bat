@echo off
:: VoiceFlow Daily Learning Batch Job
:: Processes prior-day transcription/correction data and updates adaptive patterns.

cd /d "%~dp0"

:: Python runtime selection:
:: 1) .venv-gpu (preferred)
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

cd src
"%PYTHON_EXE%" -m voiceflow.ai.daily_learning --days-back 1 %*

