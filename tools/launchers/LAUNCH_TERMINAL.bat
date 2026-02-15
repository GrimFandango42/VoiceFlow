@echo off
cd /d %~dp0\..\..
echo ==========================================
echo VoiceFlow - Terminal Mode
echo ==========================================
echo.
echo - Console-first launch path
echo - Uses voiceflow.py --no-tray
echo.
echo Press Ctrl+C to exit
echo.

set PYTHONPATH=src
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
"%PYTHON_EXE%" voiceflow.py --no-tray

pause
