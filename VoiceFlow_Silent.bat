@echo off
:: VoiceFlow 3.0 - Silent Mode (minimized to tray)
:: Console hidden, runs in background. Check tray icon for status.
:: Debug logs: %LOCALAPPDATA%\LocalFlow\logs\voiceflow_silent.log

cd /d "%~dp0"

set "PYTHONW_EXE="
if /I not "%VOICEFLOW_USE_GPU_VENV%"=="0" if exist ".venv-gpu\Scripts\pythonw.exe" (
    set "PYTHONW_EXE=%cd%\.venv-gpu\Scripts\pythonw.exe"
)
if "%PYTHONW_EXE%"=="" if exist "venv\Scripts\pythonw.exe" (
    set "PYTHONW_EXE=%cd%\venv\Scripts\pythonw.exe"
)

if "%PYTHONW_EXE%"=="" (
    set "PYTHONW_EXE=pyw"
)

set "SCRIPT=%cd%\src\voiceflow\ui\launcher_silent.pyw"
if not exist "%SCRIPT%" (
    echo ERROR: launcher script missing: %SCRIPT%
    exit /b 1
)

powershell -NoProfile -WindowStyle Hidden -Command "Start-Process -FilePath '%PYTHONW_EXE%' -ArgumentList '\"%SCRIPT%\"' -WorkingDirectory '%cd%\src' -WindowStyle Hidden"
