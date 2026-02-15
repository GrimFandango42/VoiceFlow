@echo off
setlocal
cd /d %~dp0\..\..

echo ==========================================
echo VoiceFlow - Smart Launch
echo ==========================================
echo.

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

"%PYTHON_EXE%" --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.9+ and retry.
    pause
    exit /b 1
)

echo [INFO] Running setup validation...
"%PYTHON_EXE%" scripts\setup\setup_voiceflow.py --no-install
if errorlevel 1 (
    echo.
    echo [WARNING] Setup validation reported missing dependencies.
    choice /C YN /M "Install missing dependencies now? (Y/N)"
    if errorlevel 2 (
        echo [WARNING] Continuing without installing missing dependencies.
    ) else (
        "%PYTHON_EXE%" scripts\setup\setup_voiceflow.py
        if errorlevel 1 (
            echo [ERROR] Dependency installation failed.
            pause
            exit /b 1
        )
    )
)

echo.
echo [INFO] Launching VoiceFlow Quick...
call VoiceFlow_Quick.bat
