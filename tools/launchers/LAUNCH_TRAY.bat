@echo off
cd /d %~dp0\..\..
echo ==========================================
echo VoiceFlow - Tray Mode (With Visuals)
echo ==========================================
echo.
echo Features:
echo - System tray icon with status colors
echo - Bottom-screen overlay (like Wispr Flow)
echo - Visual feedback for all transcription states
echo - Background operation (can close terminal)
echo.
echo Press Ctrl+C to exit or close from tray menu
echo.

set PYTHONPATH=%cd%\src
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
"%PYTHON_EXE%" -c "import sys; sys.path.insert(0, 'src'); exec(open('src/voiceflow/ui/cli_enhanced.py').read())"

pause
