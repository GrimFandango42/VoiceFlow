@echo off
setlocal

REM High-performance tray launcher for VoiceFlow
REM - No terminal window
REM - Runs in background
REM - Optimized for speed

cd /d %~dp0

IF NOT EXIST venv (
  echo Creating virtual environment...
  py -3 -m venv venv || goto :error
)

call venv\Scripts\activate.bat || goto :error
python -m pip install --upgrade pip >nul 2>&1
python -m pip install -r requirements-localflow.txt >nul 2>&1

REM Launch in tray mode with no console output
start /min "" python -m localflow.cli >nul 2>&1
echo VoiceFlow started in tray mode (Ctrl+Shift to dictate)
goto :eof

:error
echo Failed during setup or launch.
exit /b 1