@echo off
setlocal

REM Simple launcher for LocalFlow MVP
REM - Creates/uses .\venv
REM - Installs requirements
REM - Runs the app

cd /d %~dp0

IF NOT EXIST venv (
  echo Creating virtual environment...
  py -3 -m venv venv || goto :error
)

call venv\Scripts\activate.bat || goto :error
python -m pip install --upgrade pip || goto :error
python -m pip install -r requirements-localflow.txt || goto :error

echo.
echo ======================
echo  LocalFlow is starting
echo  Hold Ctrl+Shift+Space to dictate
echo  Toggles: Ctrl+Alt+C (code mode), Ctrl+Alt+P (paste/type), Ctrl+Alt+Enter (send Enter)
echo  Change PTT hotkey from tray (PTT Hotkey menu)
echo ======================
echo.

python -m localflow.cli
goto :eof

:error
echo Failed during setup or launch.
exit /b 1
