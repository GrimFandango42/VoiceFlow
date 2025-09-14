@echo off
setlocal

echo =================================================================
echo VoiceFlow Windows Setup Script
echo =================================================================
echo.

REM Check for Python
echo Checking for Python installation and version (minimum 3.8+)...
set MIN_PYTHON_MAJOR=3
set MIN_PYTHON_MINOR=8
set PYTHON_VERSION_MAJOR=0
set PYTHON_VERSION_MINOR=0

for /f "tokens=1,2 delims=." %%a in ('python --version 2^>^&1 ^| findstr /R /C:"Python [0-9][0-9]*\.[0-9][0-9]*"') do (
    for /f "tokens=2 delims= " %%v in ("%%a") do set PYTHON_VERSION_MAJOR=%%v
    set PYTHON_VERSION_MINOR=%%b
)

rem Clean up potential non-numeric parts from minor version (e.g., "10rc1" -> "10")
for /f "tokens=1 delims=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" %%N in ("%PYTHON_VERSION_MINOR%") do set PYTHON_VERSION_MINOR=%%N

if "%PYTHON_VERSION_MAJOR%"=="0" (
    echo [ERROR] Python not found in your PATH or its version is unreadable.
    echo Please install Python %MIN_PYTHON_MAJOR%.%MIN_PYTHON_MINOR% or higher and ensure it's added to your PATH.
    echo You can download Python from: https://www.python.org/downloads/
    goto :eof
)

set /a PYTHON_VERSION_MAJOR_NUM=PYTHON_VERSION_MAJOR
set /a PYTHON_VERSION_MINOR_NUM=PYTHON_VERSION_MINOR

if %PYTHON_VERSION_MAJOR_NUM% LSS %MIN_PYTHON_MAJOR% (
    call :python_version_too_low_err_msg
)
if %PYTHON_VERSION_MAJOR_NUM% EQU %MIN_PYTHON_MAJOR% (
    if %PYTHON_VERSION_MINOR_NUM% LSS %MIN_PYTHON_MINOR% (
        call :python_version_too_low_err_msg
    )
)

echo Python version %PYTHON_VERSION_MAJOR%.%PYTHON_VERSION_MINOR% found. Meets requirements.
python --version
echo.
goto :after_python_check_marker

:python_version_too_low_err_msg
echo [ERROR] Python version %PYTHON_VERSION_MAJOR%.%PYTHON_VERSION_MINOR% is installed.
echo VoiceFlow requires Python %MIN_PYTHON_MAJOR%.%MIN_PYTHON_MINOR% or higher.
echo Please upgrade your Python installation.
echo You can download Python from: https://www.python.org/downloads/
goto :eof

:after_python_check_marker
REM Marker to continue script execution after Python check

REM Virtual environment setup
set VENV_DIR=venv
if exist "%VENV_DIR%" (
    echo Virtual environment "%VENV_DIR%" already exists.
    set /p REUSE_VENV="Do you want to reuse it? (Y/N, default N): "
    if /i "%REUSE_VENV%" neq "Y" (
        echo Deleting existing virtual environment...
        rmdir /s /q "%VENV_DIR%"
        if errorlevel 1 (
            echo Failed to delete existing virtual environment. Please delete it manually.
            goto :eof
        )
        call :create_venv
    )
) else (
    call :create_venv
)
if errorlevel 1 goto :eof
echo.

REM Activate virtual environment and install
echo Activating virtual environment and installing VoiceFlow...
call "%VENV_DIR%\Scripts\activate.bat"

echo Installing VoiceFlow (core)...
pip install .
if errorlevel 1 (
    echo ERROR: Failed to install VoiceFlow.
    echo Please check the error messages above.
    goto :deactivate_and_exit
)
echo VoiceFlow core installed successfully.

REM Verify console entry points exist
set "ENTRY_OK=0"
for %%E in (voiceflow.exe voiceflow voiceflow-tray.exe voiceflow-tray) do (
    if exist "%VENV_DIR%\Scripts\%%E" (
        set "ENTRY_OK=1"
        goto :entry_found
    )
)
:entry_found
if "%ENTRY_OK%"=="0" (
    echo [WARNING] VoiceFlow console scripts not found in %VENV_DIR%\Scripts.
    echo You may need to ensure that setuptools installed scripts; try reinstalling with:
    echo     %VENV_DIR%\Scripts\pip install --force-reinstall .
    echo Continuing installer regardless.
) else (
    echo Verified VoiceFlow entry points.
)

echo.

set /p INSTALL_LITE="Do you want to install the Lite version dependencies? (Y/N, default N): "
if /i "%INSTALL_LITE%" equ "Y" (
    echo Installing VoiceFlow Lite specific dependencies...
    pip install .[lite]
    if errorlevel 1 (
        echo WARNING: Failed to install VoiceFlow Lite dependencies. Core version is still available.
    ) else (
        echo VoiceFlow Lite dependencies installed.
    )
)
echo.

set /p INSTALL_ADVANCED="Do you want to install Advanced features (e.g., RealtimeSTT)? (Y/N, default N): "
if /i "%INSTALL_ADVANCED%" equ "Y" (
    echo Installing VoiceFlow Advanced feature dependencies...
    pip install .[advanced]
    if errorlevel 1 (
        echo WARNING: Failed to install VoiceFlow Advanced dependencies.
    ) else (
        echo VoiceFlow Advanced dependencies installed.
    )
)
echo.

REM --- Create Run Script for System Tray App & Desktop Shortcut ---
echo.
echo Creating helper script (run_voiceflow_tray.bat) for the System Tray App...
(
    echo @echo off
    echo setlocal
    echo echo Activating VoiceFlow virtual environment...
    echo call "%~dp0%VENV_DIR%\Scripts\activate.bat"
    echo.
    echo echo Starting VoiceFlow System Tray Application...
    echo echo If it doesn't start, ensure '%VENV_DIR%\Scripts' is in your PATH after activation,
    echo echo or try: python -m voiceflow.tray_app
    echo voiceflow-tray
    echo.
    echo if errorlevel 1 (
    echo   echo VoiceFlow Tray exited with an error.
    echo   pause
    echo )
    echo call "%~dp0%VENV_DIR%\Scripts\deactivate.bat"
    echo endlocal
) ^> "run_voiceflow_tray.bat"

if %errorlevel% neq 0 (
    echo [WARNING] Failed to create run_voiceflow_tray.bat. You can still run manually as per instructions.
) else (
    echo run_voiceflow_tray.bat created successfully.
    echo You can use this script to easily start the VoiceFlow tray application.
    echo.
    set /p CREATE_SHORTCUT="Do you want to create a desktop shortcut for VoiceFlow Tray? (Y/N, default Y): "
    if /i not "%CREATE_SHORTCUT%" == "N" (
        echo Creating desktop shortcut...
        powershell -ExecutionPolicy Bypass -NoProfile -Command "try { $ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([IO.Path]::Combine($env:USERPROFILE, 'Desktop', 'VoiceFlow Tray.lnk')); $s.TargetPath = [IO.Path]::Combine($pwd.ProviderPath, 'run_voiceflow_tray.bat'); $s.WorkingDirectory = $pwd.ProviderPath; $s.IconLocation = 'shell32.dll,3'; $s.Save(); Write-Host 'Desktop shortcut created.' } catch { Write-Warning 'Failed to create desktop shortcut.'; exit 1 }"
        if %errorlevel% neq 0 (
            echo [WARNING] Failed to create desktop shortcut.
            echo You may need to enable PowerShell script execution or create it manually.
            echo Target: %CD%\run_voiceflow_tray.bat
        )
    )
)
echo.

echo =================================================================
echo Setup Complete!
echo =================================================================
echo.
echo To run VoiceFlow:
echo 1. Open a new command prompt or activate the venv: %CD%\%VENV_DIR%\Scripts\activate.bat
echo 2. Then run one of the following commands:
echo    - For the system tray application (recommended on Windows): voiceflow-tray
echo    - For the standard command-line version: voiceflow
echo    - For the lite command-line version:     voiceflow-lite
echo    - For the debug command-line version:    voiceflow-debug
echo.
echo To install development tools (for contributing):
echo    pip install .[dev]
echo.

goto :deactivate_and_exit

:create_venv
echo Creating virtual environment in "%VENV_DIR%"...
python -m venv "%VENV_DIR%"
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment.
    exit /b 1
)
echo Virtual environment created.

:: Upgrade pip inside the newly-created venv to ensure modern packaging features
"%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel >nul 2>&1
if errorlevel 1 (
    echo WARNING: Failed to upgrade pip. Continuing with default version.
) else (
    echo Pip and build tools upgraded to latest versions.
)
exit /b 0

:deactivate_and_exit
if defined VIRTUAL_ENV (
    echo Deactivating virtual environment for this script session...
    call deactivate >nul 2>&1
)
endlocal
pause