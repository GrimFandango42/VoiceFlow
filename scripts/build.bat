@echo off
setlocal

cd /d C:\AI_Projects\VoiceFlow

:: Set up full environment
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
set PATH=C:\home\nithin\.npm-global;%PATH%

echo ================================================
echo Building VoiceFlow Executable
echo ================================================
echo.

:: Ensure frontend is built
echo [1/3] Building frontend...
call npm run build
if %errorlevel% neq 0 (
    echo Frontend build failed!
    pause
    exit /b 1
)

echo.
echo [2/3] Starting Tauri build (this may take several minutes)...
echo.

:: Use cargo directly if npx fails
where cargo >nul 2>&1
if %errorlevel% equ 0 (
    echo Using cargo to build...
    cd src-tauri
    cargo build --release
    cd ..
) else (
    echo Using npx tauri...
    call npx tauri build
)

echo.
echo [3/3] Checking build output...
echo.

:: Check for executable
if exist "src-tauri\target\release\voiceflow.exe" (
    echo ================================================
    echo BUILD SUCCESSFUL!
    echo ================================================
    echo.
    echo Executable location:
    echo   %CD%\src-tauri\target\release\voiceflow.exe
    echo.
    echo You can run it directly from there!
    echo.
    
    :: Create desktop shortcut
    echo Creating desktop shortcut...
    powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\VoiceFlow.lnk'); $Shortcut.TargetPath = '%CD%\src-tauri\target\release\voiceflow.exe'; $Shortcut.WorkingDirectory = '%CD%'; $Shortcut.Save()"
    echo Desktop shortcut created!
) else if exist "src-tauri\target\debug\voiceflow.exe" (
    echo ================================================
    echo DEBUG BUILD SUCCESSFUL!
    echo ================================================
    echo.
    echo Debug executable location:
    echo   %CD%\src-tauri\target\debug\voiceflow.exe
    echo.
    echo Note: This is a debug build (larger and slower)
    echo.
    
    :: Create desktop shortcut for debug
    echo Creating desktop shortcut...
    powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\VoiceFlow-Debug.lnk'); $Shortcut.TargetPath = '%CD%\src-tauri\target\debug\voiceflow.exe'; $Shortcut.WorkingDirectory = '%CD%'; $Shortcut.Save()"
    echo Desktop shortcut created!
) else (
    echo Build appears to be in progress or failed.
    echo Check src-tauri\target\ for build artifacts.
)

echo.
pause