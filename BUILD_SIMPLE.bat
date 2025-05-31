@echo off
setlocal

echo ================================================
echo Direct Tauri Build
echo ================================================
echo.

cd /d C:\AI_Projects\VoiceFlow

:: Set Rust path
set PATH=%USERPROFILE%\.cargo\bin;%PATH%

:: First, ensure npm packages are installed
echo Installing dependencies...
call npm install
echo.

:: Build frontend
echo Building frontend...
call npm run build
echo.

:: Now use npx to run tauri with the correct path
echo Building Tauri app...
set PATH=%cd%\node_modules\.bin;%PATH%
npx tauri build

echo.
echo Build complete. Checking for output...
echo.

:: Check multiple possible locations
if exist "src-tauri\target\release\VoiceFlow.exe" (
    echo Found: src-tauri\target\release\VoiceFlow.exe
    dir "src-tauri\target\release\VoiceFlow.exe"
) else if exist "src-tauri\target\release\voiceflow.exe" (
    echo Found: src-tauri\target\release\voiceflow.exe
    dir "src-tauri\target\release\voiceflow.exe"
) else if exist "src-tauri\target\debug\VoiceFlow.exe" (
    echo Found: src-tauri\target\debug\VoiceFlow.exe (Debug build)
    dir "src-tauri\target\debug\VoiceFlow.exe"
) else if exist "src-tauri\target\debug\voiceflow.exe" (
    echo Found: src-tauri\target\debug\voiceflow.exe (Debug build)
    dir "src-tauri\target\debug\voiceflow.exe"
) else (
    echo No executable found. Checking entire release directory...
    dir "src-tauri\target\release\*.exe" 2>nul
    echo.
    echo Checking debug directory...
    dir "src-tauri\target\debug\*.exe" 2>nul
)

pause