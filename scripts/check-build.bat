@echo off
cd /d C:\AI_Projects\VoiceFlow

echo Checking build status...
echo.

if exist "src-tauri\target\release\voiceflow.exe" (
    echo ✓ RELEASE BUILD FOUND!
    echo   Location: %CD%\src-tauri\target\release\voiceflow.exe
    dir "src-tauri\target\release\voiceflow.exe" | findstr voiceflow
) else if exist "src-tauri\target\debug\voiceflow.exe" (
    echo ✓ DEBUG BUILD FOUND!
    echo   Location: %CD%\src-tauri\target\debug\voiceflow.exe
    dir "src-tauri\target\debug\voiceflow.exe" | findstr voiceflow
) else (
    echo ⏳ No executable found yet. Build may still be in progress.
    echo.
    echo Checking for build artifacts...
    if exist "src-tauri\target\debug\deps" (
        echo Build process has started - dependencies being compiled.
    )
)

echo.
pause