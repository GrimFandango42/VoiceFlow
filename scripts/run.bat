@echo off
cd /d C:\AI_Projects\VoiceFlow

echo ================================================
echo VoiceFlow Launcher
echo ================================================
echo.

if exist "src-tauri\target\release\voiceflow.exe" (
    echo Starting VoiceFlow (Release)...
    start "" "src-tauri\target\release\voiceflow.exe"
) else if exist "src-tauri\target\debug\voiceflow.exe" (
    echo Starting VoiceFlow (Debug)...
    start "" "src-tauri\target\debug\voiceflow.exe"
) else (
    echo No executable found!
    echo.
    echo Please run FINAL_BUILD.bat first.
    echo.
    pause
)