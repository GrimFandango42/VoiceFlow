@echo off
echo ================================================================
echo                     VoiceFlow Simple - READY TO TEST
echo ================================================================
echo.
echo All dependencies verified and ready!
echo.
echo Choose your launch mode:
echo.
echo [1] System Tray Mode (Invisible - Recommended)
echo     Runs invisibly in system tray like Wispr Flow
echo.
echo [2] Console Mode (Visible logging)
echo     Shows real-time status and logging
echo.
choice /c 12 /m "Select mode (1 or 2): "

if errorlevel 2 goto console
if errorlevel 1 goto tray

:tray
echo.
echo Starting VoiceFlow in System Tray mode...
echo Look for the VoiceFlow icon in your system tray!
echo.
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "VoiceFlow-Tray-Simple.ps1"
goto end

:console
echo.
echo Starting VoiceFlow in Console mode...
echo.
call "VoiceFlow-Simple.bat"
goto end

:end
echo.
echo VoiceFlow session ended.
pause