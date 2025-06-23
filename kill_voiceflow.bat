@echo off
echo.
echo 🛑 Stopping all VoiceFlow processes...
echo.

REM Kill Python processes running VoiceFlow scripts
taskkill /F /IM python.exe /FI "WINDOWTITLE eq VoiceFlow*" 2>nul
taskkill /F /IM pythonw.exe /FI "WINDOWTITLE eq VoiceFlow*" 2>nul

REM Kill by common script names
wmic process where "CommandLine like '%%simple_server.py%%'" delete 2>nul
wmic process where "CommandLine like '%%stt_server.py%%'" delete 2>nul
wmic process where "CommandLine like '%%blazing_fast%%'" delete 2>nul
wmic process where "CommandLine like '%%voiceflow%%'" delete 2>nul

echo ✅ Cleanup complete
echo.
pause