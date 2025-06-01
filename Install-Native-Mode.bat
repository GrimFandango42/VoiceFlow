@echo off
title VoiceFlow - Install Native System Integration
cd /d "C:\AI_Projects\VoiceFlow\"

echo ========================================
echo VoiceFlow - Native System Integration
echo ========================================
echo.
echo Installing dependencies for native mode...
echo (Global hotkeys + text injection)
echo.

:: Install system integration packages
echo [1/3] Installing pyautogui (text injection)...
python\venv\Scripts\pip install pyautogui>=0.9.54

echo [2/3] Installing keyboard (global hotkeys)...
python\venv\Scripts\pip install keyboard>=0.13.5

echo [3/3] Installing pywin32 (Windows API)...
python\venv\Scripts\pip install pywin32>=306

echo.
echo ========================================
echo ✅ Native Integration Installed!
echo ========================================
echo.
echo You can now use VoiceFlow as a native service:
echo.
echo 🎯 INVISIBLE MODE: VoiceFlow-Invisible.bat
echo    • Runs in system tray only
echo    • No visible windows
echo    • Just like Wispr Flow!
echo.
echo 🔧 NATIVE MODE: VoiceFlow-Native.bat  
echo    • Shows status window
echo    • Easy to monitor/debug
echo.
echo Both modes support:
echo • Global hotkey: Ctrl+Alt
echo • Text injection at cursor
echo • Works in ANY application
echo.
pause
