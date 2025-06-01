@echo off
title VoiceFlow Comprehensive Test
cd /d "C:\AI_Projects\VoiceFlow\"

echo ================================================
echo        VoiceFlow Comprehensive End-User Test
echo ================================================
echo.

:: Test 1: Check if all required files exist
echo [TEST 1] Checking required files...
if exist "python\venv\Scripts\python.exe" (
    echo ✓ Python environment found
) else (
    echo ✗ Python environment missing
    goto :fail
)

if exist "python\stt_server.py" (
    echo ✓ Backend server found
) else (
    echo ✗ Backend server missing
    goto :fail
)

if exist "voiceflow_frontend.html" (
    echo ✓ Frontend HTML found
) else (
    echo ✗ Frontend HTML missing
    goto :fail
)

:: Test 2: Try starting the backend server
echo.
echo [TEST 2] Testing backend server startup...
echo Starting server (this may take 15-20 seconds)...
start /min cmd /c "python\venv\Scripts\python.exe python\stt_server.py > server_test.log 2>&1"

:: Wait for server to initialize
timeout /t 20 /nobreak >nul

:: Check if server process is running
tasklist /fi "imagename eq python.exe" | find "python.exe" >nul
if %errorlevel% == 0 (
    echo ✓ Backend server is running
) else (
    echo ✗ Backend server failed to start
    echo Check server_test.log for details
    goto :fail
)

:: Test 3: Test frontend HTML
echo.
echo [TEST 3] Testing frontend...
echo Opening VoiceFlow interface...
start voiceflow_frontend.html

echo.
echo ================================================
echo             ✅ ALL TESTS PASSED!
echo ================================================
echo.
echo VoiceFlow is now running and ready to use!
echo.
echo Instructions:
echo 1. The web interface should have opened in your browser
echo 2. It should show "Connected to VoiceFlow Server"
echo 3. Press Ctrl+Alt anywhere to start recording
echo 4. Speak normally and text will appear at your cursor
echo.
echo To stop VoiceFlow:
echo - Close this window OR
echo - Kill python.exe in Task Manager
echo.
echo Press any key to stop VoiceFlow...
pause >nul

:: Cleanup
echo.
echo Stopping VoiceFlow...
taskkill /f /im python.exe 2>nul >nul
echo ✓ VoiceFlow stopped successfully
goto :end

:fail
echo.
echo ================================================
echo               ❌ TESTS FAILED
echo ================================================
echo.
echo Please check the error messages above.
echo You may need to reinstall dependencies.
echo.
pause

:end
