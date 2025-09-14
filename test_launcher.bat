@echo off
cd /d %~dp0
echo Testing VoiceFlow launcher compatibility...
echo.

REM Test PYTHONPATH setup and import
set PYTHONPATH=src
python -c "import sys; sys.path.insert(0, 'src'); import voiceflow.core.config; print('[OK] VoiceFlow imports working')"

if errorlevel 1 (
    echo [FAIL] Import test failed
    goto :error
)

echo [OK] Launcher test passed
echo VoiceFlow is ready for launch!
goto :end

:error
echo [ERROR] Launcher test failed
exit /b 1

:end
echo Test completed successfully