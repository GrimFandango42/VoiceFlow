@echo off
title VoiceFlow Performance Edition
cd /d "%~dp0"

echo.
echo ============================================
echo  VoiceFlow Performance Edition
echo ============================================
echo.
echo Speed optimizations:
echo [FAST] In-memory audio processing (no temp files)
echo [FAST] Tiny/Base model selection for speed
echo [FAST] Optimized VAD parameters
echo [FAST] Model preloading and warmup
echo [FAST] Reduced audio buffer (0.6s)
echo [FAST] Parallel processing pipeline
echo.

rem Check if Python environment exists
if not exist "python\venv\Scripts\python.exe" (
    echo [Error] Python environment not found!
    echo Please run INSTALL_ENHANCED_DEPS.bat first
    echo.
    pause
    exit /b 1
)

echo [Starting] Performance-optimized VoiceFlow...
echo.

rem Activate Python environment and run performance version
cd python
call venv\Scripts\activate.bat
python voiceflow_performance.py

echo.
echo [Stopped] VoiceFlow Performance Edition
pause