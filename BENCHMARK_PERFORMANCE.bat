@echo off
title VoiceFlow Performance Benchmark
cd /d "%~dp0"

echo.
echo ============================================
echo  VoiceFlow Performance Benchmark
echo ============================================
echo.
echo This will test different configurations to find
echo the fastest Whisper model setup for your system.
echo.

rem Check if Python environment exists
if not exist "python\venv\Scripts\python.exe" (
    echo [Error] Python environment not found!
    echo Please run INSTALL_ENHANCED_DEPS.bat first
    echo.
    pause
    exit /b 1
)

echo [Starting] Performance benchmark...
echo This may take a few minutes...
echo.

rem Activate Python environment and run benchmark
cd python
call venv\Scripts\activate.bat
python performance_benchmark.py

echo.
echo [Complete] Check results above for optimal configuration
echo.
pause