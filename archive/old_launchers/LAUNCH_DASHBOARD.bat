@echo off
REM VoiceFlow Performance Dashboard Launcher
REM Provides multiple dashboard launch options

echo ===============================================
echo    VoiceFlow Performance Dashboard Launcher
echo ===============================================
echo.
echo Choose your dashboard mode:
echo.
echo 1. Console Monitoring (Terminal-based)
echo 2. GUI Dashboard (Desktop Window)
echo 3. Web Dashboard (Browser-based)
echo 4. Help and Options
echo.
set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" goto console
if "%choice%"=="2" goto gui
if "%choice%"=="3" goto web
if "%choice%"=="4" goto help
goto invalid

:console
echo.
echo Starting Console Monitoring...
echo Press Ctrl+C to stop monitoring
echo.
python performance_dashboard.py --monitor
goto end

:gui
echo.
echo Starting GUI Dashboard...
python performance_dashboard.py --gui
goto end

:web
echo.
echo Starting Web Dashboard...
echo Web dashboard will be available at: http://localhost:5000
echo Press Ctrl+C to stop the web server
echo.
python performance_dashboard.py --web-dashboard
goto end

:help
echo.
echo ===============================================
echo           Dashboard Help and Options
echo ===============================================
echo.
echo Available Commands:
echo.
echo  Console Monitoring:
echo    python performance_dashboard.py --monitor
echo.
echo  GUI Dashboard:
echo    python performance_dashboard.py --gui
echo.
echo  Web Dashboard:
echo    python performance_dashboard.py --web-dashboard
echo.
echo  Custom Log Directory:
echo    python performance_dashboard.py --monitor --log-dir "path\to\logs"
echo.
echo  Log Analysis:
echo    python performance_dashboard.py --analyze "path\to\logs"
echo.
echo Features:
echo  - Real-time performance monitoring
echo  - Component health tracking
echo  - Memory usage analysis
echo  - Speed factor monitoring
echo  - Error rate tracking
echo  - Optimization recommendations
echo  - Performance data export
echo.
echo Requirements:
echo  - Python 3.8+
echo  - psutil (installed automatically)
echo  - Optional: Flask (for web dashboard)
echo  - Optional: tkinter (for GUI, usually included)
echo  - Optional: matplotlib (for advanced charts)
echo.
pause
goto end

:invalid
echo.
echo Invalid choice. Please run the script again and choose 1-4.
pause
goto end

:end
echo.
echo Dashboard session ended.
pause