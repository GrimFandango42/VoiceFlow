@echo off
setlocal EnableDelayedExpansion

echo ================================================
echo VoiceFlow Multi-Method Build Script
echo ================================================
echo.
echo This script will try multiple methods to create
echo an executable for VoiceFlow.
echo.

cd /d C:\AI_Projects\VoiceFlow

:: Method 1: PyInstaller for Python backend
echo [Method 1] Building Python backend executable...
echo.

if exist "python\venv\Scripts\activate.bat" (
    call python\venv\Scripts\activate.bat
    
    echo Installing PyInstaller...
    pip install pyinstaller --quiet
    
    echo Building STT server executable...
    cd python
    pyinstaller --onefile --noconsole ^
        --add-data "..\src-tauri\icons;icons" ^
        --hidden-import=websockets ^
        --hidden-import=numpy ^
        --hidden-import=RealtimeSTT ^
        --hidden-import=faster_whisper ^
        --name VoiceFlow-Backend ^
        stt_server.py
    
    if exist "dist\VoiceFlow-Backend.exe" (
        echo [SUCCESS] Python backend built: python\dist\VoiceFlow-Backend.exe
        move dist\VoiceFlow-Backend.exe ..
    ) else (
        echo [FAIL] PyInstaller build failed
    )
    
    cd ..
) else (
    echo [SKIP] Python virtual environment not found
)

echo.
echo ================================================
echo.

:: Method 2: Electron Builder
echo [Method 2] Building Electron app...
echo.

if exist "electron\node_modules" (
    cd electron
    
    echo Running Electron Builder...
    call npm run dist
    
    if exist "dist\*.exe" (
        echo [SUCCESS] Electron app built in: electron\dist\
        for %%f in (dist\*.exe) do (
            echo Found: %%f
            copy "%%f" "..\VoiceFlow-Electron.exe" >nul
        )
    ) else (
        echo [FAIL] Electron build failed
    )
    
    cd ..
) else (
    echo [SKIP] Electron not set up properly
)

echo.
echo ================================================
echo.

:: Method 3: Create standalone launcher
echo [Method 3] Creating standalone launcher...
echo.

(
echo @echo off
echo title VoiceFlow Launcher
echo cd /d "%~dp0"
echo.
echo echo Starting VoiceFlow...
echo.
echo :: Start Python backend
echo start /min cmd /c "python\venv\Scripts\python.exe python\stt_server.py"
echo.
echo :: Wait for server to start
echo timeout /t 3 /nobreak ^>nul
echo.
echo :: Open frontend in browser
echo start http://localhost:8765
echo.
echo :: Keep window open
echo echo VoiceFlow is running. Close this window to stop.
echo pause ^>nul
echo.
echo :: Cleanup
echo taskkill /f /im python.exe 2^>nul
) > VoiceFlow-Launcher.bat

echo [SUCCESS] Created VoiceFlow-Launcher.bat

echo.
echo ================================================
echo.

:: Method 4: Create PowerShell launcher with tray icon
echo [Method 4] Creating PowerShell launcher with tray...
echo.

(
echo # VoiceFlow PowerShell Launcher with System Tray
echo Add-Type -AssemblyName System.Windows.Forms
echo Add-Type -AssemblyName System.Drawing
echo.
echo $script:running = $false
echo $script:process = $null
echo.
echo # Create tray icon
echo $trayIcon = New-Object System.Windows.Forms.NotifyIcon
echo $trayIcon.Text = "VoiceFlow"
echo $trayIcon.Icon = [System.Drawing.SystemIcons]::Information
echo $trayIcon.Visible = $true
echo.
echo # Create context menu
echo $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
echo.
echo $toggleItem = $contextMenu.Items.Add("Start VoiceFlow"^)
echo $toggleItem.Add_Click({
echo     if ($script:running^) {
echo         # Stop
echo         if ($script:process^) { $script:process.Kill(^) }
echo         $script:running = $false
echo         $toggleItem.Text = "Start VoiceFlow"
echo         $trayIcon.ShowBalloonTip(1000, "VoiceFlow", "Stopped", [System.Windows.Forms.ToolTipIcon]::Info^)
echo     } else {
echo         # Start
echo         $script:process = Start-Process -FilePath "python\venv\Scripts\python.exe" -ArgumentList "python\stt_server.py" -WindowStyle Hidden -PassThru
echo         $script:running = $true
echo         $toggleItem.Text = "Stop VoiceFlow"
echo         $trayIcon.ShowBalloonTip(1000, "VoiceFlow", "Started - Press Ctrl+Alt+Space to record", [System.Windows.Forms.ToolTipIcon]::Info^)
echo         Start-Sleep -Seconds 2
echo         Start-Process "http://localhost:8765"
echo     }
echo }^)
echo.
echo $contextMenu.Items.Add("-"^) ^| Out-Null
echo.
echo $exitItem = $contextMenu.Items.Add("Exit"^)
echo $exitItem.Add_Click({
echo     if ($script:process^) { $script:process.Kill(^) }
echo     $trayIcon.Visible = $false
echo     [System.Windows.Forms.Application]::Exit(^)
echo }^)
echo.
echo $trayIcon.ContextMenuStrip = $contextMenu
echo.
echo # Keep running
echo [System.Windows.Forms.Application]::Run(^)
) > VoiceFlow-Tray.ps1

echo [SUCCESS] Created VoiceFlow-Tray.ps1

:: Create batch file to run PowerShell script
(
echo @echo off
echo powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0VoiceFlow-Tray.ps1"
) > VoiceFlow-SystemTray.bat

echo [SUCCESS] Created VoiceFlow-SystemTray.bat

echo.
echo ================================================
echo BUILD SUMMARY
echo ================================================
echo.

if exist "VoiceFlow-Backend.exe" (
    echo [/] Python Backend: VoiceFlow-Backend.exe
) else (
    echo [ ] Python Backend: Not built
)

if exist "VoiceFlow-Electron.exe" (
    echo [/] Electron App: VoiceFlow-Electron.exe  
) else (
    echo [ ] Electron App: Not built
)

echo [/] Batch Launcher: VoiceFlow-Launcher.bat
echo [/] System Tray: VoiceFlow-SystemTray.bat

echo.
echo ================================================
echo NEXT STEPS:
echo ================================================
echo.
echo 1. For quick testing:
echo    Run: VoiceFlow-Launcher.bat
echo.
echo 2. For system tray integration:
echo    Run: VoiceFlow-SystemTray.bat
echo.
echo 3. For standalone executable:
echo    - VoiceFlow-Backend.exe (if built)
echo    - VoiceFlow-Electron.exe (if built)
echo.
pause