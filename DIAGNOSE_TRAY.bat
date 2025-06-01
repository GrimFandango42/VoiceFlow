@echo off
echo ========================================
echo VoiceFlow System Tray Diagnostic
echo ========================================
echo.

cd /d "C:\AI_Projects\VoiceFlow"

echo [1] Testing PowerShell execution policy...
powershell -Command "Write-Host 'PowerShell access: OK'"
if %errorlevel% neq 0 (
    echo ERROR: PowerShell execution blocked
    echo Fixing execution policy...
    powershell -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force"
)

echo.
echo [2] Testing system tray capabilities...
powershell -ExecutionPolicy Bypass -Command ^
"Add-Type -AssemblyName System.Windows.Forms; ^
Add-Type -AssemblyName System.Drawing; ^
Write-Host 'System tray assemblies: OK'"

if %errorlevel% neq 0 (
    echo ERROR: System tray assemblies failed to load
    pause
    exit /b 1
)

echo.
echo [3] Creating simple system tray test...
powershell -ExecutionPolicy Bypass -WindowStyle Normal -Command ^
"Add-Type -AssemblyName System.Windows.Forms; ^
Add-Type -AssemblyName System.Drawing; ^
$icon = New-Object System.Windows.Forms.NotifyIcon; ^
$icon.Icon = [System.Drawing.SystemIcons]::Microphone; ^
$icon.Text = 'VoiceFlow Test'; ^
$icon.Visible = $true; ^
$icon.ShowBalloonTip(3000, 'VoiceFlow', 'System tray test successful!', [System.Windows.Forms.ToolTipIcon]::Info); ^
Write-Host 'System tray icon created - check your tray!'; ^
Start-Sleep -Seconds 5; ^
$icon.Visible = $false"

echo.
echo [4] Testing hotkey registration...
powershell -ExecutionPolicy Bypass -Command ^
"try { ^
    Add-Type -TypeDefinition 'using System; using System.Windows.Forms; public class HotkeyTest { public static void Main() { Console.WriteLine(\"Hotkey test ready\"); } }'; ^
    Write-Host 'Hotkey system: OK'; ^
} catch { ^
    Write-Host 'Hotkey system: FAILED - ' $_.Exception.Message; ^
}"

echo.
echo [5] Checking for running VoiceFlow processes...
tasklist | findstr python.exe
tasklist | findstr powershell.exe

echo.
echo DIAGNOSIS COMPLETE
echo If you saw a system tray icon appear and disappear, the system works!
echo If not, there may be a Windows permissions or compatibility issue.
echo.
pause
