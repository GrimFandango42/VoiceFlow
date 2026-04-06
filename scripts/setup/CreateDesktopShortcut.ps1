param(
    [switch]$Launch
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "VoiceFlow.lnk"
$TargetPath = "$env:WINDIR\System32\wscript.exe"
$LauncherPath = Join-Path $ScriptDir "VoiceFlow_Tray.vbs"
$IconPath = Join-Path $ScriptDir "assets\icon.ico"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VoiceFlow - Create Desktop Shortcut   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $LauncherPath)) {
    Write-Host "ERROR: VoiceFlow_Tray.vbs not found at: $LauncherPath" -ForegroundColor Red
    exit 1
}

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $TargetPath
$Shortcut.Arguments = "`"$LauncherPath`""
$Shortcut.WorkingDirectory = $ScriptDir
$Shortcut.Description = "VoiceFlow tray launcher"
$Shortcut.WindowStyle = 7

if (Test-Path $IconPath) {
    $Shortcut.IconLocation = $IconPath
} else {
    $Shortcut.IconLocation = "%SystemRoot%\System32\shell32.dll,168"
}

$Shortcut.Save()

Write-Host "SUCCESS: Desktop shortcut created:" -ForegroundColor Green
Write-Host "  $ShortcutPath"
Write-Host ""
Write-Host "Double-click to launch VoiceFlow in tray mode." -ForegroundColor Yellow

if ($Launch) {
    Start-Process -FilePath $TargetPath -ArgumentList "`"$LauncherPath`"" -WorkingDirectory $ScriptDir
}
