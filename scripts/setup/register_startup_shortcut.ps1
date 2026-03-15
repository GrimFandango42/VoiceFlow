param(
    [string]$TargetExe = "",
    [string]$ShortcutName = "VoiceFlow",
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not $TargetExe) {
    $TargetExe = Join-Path $repoRoot "dist\VoiceFlow\VoiceFlow.exe"
}

$startupDir = [Environment]::GetFolderPath("Startup")
$shortcutPath = Join-Path $startupDir ($ShortcutName + ".lnk")

if ($Remove) {
    if (Test-Path $shortcutPath) {
        Remove-Item -Path $shortcutPath -Force
        Write-Output ("Removed startup shortcut: " + $shortcutPath)
    } else {
        Write-Output ("Startup shortcut not present: " + $shortcutPath)
    }
    exit 0
}

if (-not (Test-Path $TargetExe)) {
    throw "Packaged executable not found: $TargetExe"
}

$targetDir = Split-Path -Parent $TargetExe
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $TargetExe
$shortcut.WorkingDirectory = $targetDir
$shortcut.Description = "Launch VoiceFlow packaged executable at Windows sign-in"
$shortcut.IconLocation = $TargetExe
$shortcut.WindowStyle = 7
$shortcut.Save()

Write-Output ("Startup shortcut ready: " + $shortcutPath)
Write-Output ("Target: " + $TargetExe)
