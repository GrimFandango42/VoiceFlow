<#
.SYNOPSIS
  Keep VoiceFlow running. Start it if it is not.

.DESCRIPTION
  VoiceFlow is a tray app with no service wrapper, so nothing restarts it when
  it dies, and it can stay down unnoticed, because:

    * the Startup-folder shortcut only fires at logon, so a desktop left
      running for weeks never gets one, and
    * a process launched from a tool or terminal session goes down when that
      session's host does.

  Run from Task Scheduler this is session-independent: the scheduler owns the
  process, so it outlives whatever started the watchdog.

  Idempotent and quiet. Exits 0 when the app is already running.

.NOTES
  Deliberately does NOT touch other dictation apps. VoiceFlow is safe to run
  side by side with one, as long as the hotkeys differ.
#>
[CmdletBinding()]
param(
    [string]$ExePath = "C:\AI_Projects\VoiceFlow\dist\VoiceFlow\VoiceFlow.exe",
    [string]$LogPath = "$env:LOCALAPPDATA\VoiceFlow\logs\watchdog.log",
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'

function Write-WatchdogLog {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    try {
        $dir = Split-Path -Parent $LogPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        # This runs every 15 minutes; keep the log from growing without bound.
        if ((Test-Path $LogPath) -and ((Get-Item $LogPath).Length -gt 256KB)) {
            $keep = Get-Content $LogPath -Tail 500
            Set-Content -Path $LogPath -Value $keep
        }
        Add-Content -Path $LogPath -Value $line
    } catch {
        # A watchdog that dies because it could not log is worse than a quiet one.
    }
}

$running = @(Get-Process -Name 'VoiceFlow' -ErrorAction SilentlyContinue)

if ($running.Count -gt 1) {
    # Two instances fight over the hotkey and the audio device. Keep the oldest.
    $keep = $running | Sort-Object StartTime | Select-Object -First 1
    foreach ($dup in ($running | Where-Object { $_.Id -ne $keep.Id })) {
        Write-WatchdogLog "duplicate instance pid=$($dup.Id) stopped; keeping pid=$($keep.Id)"
        if (-not $WhatIfOnly) { Stop-Process -Id $dup.Id -Force -ErrorAction SilentlyContinue }
    }
    exit 0
}

if ($running.Count -eq 1) { exit 0 }

if (-not (Test-Path $ExePath)) {
    Write-WatchdogLog "NOT STARTED: executable missing at $ExePath"
    exit 1
}

Write-WatchdogLog "VoiceFlow not running; starting $ExePath"
if ($WhatIfOnly) { exit 0 }

try {
    # Win32_Process::Create parents the new process to the WMI host rather than
    # to this script, so the app outlives the watchdog invocation itself.
    $result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine      = "`"$ExePath`""
        CurrentDirectory = (Split-Path -Parent $ExePath)
    }
    if ($result.ReturnValue -eq 0) {
        Write-WatchdogLog "started pid=$($result.ProcessId)"
    } else {
        Write-WatchdogLog "START FAILED rc=$($result.ReturnValue)"
        exit 1
    }
} catch {
    Write-WatchdogLog "START FAILED $($_.Exception.Message)"
    exit 1
}

exit 0
