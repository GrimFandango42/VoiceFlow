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
    # Start-Process, NOT Win32_Process::Create.
    #
    # Win32_Process::Create was the original choice because it parents the new
    # process to the WMI host, so the app outlives the watchdog invocation. It
    # does that, and it also hands back a crippled process: launched that way
    # VoiceFlow cannot reach the GPU (Whisper silently drops to CPU int8,
    # roughly 85x slower and no live caption), writes nothing to its log, and
    # records no transcription history. The app otherwise looks fine -- tray,
    # hotkey, injection all work -- so nothing announces the damage.
    #
    # That is not a theory. The transcription history's last entry was
    # 2026-11-03 20:32, the last time VoiceFlow started from the Startup
    # shortcut. This watchdog took over on 2026-11-06 and every launch after
    # it was degraded. The same binary started with Start-Process is on
    # device=cuda compute=float16, appears in nvidia-smi, and logs normally.
    #
    # Start-Process is safe here: this script runs from Task Scheduler, so the
    # child is parented to a PowerShell that exits immediately, and the app
    # keeps running. The scheduler, not an interactive session, owns the chain.
    # Load models from the local cache only.
    #
    # The app preloads two Whisper models at the same instant. Each goes through
    # huggingface_hub's snapshot_download, whose progress-bar class shares one
    # class-level lock that the two threads create and delete under each other.
    # The loser fails with "type object 'disabled_tqdm' has no attribute '_lock'"
    # and the app answers by dropping that model to CPU int8 -- a main model that
    # takes seconds per dictation instead of a fraction of one. Which launch
    # loses is luck (seen 2026-11-10 12:22: warmup 4.62s on CPU vs 0.10s on GPU).
    # Offline mode returns the cached path without that code. Every model the
    # app uses is already cached; a new model needs one online start.
    $env:HF_HUB_OFFLINE = '1'

    $proc = Start-Process -FilePath $ExePath `
                          -WorkingDirectory (Split-Path -Parent $ExePath) `
                          -WindowStyle Hidden `
                          -PassThru
    if ($proc) {
        # Task Scheduler runs this at priority 7, and the child inherits
        # BelowNormal CPU priority. Dictation is interactive; put it back.
        try { $proc.PriorityClass = 'Normal' } catch { Write-WatchdogLog "could not raise priority: $($_.Exception.Message)" }
        Write-WatchdogLog "started pid=$($proc.Id)"
    } else {
        Write-WatchdogLog "START FAILED: no process handle returned"
        exit 1
    }
} catch {
    Write-WatchdogLog "START FAILED $($_.Exception.Message)"
    exit 1
}

exit 0
