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

  "Running" is decided from what VoiceFlow itself publishes (VF-22), not from a
  process name, so an instance started from source (pythonw.exe via the Desktop
  shortcut) counts:

    * the single-instance mutex Local\VoiceFlow_CLI_Enhanced, held by every
      VoiceFlow (bundle or source) for its whole life, and
    * the instance record %LOCALAPPDATA%\VoiceFlow\instance.json (pid, process
      name, start time, kind), checked against the live process so a record
      left behind by a crash does not count.

  Before VF-22 it looked only for VoiceFlow.exe, so while a source instance
  ran it started the bundle every 15 minutes, and the bundle exited at once on
  the single-instance check without anyone noticing. Now, when it does start
  the bundle, it checks 20 s later whether that process is still alive, logs
  "exited early, code N" if not, and does not start it again for an hour.

  Idempotent and quiet. Exits 0 when the app is already running.

.PARAMETER WhatIf
  Print the decision and start or stop nothing (and write no log or state).

.NOTES
  Deliberately does NOT touch other dictation apps. VoiceFlow is safe to run
  side by side with one, as long as the hotkeys differ.

  The decision is Get-WatchdogDecision, a pure function of its parameters.
  Dot-source this script to call it without running the watchdog:
      . .\voiceflow-watchdog.ps1
      Get-WatchdogDecision -MutexHeld $false -Now (Get-Date) ...
  tests\ops\test_watchdog_decision.ps1 does exactly that.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ExePath = "C:\AI_Projects\VoiceFlow\dist\VoiceFlow\VoiceFlow.exe",
    [string]$LogPath = "$env:LOCALAPPDATA\VoiceFlow\logs\watchdog.log",
    [string]$InstancePath = "$env:LOCALAPPDATA\VoiceFlow\instance.json",
    [string]$StatePath = "",
    [string]$MutexName = "Local\VoiceFlow_CLI_Enhanced",
    [int]$EarlyExitSeconds = 20,
    [int]$BackoffMinutes = 60,
    # Legacy spelling of -WhatIf.
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Pure decision (no I/O). Everything it needs comes in as parameters.
# ---------------------------------------------------------------------------

function ConvertFrom-UnixSeconds {
    param([double]$Seconds)
    return [DateTimeOffset]::FromUnixTimeMilliseconds([long][math]::Round($Seconds * 1000)).LocalDateTime
}

function Test-InstanceRecordAlive {
    <#
      True when the process named by the instance record is the one that wrote
      it: same pid, same process name, started within the tolerance of the
      recorded start time. A dead pid, or a pid Windows reused for some other
      program, is a stale record.
    #>
    param(
        $Record,
        $Process,
        [int]$StartToleranceSeconds = 120
    )
    if ($null -eq $Record -or $null -eq $Process) { return $false }
    $recordName = ([string]$Record.process_name) -replace '\.exe$', ''
    $liveName = ([string]$Process.ProcessName) -replace '\.exe$', ''
    if ($recordName -and $liveName -and ($recordName -ne $liveName)) { return $false }
    if ($null -ne $Record.started_unix -and $null -ne $Process.StartTime) {
        $recorded = ConvertFrom-UnixSeconds ([double]$Record.started_unix)
        $delta = [math]::Abs(([datetime]$Process.StartTime - $recorded).TotalSeconds)
        if ($delta -gt $StartToleranceSeconds) { return $false }
    }
    return $true
}

function Get-WatchdogDecision {
    <#
      Decide what the watchdog should do. Returns an object with:
        Action   none | stop-duplicates | start | backoff | missing-exe
        Reason   one line for the log
        KeepPid  (stop-duplicates) the instance to keep
        StopPids (stop-duplicates) the instances to stop
    #>
    [CmdletBinding()]
    param(
        [bool]$MutexHeld = $false,
        $InstanceRecord = $null,
        $InstanceProcess = $null,
        [object[]]$BundleProcesses = @(),
        [bool]$ExeExists = $true,
        $BackoffUntil = $null,
        [datetime]$Now = (Get-Date),
        [int]$StartToleranceSeconds = 120
    )
    $bundles = @($BundleProcesses | Where-Object { $null -ne $_ })
    $result = [ordered]@{ Action = 'none'; Reason = ''; KeepPid = $null; StopPids = @() }

    if ($bundles.Count -gt 1) {
        # Two instances fight over the hotkey and the audio device. Keep the oldest.
        $keep = $bundles | Sort-Object StartTime | Select-Object -First 1
        $result.Action = 'stop-duplicates'
        $result.KeepPid = $keep.Id
        $result.StopPids = @($bundles | Where-Object { $_.Id -ne $keep.Id } | ForEach-Object { $_.Id })
        $result.Reason = "duplicate VoiceFlow.exe instances; keeping pid=$($keep.Id)"
        return [pscustomobject]$result
    }

    $recordAlive = Test-InstanceRecordAlive -Record $InstanceRecord -Process $InstanceProcess `
        -StartToleranceSeconds $StartToleranceSeconds
    $recordText = ''
    if ($null -ne $InstanceRecord) {
        $recordText = "kind=$($InstanceRecord.kind) pid=$($InstanceRecord.pid) name=$($InstanceRecord.process_name)"
    }

    if ($MutexHeld) {
        $result.Reason = 'running (single-instance mutex held' + $(if ($recordAlive) { "; $recordText)" } else { ')' })
        return [pscustomobject]$result
    }
    if ($recordAlive) {
        $result.Reason = "running (instance record $recordText)"
        return [pscustomobject]$result
    }
    if ($bundles.Count -eq 1) {
        $result.Reason = "running (VoiceFlow.exe pid=$($bundles[0].Id))"
        return [pscustomobject]$result
    }

    $stale = ''
    if ($null -ne $InstanceRecord) { $stale = "; stale instance record ($recordText) ignored" }

    if ($null -ne $BackoffUntil -and $Now -lt [datetime]$BackoffUntil) {
        $result.Action = 'backoff'
        $result.Reason = "not running, but the bundle exited early last time; not starting it again until " +
            ([datetime]$BackoffUntil).ToString('yyyy-MM-dd HH:mm:ss') + $stale
        return [pscustomobject]$result
    }
    if (-not $ExeExists) {
        $result.Action = 'missing-exe'
        $result.Reason = "NOT STARTED: executable missing$stale"
        return [pscustomobject]$result
    }
    $result.Action = 'start'
    $result.Reason = "VoiceFlow not running$stale"
    return [pscustomobject]$result
}

# ---------------------------------------------------------------------------
# I/O helpers.
# ---------------------------------------------------------------------------

function Test-VoiceFlowMutex {
    param([string]$Name)
    # Opening an existing named mutex does not acquire it; the handle is closed at once.
    $mutex = $null
    try {
        if ([System.Threading.Mutex]::TryOpenExisting($Name, [ref]$mutex)) {
            $mutex.Dispose()
            return $true
        }
    } catch [System.UnauthorizedAccessException] {
        return $true  # it exists; we just may not open it
    } catch {
        return $false
    }
    return $false
}

function Read-InstanceRecord {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $record = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        if ($null -eq $record.pid) { return $null }
        return $record
    } catch {
        return $null
    }
}

function Read-WatchdogState {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) } catch { return $null }
}

function Get-BackoffUntil {
    param($State)
    if ($null -eq $State -or -not $State.backoff_until) { return $null }
    try {
        return [datetime]::Parse([string]$State.backoff_until, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
    } catch {
        return $null
    }
}

function Write-WatchdogState {
    param([string]$Path, [datetime]$BackoffUntil, [string]$Reason)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $state = [ordered]@{
        backoff_until = $BackoffUntil.ToUniversalTime().ToString('o')
        reason        = $Reason
    }
    Set-Content -LiteralPath $Path -Value ($state | ConvertTo-Json) -Encoding UTF8
}

# Dot-sourced (tests, interactive use): define the functions, run nothing.
if ($MyInvocation.InvocationName -eq '.') { return }

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

if ($WhatIfOnly) { $WhatIfPreference = $true }
$dryRun = [bool]$WhatIfPreference
if (-not $StatePath) { $StatePath = Join-Path (Split-Path -Parent $LogPath) 'watchdog.state.json' }

function Write-WatchdogLog {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    if ($dryRun) {
        Write-Output "[WhatIf] $line"
        return
    }
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

$bundleProcesses = @(Get-Process -Name 'VoiceFlow' -ErrorAction SilentlyContinue)
$record = Read-InstanceRecord -Path $InstancePath
$recordProcess = $null
if ($null -ne $record) {
    $recordProcess = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
}
$decision = Get-WatchdogDecision `
    -MutexHeld (Test-VoiceFlowMutex -Name $MutexName) `
    -InstanceRecord $record `
    -InstanceProcess $recordProcess `
    -BundleProcesses $bundleProcesses `
    -ExeExists (Test-Path -LiteralPath $ExePath) `
    -BackoffUntil (Get-BackoffUntil (Read-WatchdogState -Path $StatePath)) `
    -Now (Get-Date)

if ($dryRun) {
    Write-Output ("decision action={0} reason={1}" -f $decision.Action, $decision.Reason)
}

switch ($decision.Action) {
    'none' {
        exit 0
    }
    'stop-duplicates' {
        foreach ($dupId in $decision.StopPids) {
            Write-WatchdogLog "duplicate instance pid=$dupId stopped; keeping pid=$($decision.KeepPid)"
            if ($PSCmdlet.ShouldProcess("VoiceFlow pid=$dupId", 'Stop duplicate instance')) {
                Stop-Process -Id $dupId -Force -ErrorAction SilentlyContinue
            }
        }
        exit 0
    }
    'backoff' {
        Write-WatchdogLog $decision.Reason
        exit 0
    }
    'missing-exe' {
        Write-WatchdogLog "$($decision.Reason) at $ExePath"
        exit 1
    }
}

# Action: start.
Write-WatchdogLog "$($decision.Reason); starting $ExePath"
if (-not $PSCmdlet.ShouldProcess($ExePath, 'Start VoiceFlow')) { exit 0 }

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
    if (-not $proc) {
        Write-WatchdogLog "START FAILED: no process handle returned"
        exit 1
    }
    # Touch the handle now so ExitCode is still readable if it exits early.
    $null = $proc.Handle
    # Task Scheduler runs this at priority 7, and the child inherits
    # BelowNormal CPU priority. Dictation is interactive; put it back.
    try { $proc.PriorityClass = 'Normal' } catch { Write-WatchdogLog "could not raise priority: $($_.Exception.Message)" }
    Write-WatchdogLog "started pid=$($proc.Id)"
} catch {
    Write-WatchdogLog "START FAILED $($_.Exception.Message)"
    exit 1
}

# VF-22: a bundle that loses the single-instance check exits within a second or
# two and logs nothing. Look again after a while and say so.
Start-Sleep -Seconds ([math]::Max(1, $EarlyExitSeconds))
$proc.Refresh()
if ($proc.HasExited) {
    $code = $null
    try { $code = $proc.ExitCode } catch { $code = 'unknown' }
    $until = (Get-Date).AddMinutes($BackoffMinutes)
    Write-WatchdogLog ("pid={0} exited early, code {1}; not starting the bundle again until {2}" -f `
        $proc.Id, $code, $until.ToString('yyyy-MM-dd HH:mm:ss'))
    try { Write-WatchdogState -Path $StatePath -BackoffUntil $until -Reason "pid=$($proc.Id) exited early, code $code" } catch {
        Write-WatchdogLog "could not write state: $($_.Exception.Message)"
    }
    exit 1
}
Write-WatchdogLog ("pid={0} still running after {1}s" -f $proc.Id, $EarlyExitSeconds)
exit 0
