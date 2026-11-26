<#
  VF-22: the watchdog decision, without starting anything.

  Dot-sources scripts\ops\voiceflow-watchdog.ps1 (which then only defines its
  functions) and checks Get-WatchdogDecision with fake inputs: no process is
  started or stopped, no mutex is opened, nothing under %LOCALAPPDATA% is read.
  State-file helpers are exercised against a temporary directory.

      pwsh -NoProfile -File tests\ops\test_watchdog_decision.ps1

  Exit code 0 = all cases pass. Plain assertions: no Pester dependency.
#>
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot '..\..\scripts\ops\voiceflow-watchdog.ps1'
. $script

$failures = New-Object System.Collections.Generic.List[string]
$passed = 0

function Check {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ ; Write-Output "ok   $Name" }
    else { $script:failures.Add("$Name $Detail"); Write-Output "FAIL $Name $Detail" }
}

$now = Get-Date '2026-11-26T10:15:01'

function New-Record([int]$ProcessId, [string]$Name, [datetime]$Started, [string]$Kind) {
    [pscustomobject]@{
        pid          = $ProcessId
        process_name = $Name
        started_unix = ([DateTimeOffset]$Started).ToUnixTimeMilliseconds() / 1000.0
        kind         = $Kind
    }
}
function New-Proc([int]$ProcessId, [string]$Name, [datetime]$Started) {
    [pscustomobject]@{ Id = $ProcessId; ProcessName = $Name; StartTime = $Started }
}

$srcStart = $now.AddMinutes(-50)
$srcRecord = New-Record 4242 'pythonw.exe' $srcStart 'source'
$srcProc = New-Proc 4242 'pythonw' $srcStart.AddSeconds(1)

# 1. Bundle running (the old name-based case still counts).
$d = Get-WatchdogDecision -BundleProcesses @(New-Proc 100 'VoiceFlow' $now.AddHours(-1)) -Now $now
Check 'bundle running -> none' ($d.Action -eq 'none') $d.Reason

# 1b. Bundle running and holding the mutex.
$d = Get-WatchdogDecision -MutexHeld $true -BundleProcesses @(New-Proc 100 'VoiceFlow' $now.AddHours(-1)) -Now $now
Check 'bundle with mutex -> none' ($d.Action -eq 'none' -and $d.Reason -match 'mutex') $d.Reason

# 2. Source instance running: mutex held, no VoiceFlow.exe process (the 2026-11-26 case).
$d = Get-WatchdogDecision -MutexHeld $true -InstanceRecord $srcRecord -InstanceProcess $srcProc -Now $now
Check 'source instance (mutex) -> none' ($d.Action -eq 'none' -and $d.Reason -match 'kind=source') $d.Reason

# 2b. Source instance running, mutex not visible (watchdog in another session): the record decides.
$d = Get-WatchdogDecision -MutexHeld $false -InstanceRecord $srcRecord -InstanceProcess $srcProc -Now $now
Check 'source instance (record only) -> none' ($d.Action -eq 'none' -and $d.Reason -match 'instance record') $d.Reason

# 3. Nothing running.
$d = Get-WatchdogDecision -Now $now
Check 'nothing running -> start' ($d.Action -eq 'start') $d.Reason

# 3b. Nothing running and the bundle is missing.
$d = Get-WatchdogDecision -ExeExists $false -Now $now
Check 'nothing running, no exe -> missing-exe' ($d.Action -eq 'missing-exe') $d.Reason

# 4. Stale record: the pid is gone.
$d = Get-WatchdogDecision -InstanceRecord $srcRecord -InstanceProcess $null -Now $now
Check 'stale record (dead pid) -> start' ($d.Action -eq 'start' -and $d.Reason -match 'stale') $d.Reason

# 4b. Stale record: Windows reused the pid for another program.
$d = Get-WatchdogDecision -InstanceRecord $srcRecord -InstanceProcess (New-Proc 4242 'notepad' $srcStart) -Now $now
Check 'stale record (pid reused, other name) -> start' ($d.Action -eq 'start' -and $d.Reason -match 'stale') $d.Reason

# 4c. Stale record: same name, but a later process (the old one died, a new pythonw got the pid).
$d = Get-WatchdogDecision -InstanceRecord $srcRecord -InstanceProcess (New-Proc 4242 'pythonw' $now.AddMinutes(-5)) -Now $now
Check 'stale record (pid reused, later start) -> start' ($d.Action -eq 'start') $d.Reason

# 5. Early-exit back-off: nothing running, back-off still active.
$d = Get-WatchdogDecision -BackoffUntil $now.AddMinutes(40) -Now $now
Check 'early exit back-off active -> backoff' ($d.Action -eq 'backoff') $d.Reason

# 5b. Back-off over: start again.
$d = Get-WatchdogDecision -BackoffUntil $now.AddMinutes(-1) -Now $now
Check 'early exit back-off expired -> start' ($d.Action -eq 'start') $d.Reason

# 5c. A running source instance wins over a back-off (nothing to do either way).
$d = Get-WatchdogDecision -MutexHeld $true -BackoffUntil $now.AddMinutes(40) -Now $now
Check 'running beats back-off -> none' ($d.Action -eq 'none') $d.Reason

# 6. Duplicate bundles: keep the oldest.
$d = Get-WatchdogDecision -BundleProcesses @(
    (New-Proc 200 'VoiceFlow' $now.AddMinutes(-5)),
    (New-Proc 100 'VoiceFlow' $now.AddHours(-1))
) -Now $now
Check 'duplicates -> stop newer, keep oldest' (
    $d.Action -eq 'stop-duplicates' -and $d.KeepPid -eq 100 -and (@($d.StopPids) -join ',') -eq '200'
) $d.Reason

# 7. State file round trip (temporary directory only).
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("vf22-watchdog-" + [guid]::NewGuid().ToString('N'))
try {
    $statePath = Join-Path $tmp 'watchdog.state.json'
    Check 'no state file -> no back-off' ($null -eq (Get-BackoffUntil (Read-WatchdogState -Path $statePath)))
    $until = $now.AddMinutes(60)
    Write-WatchdogState -Path $statePath -BackoffUntil $until -Reason 'pid=9056 exited early, code 0'
    $read = Get-BackoffUntil (Read-WatchdogState -Path $statePath)
    Check 'state round trip keeps back-off time' ($null -ne $read -and [math]::Abs(($read - $until).TotalSeconds) -lt 1) "$read vs $until"

    $recordPath = Join-Path $tmp 'instance.json'
    Set-Content -LiteralPath $recordPath -Value '{"pid": 4242, "process_name": "pythonw.exe", "started_unix": 1795000000.5, "kind": "source"}'
    $r = Read-InstanceRecord -Path $recordPath
    Check 'instance record parses' ($null -ne $r -and $r.pid -eq 4242 -and $r.kind -eq 'source')
    Set-Content -LiteralPath $recordPath -Value 'not json'
    Check 'corrupt instance record -> null' ($null -eq (Read-InstanceRecord -Path $recordPath))
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output ("{0} passed, {1} failed" -f $passed, $failures.Count)
if ($failures.Count -gt 0) { exit 1 }
exit 0
