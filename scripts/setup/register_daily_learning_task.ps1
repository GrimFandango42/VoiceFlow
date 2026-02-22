param(
    [string]$TaskName = "VoiceFlow-DailyLearning",
    [string]$StartTime = "08:00",
    [int]$DaysBack = 1,
    [switch]$DryRun,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$batchPath = Join-Path $repoRoot "VoiceFlow_DailyLearning.bat"
if (-not (Test-Path $batchPath)) {
    throw "Batch file not found: $batchPath"
}

if ($DaysBack -lt 1) {
    throw "DaysBack must be >= 1"
}

$batchArgs = "--days-back $DaysBack"
if ($DryRun) {
    $batchArgs += " --dry-run"
}

$cmdArgs = "/c `"$batchPath`" $batchArgs"
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $cmdArgs -WorkingDirectory $repoRoot
$trigger = New-ScheduledTaskTrigger -Daily -At $StartTime
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

$userId = "$env:USERDOMAIN\$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    if (-not $Force) {
        throw "Scheduled task '$TaskName' already exists. Re-run with -Force to replace it."
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "VoiceFlow daily adaptive learning job (previous-day conversation analysis)."

$info = Get-ScheduledTaskInfo -TaskName $TaskName
Write-Output "Registered scheduled task: $TaskName"
Write-Output "  User: $userId"
Write-Output "  Start time: $StartTime (daily)"
Write-Output "  Last run: $($info.LastRunTime)"
Write-Output "  Next run: $($info.NextRunTime)"
Write-Output "  Command: cmd.exe $cmdArgs"
