param(
    [switch]$Quiet
)

$ErrorActionPreference = "SilentlyContinue"

function Write-Info {
    param([string]$Message)
    if (-not $Quiet) {
        Write-Host $Message
    }
}

$killed = @()

$targets = Get-CimInstance Win32_Process | Where-Object {
    $name = [string]$_.Name
    $cmd = [string]$_.CommandLine
    ($name -match "(?i)^voiceflow.*\.exe$") -or
    ($name -ieq "python.exe" -and $cmd -match "voiceflow\.ui\.cli_enhanced") -or
    ($name -ieq "pythonw.exe" -and ($cmd -match "launcher_silent" -or $cmd -match "voiceflow\.ui\.cli_enhanced"))
}

foreach ($proc in $targets) {
    try {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
        $killed += [int]$proc.ProcessId
    } catch {
        # Ignore races where process exits naturally before kill.
    }
}

Start-Sleep -Milliseconds 350

$remaining = Get-CimInstance Win32_Process | Where-Object {
    $name = [string]$_.Name
    $cmd = [string]$_.CommandLine
    ($name -match "(?i)^voiceflow.*\.exe$") -or
    ($name -ieq "python.exe" -and $cmd -match "voiceflow\.ui\.cli_enhanced") -or
    ($name -ieq "pythonw.exe" -and ($cmd -match "launcher_silent" -or $cmd -match "voiceflow\.ui\.cli_enhanced"))
}

if ($remaining.Count -gt 0) {
    foreach ($proc in $remaining) {
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
            $killed += [int]$proc.ProcessId
        } catch {
            # Ignore final races.
        }
    }
    Start-Sleep -Milliseconds 200
}

$stillRunning = Get-CimInstance Win32_Process | Where-Object {
    $name = [string]$_.Name
    $cmd = [string]$_.CommandLine
    ($name -match "(?i)^voiceflow.*\.exe$") -or
    ($name -ieq "python.exe" -and $cmd -match "voiceflow\.ui\.cli_enhanced") -or
    ($name -ieq "pythonw.exe" -and ($cmd -match "launcher_silent" -or $cmd -match "voiceflow\.ui\.cli_enhanced"))
}

if ($killed.Count -gt 0) {
    $unique = $killed | Sort-Object -Unique
    Write-Info ("[cleanup] Stopped VoiceFlow process IDs: " + ($unique -join ", "))
} else {
    Write-Info "[cleanup] No stale VoiceFlow processes found."
}

if ($stillRunning.Count -gt 0) {
    $ids = ($stillRunning | ForEach-Object { [int]$_.ProcessId }) -join ", "
    Write-Info ("[cleanup] Warning: VoiceFlow-related processes still running: " + $ids)
}
