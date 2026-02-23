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

if ($killed.Count -gt 0) {
    Write-Info ("[cleanup] Stopped VoiceFlow process IDs: " + ($killed -join ", "))
} else {
    Write-Info "[cleanup] No stale VoiceFlow processes found."
}
