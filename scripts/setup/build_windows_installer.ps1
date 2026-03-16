param(
    [string]$PythonExe = "",
    [string]$AppVersion = "",
    [string]$IsccPath = "",
    [switch]$SkipBuild,
    [switch]$InstallInnoSetup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-IsccPath {
    param([string]$ExplicitPath)

    if ($ExplicitPath -and (Test-Path $ExplicitPath)) {
        return $ExplicitPath
    }

    $known = @(
        "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )
    foreach ($candidate in $known) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    try {
        $cmd = Get-Command ISCC.exe -ErrorAction Stop
        if ($cmd -and $cmd.Source) {
            return $cmd.Source
        }
    } catch {
        # no-op
    }

    return ""
}

function Resolve-AppVersion {
    param(
        [string]$RepoRoot,
        [string]$ExplicitVersion
    )

    if ($ExplicitVersion) {
        return $ExplicitVersion
    }

    $pyproject = Join-Path $RepoRoot "pyproject.toml"
    if (Test-Path $pyproject) {
        $match = Select-String -Path $pyproject -Pattern '^\s*version\s*=\s*"([^"]+)"' | Select-Object -First 1
        if ($match -and $match.Matches.Count -gt 0) {
            return $match.Matches[0].Groups[1].Value
        }
    }

    throw "Unable to resolve AppVersion. Pass -AppVersion explicitly or define [project].version in pyproject.toml."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$AppVersion = Resolve-AppVersion -RepoRoot $repoRoot -ExplicitVersion $AppVersion
$bundleDir = Join-Path $repoRoot "dist\VoiceFlow"
$issFile = Join-Path $repoRoot "packaging\windows\VoiceFlowSetup.iss"

if (-not $SkipBuild) {
    $buildScript = Join-Path $repoRoot "scripts\setup\build_windows_exe.ps1"
    if (-not (Test-Path $buildScript)) {
        throw "Build script not found: $buildScript"
    }
    Write-Host "[build_windows_installer] Building executable bundle first..."
    & powershell -NoProfile -ExecutionPolicy Bypass -File $buildScript -PythonExe $PythonExe -Clean
}

if (-not (Test-Path $bundleDir)) {
    throw "Expected executable bundle not found: $bundleDir"
}
if (-not (Test-Path $issFile)) {
    throw "Installer script not found: $issFile"
}

if ($InstallInnoSetup) {
    Write-Host "[build_windows_installer] Installing Inno Setup via Chocolatey..."
    choco install innosetup -y --no-progress
}

$iscc = Resolve-IsccPath -ExplicitPath $IsccPath
if (-not $iscc) {
    throw @"
Inno Setup compiler (ISCC.exe) not found.
Install Inno Setup 6: https://jrsoftware.org/isdl.php
or run this script with -InstallInnoSetup (requires Chocolatey).
"@
}

Write-Host "[build_windows_installer] ISCC: $iscc"
Write-Host "[build_windows_installer] AppVersion: $AppVersion"

$outputDir = Join-Path $repoRoot "dist\installer"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

& $iscc "/DAppVersion=$AppVersion" "/DRepoRoot=$repoRoot" "/DSourceDir=$bundleDir" $issFile

$installer = Get-ChildItem -Path $outputDir -Filter "VoiceFlow-Setup-*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $installer) {
    throw "Installer build did not produce an output in $outputDir"
}

Write-Host "[build_windows_installer] Installer ready: $($installer.FullName)"
