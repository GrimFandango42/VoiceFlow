param(
    [switch]$GpuVenv,
    [switch]$SkipSmoke
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repoRoot

$venvName = if ($GpuVenv) { ".venv-gpu" } else { "venv" }
$venvPath = Join-Path $repoRoot $venvName
$pythonExe = Join-Path $venvPath "Scripts\python.exe"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "VoiceFlow Windows Bootstrap" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Repo: $repoRoot"
Write-Host "Environment: $venvName"
Write-Host ""

if (-not (Test-Path $pythonExe)) {
    Write-Host "[1/4] Creating virtual environment: $venvName" -ForegroundColor Yellow
    py -3 -m venv $venvName
} else {
    Write-Host "[1/4] Virtual environment exists: $venvName" -ForegroundColor Green
}

Write-Host "[2/4] Upgrading pip" -ForegroundColor Yellow
& $pythonExe -m pip install --upgrade pip

Write-Host "[3/4] Installing requirements" -ForegroundColor Yellow
& $pythonExe -m pip install -r "scripts\setup\requirements_windows.txt"

if (-not $SkipSmoke) {
    Write-Host "[4/4] Running smoke check" -ForegroundColor Yellow
    & $pythonExe "scripts\dev\quick_smoke_test.py"
    if ($LASTEXITCODE -ne 0) {
        throw "Smoke check failed (exit code $LASTEXITCODE)."
    }
} else {
    Write-Host "[4/4] Smoke check skipped (--SkipSmoke)" -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "Bootstrap complete." -ForegroundColor Green
Write-Host "Launch with: .\VoiceFlow_Quick.bat" -ForegroundColor Green
