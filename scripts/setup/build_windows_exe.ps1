Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

param(
    [string]$PythonExe = "",
    [string]$OutputName = "VoiceFlow",
    [switch]$Clean,
    [switch]$OneFile,
    [switch]$Console,
    [switch]$InstallPackagingDeps
)

function Resolve-PythonExe {
    param([string]$RepoRoot, [string]$ExplicitPython)

    if ($ExplicitPython) {
        return $ExplicitPython
    }

    $preferGpu = $true
    if ($env:VOICEFLOW_USE_GPU_VENV -and $env:VOICEFLOW_USE_GPU_VENV.Trim().ToLower() -eq "0") {
        $preferGpu = $false
    }

    $gpuPython = Join-Path $RepoRoot ".venv-gpu\Scripts\python.exe"
    $venvPython = Join-Path $RepoRoot "venv\Scripts\python.exe"

    if ($preferGpu -and (Test-Path $gpuPython)) {
        return $gpuPython
    }
    if (Test-Path $venvPython) {
        return $venvPython
    }
    return "python"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$pythonExe = Resolve-PythonExe -RepoRoot $repoRoot -ExplicitPython $PythonExe

Write-Host "[build_windows_exe] repo: $repoRoot"
Write-Host "[build_windows_exe] python: $pythonExe"

if ($InstallPackagingDeps) {
    Write-Host "[build_windows_exe] Installing packaging dependencies..."
    & $pythonExe -m pip install --upgrade pip
    & $pythonExe -m pip install pyinstaller pyinstaller-hooks-contrib
}

$entryScript = Join-Path $repoRoot "scripts\setup\voiceflow_exe_entry.py"
if (-not (Test-Path $entryScript)) {
    throw "Entrypoint not found: $entryScript"
}

$iconPath = Join-Path $repoRoot "icon.ico"
$srcPath = Join-Path $repoRoot "src"
$distPath = Join-Path $repoRoot "dist"
$workPath = Join-Path $repoRoot "build\pyinstaller"
$specPath = Join-Path $workPath "spec"
$packagePath = Join-Path $distPath "packages"

New-Item -ItemType Directory -Path $workPath -Force | Out-Null
New-Item -ItemType Directory -Path $specPath -Force | Out-Null
New-Item -ItemType Directory -Path $packagePath -Force | Out-Null

$args = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--name", $OutputName,
    "--paths", $srcPath,
    "--collect-submodules", "voiceflow",
    "--collect-data", "voiceflow",
    "--hidden-import", "PIL._tkinter_finder",
    "--hidden-import", "win32api",
    "--hidden-import", "win32con",
    "--hidden-import", "win32gui",
    "--hidden-import", "pythoncom",
    "--hidden-import", "pywintypes",
    "--hidden-import", "keyboard",
    "--hidden-import", "pystray",
    "--hidden-import", "sounddevice",
    "--hidden-import", "faster_whisper",
    "--hidden-import", "ctranslate2",
    "--hidden-import", "torch",
    "--hidden-import", "pyperclip",
    "--add-data", ((Join-Path $repoRoot "docs\examples\engineering_terms.json") + ";defaults"),
    "--add-data", ((Join-Path $repoRoot "docs\examples\technical_terms.json") + ";defaults"),
    "--distpath", $distPath,
    "--workpath", $workPath,
    "--specpath", $specPath
)

if ($Clean) {
    $args += "--clean"
}
if ($OneFile) {
    $args += "--onefile"
}
if ($Console) {
    $args += "--console"
} else {
    $args += "--windowed"
}
if (Test-Path $iconPath) {
    $args += @("--icon", $iconPath)
}

$args += $entryScript

Write-Host "[build_windows_exe] Running PyInstaller..."
& $pythonExe @args

$bundleRoot = Join-Path $distPath $OutputName
$oneFileExe = Join-Path $distPath "$OutputName.exe"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

if ($OneFile) {
    if (-not (Test-Path $oneFileExe)) {
        throw "Expected output not found: $oneFileExe"
    }
    $zipOut = Join-Path $packagePath "$OutputName-$timestamp-onefile.zip"
    Compress-Archive -Path $oneFileExe -DestinationPath $zipOut -Force
    Write-Host "[build_windows_exe] Built one-file executable: $oneFileExe"
    Write-Host "[build_windows_exe] Zip artifact: $zipOut"
} else {
    if (-not (Test-Path $bundleRoot)) {
        throw "Expected output bundle not found: $bundleRoot"
    }
    $zipOut = Join-Path $packagePath "$OutputName-$timestamp-portable.zip"
    Compress-Archive -Path (Join-Path $bundleRoot "*") -DestinationPath $zipOut -Force
    Write-Host "[build_windows_exe] Built bundled executable: $(Join-Path $bundleRoot "$OutputName.exe")"
    Write-Host "[build_windows_exe] Zip artifact: $zipOut"
}

