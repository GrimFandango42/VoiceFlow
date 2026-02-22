param(
    [string]$PythonExe = "",
    [string]$OutputName = "VoiceFlow",
    [switch]$Clean,
    [switch]$OneFile,
    [switch]$Console,
    [switch]$InstallPackagingDeps,
    [switch]$SkipCudaRuntime
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Test-IcoHeader {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return $false
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -lt 4) {
            return $false
        }
        return ($bytes[0] -eq 0 -and $bytes[1] -eq 0 -and $bytes[2] -eq 1 -and $bytes[3] -eq 0)
    } catch {
        return $false
    }
}

function Remove-ConflictingRuntimeDlls {
    param([string]$BundleRoot)

    $internalRoot = Join-Path $BundleRoot "_internal"
    if (-not (Test-Path $internalRoot)) {
        return
    }

    # The PyInstaller-collected MSVCP runtime can crash at startup on some systems
    # (APPCRASH in _internal\MSVCP140.dll). Prefer the system-installed VC runtime.
    $conflictingDlls = @(
        "MSVCP140.dll",
        "msvcp140.dll",
        "MSVCP140_1.dll",
        "msvcp140_1.dll"
    )

    foreach ($dll in $conflictingDlls) {
        $candidate = Join-Path $internalRoot $dll
        if (Test-Path $candidate) {
            Remove-Item -Path $candidate -Force -ErrorAction SilentlyContinue
            Write-Host "[build_windows_exe] Removed conflicting runtime: $candidate"
        }
    }
}

function Remove-DuplicateCudaDlls {
    param([string]$BundleRoot)

    $internalRoot = Join-Path $BundleRoot "_internal"
    $torchLib = Join-Path $internalRoot "torch\lib"
    if (-not (Test-Path $internalRoot) -or -not (Test-Path $torchLib)) {
        return
    }

    $patterns = @(
        "cudnn*.dll",
        "cublas*.dll",
        "cudart*.dll",
        "cufft*.dll",
        "curand*.dll",
        "cusolver*.dll",
        "cusparse*.dll",
        "nvrtc*.dll",
        "nvJitLink*.dll",
        "zlibwapi.dll"
    )

    $removed = 0
    foreach ($pattern in $patterns) {
        Get-ChildItem -Path $internalRoot -Filter $pattern -File -ErrorAction SilentlyContinue | ForEach-Object {
            $rootDll = $_
            $torchDll = Join-Path $torchLib $rootDll.Name
            if (Test-Path $torchDll) {
                $rootLen = (Get-Item $rootDll.FullName).Length
                $torchLen = (Get-Item $torchDll).Length
                if ($rootLen -eq $torchLen) {
                    Remove-Item -Path $rootDll.FullName -Force -ErrorAction SilentlyContinue
                    $removed += 1
                    Write-Host "[build_windows_exe] Removed duplicate CUDA runtime: $($rootDll.Name)"
                }
            }
        }
    }

    if ($removed -gt 0) {
        Write-Host ("[build_windows_exe] Removed duplicate CUDA DLL copies: {0}" -f $removed)
    }
}

function Get-CudaRuntimeDlls {
    param(
        [string]$RepoRoot,
        [string]$PythonExe
    )

    $candidates = @()
    if ($env:VOICEFLOW_TORCH_LIB_DIR) {
        $candidates += $env:VOICEFLOW_TORCH_LIB_DIR
    }

    try {
        $pyPrefix = (& $PythonExe -c "import sys; print(sys.prefix)" 2>$null | Select-Object -First 1)
        if ($pyPrefix) {
            $prefixPath = $pyPrefix.ToString().Trim()
            if ($prefixPath) {
                $candidates += (Join-Path $prefixPath "Lib\site-packages\torch\lib")
            }
        }
    } catch {
        # no-op
    }

    $candidates += (Join-Path $RepoRoot ".venv-gpu\Lib\site-packages\torch\lib")
    $candidates += (Join-Path $RepoRoot "venv\Lib\site-packages\torch\lib")
    $candidates += (Join-Path $RepoRoot ".venv\Lib\site-packages\torch\lib")

    $patterns = @(
        "cudnn*.dll",
        "cublas64_*.dll",
        "cublasLt64_*.dll",
        "cudart64_*.dll",
        "cufft64_*.dll",
        "curand64_*.dll",
        "cusolver64_*.dll",
        "cusparse64_*.dll",
        "nvrtc64_*.dll",
        "zlibwapi.dll"
    )

    $files = New-Object System.Collections.Generic.List[string]
    $seenDirs = @{}
    foreach ($dir in $candidates) {
        if (-not $dir) {
            continue
        }
        $full = [System.IO.Path]::GetFullPath($dir)
        $key = $full.ToLowerInvariant()
        if ($seenDirs.ContainsKey($key)) {
            continue
        }
        $seenDirs[$key] = $true
        if (-not (Test-Path $full)) {
            continue
        }
        foreach ($pattern in $patterns) {
            Get-ChildItem -Path $full -Filter $pattern -File -ErrorAction SilentlyContinue | ForEach-Object {
                $files.Add($_.FullName)
            }
        }
    }

    return $files | Sort-Object -Unique
}

function Compress-ArchiveWithRetry {
    param(
        [string[]]$Path,
        [string]$DestinationPath,
        [int]$MaxAttempts = 6,
        [int]$DelaySeconds = 2
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            if (Test-Path $DestinationPath) {
                Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue
            }
            Compress-Archive -Path $Path -DestinationPath $DestinationPath -Force -ErrorAction Stop
            return $true
        } catch {
            $message = $_.Exception.Message
            if ($attempt -lt $MaxAttempts) {
                Write-Warning ("[build_windows_exe] Zip attempt {0}/{1} failed: {2}" -f $attempt, $MaxAttempts, $message)
                Write-Host ("[build_windows_exe] Retrying zip in {0}s..." -f $DelaySeconds)
                Start-Sleep -Seconds $DelaySeconds
            } else {
                Write-Warning ("[build_windows_exe] Failed to create zip after {0} attempts: {1}" -f $MaxAttempts, $message)
                return $false
            }
        }
    }

    return $false
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
    "--collect-submodules", "voiceflow.core",
    "--collect-submodules", "voiceflow.ui",
    "--collect-submodules", "voiceflow.integrations",
    "--collect-submodules", "voiceflow.utils",
    "--collect-submodules", "voiceflow.ai",
    "--collect-submodules", "voiceflow.models",
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
    "--hidden-import", "pyperclip",
    "--exclude-module", "torch",
    "--exclude-module", "torchvision",
    "--exclude-module", "torchaudio",
    "--exclude-module", "onnxruntime",
    "--exclude-module", "triton",
    "--exclude-module", "xformers",
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
if (Test-IcoHeader -Path $iconPath) {
    $args += @("--icon", $iconPath)
} elseif (Test-Path $iconPath) {
    Write-Warning "[build_windows_exe] icon.ico exists but is not a valid ICO; building without custom icon."
}

if (-not $SkipCudaRuntime) {
    $cudaDlls = Get-CudaRuntimeDlls -RepoRoot $repoRoot -PythonExe $pythonExe
    if ($cudaDlls -and $cudaDlls.Count -gt 0) {
        foreach ($dll in $cudaDlls) {
            # Bundle CUDA runtime DLLs when available so packaged builds can run GPU path
            # without depending on system-wide torch installs.
            # Keep them under torch/lib to avoid duplicate giant DLL copies at bundle root.
            $args += @("--add-binary", ($dll + ";torch/lib"))
        }
        Write-Host ("[build_windows_exe] Bundling CUDA runtime DLLs: {0}" -f $cudaDlls.Count)
    } else {
        Write-Host "[build_windows_exe] No CUDA runtime DLLs found; package will run CPU-only unless host provides them."
    }
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
    Write-Host "[build_windows_exe] Built one-file executable: $oneFileExe"
    if (Compress-ArchiveWithRetry -Path @($oneFileExe) -DestinationPath $zipOut) {
        Write-Host "[build_windows_exe] Zip artifact: $zipOut"
    } else {
        Write-Warning "[build_windows_exe] Continuing without zip artifact. One-file EXE is still available."
    }
} else {
    if (-not (Test-Path $bundleRoot)) {
        throw "Expected output bundle not found: $bundleRoot"
    }
    Remove-ConflictingRuntimeDlls -BundleRoot $bundleRoot
    Remove-DuplicateCudaDlls -BundleRoot $bundleRoot
    $zipOut = Join-Path $packagePath "$OutputName-$timestamp-portable.zip"
    Write-Host "[build_windows_exe] Built bundled executable: $(Join-Path $bundleRoot "$OutputName.exe")"
    if (Compress-ArchiveWithRetry -Path @((Join-Path $bundleRoot "*")) -DestinationPath $zipOut) {
        Write-Host "[build_windows_exe] Zip artifact: $zipOut"
    } else {
        Write-Warning "[build_windows_exe] Continuing without zip artifact. Bundled build directory is still available."
    }
}
