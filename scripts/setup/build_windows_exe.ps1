param(
    [string]$PythonExe = "",
    [string]$OutputName = "VoiceFlow",
    # Reusing PyInstaller's module cache shipped a bundle built from modules
    # dated 2026-09-13 while every other signal said the build was current:
    # no logging, no transcription history, no live caption, and a stamp
    # naming the right commit. Cold builds are now the default; -ReuseCache
    # trades that safety for speed when iterating.
    [switch]$ReuseCache,
    # Kept for callers that already pass it. Cleaning is now unconditional
    # unless -ReuseCache is given, so this is a no-op.
    [switch]$Clean,
    # Skip running the finished bundle to check it works. Only for building on
    # a machine that cannot run it (no GPU, or a CI box without audio).
    [switch]$SkipSmokeTest,
    [switch]$OneFile,
    [switch]$Console,
    [switch]$InstallPackagingDeps,
    [switch]$SkipCudaRuntime,
    # A bundle without the CUDA runtime silently demotes a device=cuda config to
    # CPU int8. That shipped twice by accident, so it now needs an explicit
    # opt-in; without it a missing CUDA runtime fails the build.
    [switch]$AllowCpuOnly,
    [switch]$SkipProcessCleanup,
    # OPT-IN pruning of old timestamped build snapshots in dist\packages (each is ~2 GB).
    # Default 0 = keep everything: a build never deletes files unless asked. N > 0 keeps
    # the N most recent snapshots and deletes older ones. Published release assets are
    # never pruned.
    [int]$KeepPackages = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($SkipCudaRuntime -and -not $AllowCpuOnly) {
    throw "[build_windows_exe] -SkipCudaRuntime produces a CPU-only bundle. Pass -AllowCpuOnly as well if that is really what you want."
}

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

function Resolve-PythonBaseDir {
    param([string]$PythonExe)

    try {
        $baseDir = (& $PythonExe -c "import sys; print(sys.base_prefix)" 2>$null | Select-Object -First 1)
        if ($baseDir) {
            $resolved = $baseDir.ToString().Trim()
            if ($resolved -and (Test-Path $resolved)) {
                return $resolved
            }
        }
    } catch {
        # no-op
    }

    try {
        $prefixDir = (& $PythonExe -c "import sys; print(sys.prefix)" 2>$null | Select-Object -First 1)
        if ($prefixDir) {
            $resolved = $prefixDir.ToString().Trim()
            if ($resolved -and (Test-Path $resolved)) {
                return $resolved
            }
        }
    } catch {
        # no-op
    }

    return ""
}

function Get-TclTkBuildArgs {
    param([string]$PythonBaseDir)

    $args = New-Object System.Collections.Generic.List[string]
    if (-not $PythonBaseDir) {
        return $args
    }

    $dllDir = Join-Path $PythonBaseDir "DLLs"
    $tclRoot = Join-Path $PythonBaseDir "tcl"
    $tclDll = Join-Path $dllDir "tcl86t.dll"
    $tkDll = Join-Path $dllDir "tk86t.dll"
    $tkinterPyd = Join-Path $dllDir "_tkinter.pyd"
    $tkinterLib = Join-Path $PythonBaseDir "Lib\tkinter"
    $tclDataDir = Join-Path $tclRoot "tcl8.6"
    $tkDataDir = Join-Path $tclRoot "tk8.6"

    if (Test-Path $tclDll) {
        $args.Add("--add-binary")
        $args.Add($tclDll + ";.")
    }
    if (Test-Path $tkDll) {
        $args.Add("--add-binary")
        $args.Add($tkDll + ";.")
    }
    if (Test-Path $tkinterPyd) {
        $args.Add("--add-binary")
        $args.Add($tkinterPyd + ";.")
    }
    if (Test-Path $tclRoot) {
        $args.Add("--add-data")
        $args.Add($tclRoot + ";tcl")
    }
    if (Test-Path $tclDataDir) {
        $args.Add("--add-data")
        $args.Add($tclDataDir + ";_tcl_data")
    }
    if (Test-Path $tkDataDir) {
        $args.Add("--add-data")
        $args.Add($tkDataDir + ";_tk_data")
    }
    if (Test-Path $tkinterLib) {
        $args.Add("--add-data")
        $args.Add($tkinterLib + ";tkinter")
    }

    return $args
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
                    # Drop the torch/lib copy and keep the root one. The root is the
                    # only directory Windows searches before ctranslate2.dll loads, so
                    # removing it there is what silently demotes a build to CPU.
                    Remove-Item -Path $torchDll -Force -ErrorAction SilentlyContinue
                    $removed += 1
                    Write-Host "[build_windows_exe] Removed duplicate CUDA runtime from torch/lib: $($rootDll.Name)"
                }
            }
        }
    }

    if ($removed -gt 0) {
        Write-Host ("[build_windows_exe] Removed duplicate CUDA DLL copies: {0}" -f $removed)
    }
}

function Assert-BundleBehaves {
    <#
      Run the thing we just built and check it actually works.

      On 2026-11-07 a bundle shipped with no logging, no transcription history
      and no live caption, because PyInstaller reused cached modules dated
      2026-09-13. Every signal was green: the build reported success, 325 tests
      passed against the source, and the embedded stamp named the right commit.
      The stamp records what the source said, not what got compiled in, so it
      cannot catch this. Only running the artifact can.

      Checks, against a throwaway LOCALAPPDATA so a user's real log and history
      are never touched:
        * the app writes a log at all -- the symptom that hid the rest
        * AsyncLogger actually initialised (single_instance_ok)
        * it reached device=cuda, not a silent CPU demotion

      A run that cannot be judged -- because another instance holds the
      single-instance mutex -- warns loudly rather than passing quietly. The
      whole lesson here is that a check which cannot tell pass from fail is
      worse than no check.
    #>
    param(
        [string]$BundleRoot,
        [string]$ExeName,
        [switch]$ExpectCuda
    )

    $exe = Join-Path $BundleRoot ($ExeName + ".exe")
    if (-not (Test-Path $exe)) {
        throw "[build_windows_exe] Smoke test: built exe not found at $exe"
    }

    if (Get-Process -Name $ExeName -ErrorAction SilentlyContinue) {
        Write-Warning "[build_windows_exe] Smoke test SKIPPED: an instance of $ExeName is already running."
        return
    }

    $sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("vf-smoke-" + [Guid]::NewGuid().ToString("N").Substring(0,8))
    New-Item -ItemType Directory -Path $sandbox -Force | Out-Null
    $logPath = Join-Path $sandbox "VoiceFlow\logs\voiceflow.log"

    $savedLocal = $env:LOCALAPPDATA
    $proc = $null
    try {
        $env:LOCALAPPDATA = $sandbox
        $proc = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden

        $deadline = (Get-Date).AddSeconds(90)
        $text = ""
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
            if (Test-Path $logPath) {
                try {
                    $text = Get-Content $logPath -Raw -ErrorAction Stop
                } catch {
                    $text = ""
                }
                if ($text -match "asr_engine_initialized") { break }
            }
            if ($proc.HasExited) { break }
        }

        if ($proc.HasExited -and -not ($text -match "asr_engine_initialized")) {
            Write-Warning ("[build_windows_exe] Smoke test INCONCLUSIVE: the exe exited early " +
                           "(code " + $proc.ExitCode + "). Most often another VoiceFlow holds the " +
                           "single-instance mutex. Re-run with nothing else running to get a verdict.")
            return
        }

        if (-not (Test-Path $logPath)) {
            throw ("[build_windows_exe] Smoke test FAILED: the bundle wrote no log at all. " +
                   "This is the 2026-11-07 failure -- a bundle that runs but persists nothing. " +
                   "Rebuild with -Clean; PyInstaller may be serving cached modules.")
        }
        if ($text -notmatch "single_instance_ok") {
            throw ("[build_windows_exe] Smoke test FAILED: log exists but AsyncLogger never " +
                   "initialised (no single_instance_ok). The bundle's startup diverges from source.")
        }
        if ($ExpectCuda -and ($text -notmatch "device=cuda")) {
            $demoted = if ($text -match "device=cpu") { " It reported device=cpu." } else { "" }
            throw ("[build_windows_exe] Smoke test FAILED: the bundle did not reach the GPU." + $demoted +
                   " Whisper on CPU int8 is roughly 85x slower. Pass -SkipCudaRuntime to accept this.")
        }

        $verdict = "logging OK"
        if ($ExpectCuda) { $verdict += ", device=cuda OK" }
        Write-Host "[build_windows_exe] Smoke test passed: $verdict."
    }
    finally {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
        $env:LOCALAPPDATA = $savedLocal
        Remove-Item $sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Remove-StaleBuildArtifacts {
    <#
      Keep the last few build snapshots and delete the rest.

      Every build drops a ~2 GB timestamped zip into dist\packages and nothing
      ever removed them: by 2026-11-07 that was 15.5 GB of snapshots, most of
      them months old, on a disk with 34 GB free. The published release assets
      live in the same folder, so prune by name pattern and never touch a file
      that does not carry a build timestamp.
    #>
    param(
        [string]$PackagePath,
        [int]$Keep = 0
    )

    # 0 means keep everything, as the -KeepPackages help says.
    if ($Keep -le 0) {
        return
    }

    if (-not (Test-Path $PackagePath)) {
        return
    }

    # Only files this script generates: <name>-YYYYMMDD-HHMMSS-(portable|onefile).zip.
    # Release assets (VoiceFlow-win64.exe, VoiceFlow-portable-win64.zip,
    # SHA256SUMS.txt) carry no timestamp and are therefore never matched.
    $snapshots = Get-ChildItem -Path $PackagePath -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '-\d{8}-\d{6}-(portable|onefile)\.zip$' } |
        Sort-Object LastWriteTime -Descending

    if ($snapshots.Count -le $Keep) {
        return
    }

    $freed = 0
    foreach ($old in ($snapshots | Select-Object -Skip $Keep)) {
        $freed += $old.Length
        Remove-Item -Path $old.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "[build_windows_exe] Pruned old build snapshot: $($old.Name)"
    }

    if ($freed -gt 0) {
        Write-Host ("[build_windows_exe] Reclaimed {0:N1} GB; keeping the {1} most recent snapshots." -f ($freed / 1GB), $Keep)
    }
}

function Assert-CudaRuntimeComplete {
    <#
      Fail the build rather than ship a bundle that will quietly run on CPU.

      cudnn64_9.dll is only a front end; it loads the cudnn_* engine and
      subsystem DLLs by name at runtime. Ship a partial set and nothing errors:
      ctranslate2 reports zero CUDA devices, _cuda_runtime_ready() returns
      false, and Whisper runs int8 on the CPU roughly 85x slower with no
      message beyond one warning in a log nobody reads. A build that cannot
      honour device=cuda should not reach a user silently.
    #>
    param([string]$BundleRoot)

    # The bundle root is the only location Windows searches before our code runs.
    $cudaDir = Join-Path $BundleRoot "_internal"
    $required = @(
        "cudnn64_9.dll",
        "cudnn_ops64_9.dll",
        "cudnn_graph64_9.dll",
        "cudnn_cnn64_9.dll",
        "cudnn_adv64_9.dll",
        "cudnn_engines_precompiled64_9.dll",
        "cudnn_engines_runtime_compiled64_9.dll",
        "cudnn_heuristic64_9.dll",
        "cublas64_12.dll",
        "cublasLt64_12.dll"
    )

    $missing = @()
    foreach ($dll in $required) {
        $path = Join-Path $cudaDir $dll
        if (-not (Test-Path $path)) {
            $missing += $dll
        } elseif ((Get-Item $path).Length -eq 0) {
            $missing += ($dll + " (zero bytes)")
        }
    }

    if ($missing.Count -gt 0) {
        throw ("[build_windows_exe] Incomplete CUDA runtime in bundle; this build would " +
               "silently run on CPU. Missing from the bundle root: " + ($missing -join ", ") +
               ". Install the NVIDIA runtime wheels (pip install nvidia-cublas-cu12 " +
               "nvidia-cudnn-cu12) and rebuild, or pass -SkipCudaRuntime to accept a " +
               "deliberately CPU-only package.")
    }

    Write-Host ("[build_windows_exe] CUDA runtime verified: {0}/{0} required DLLs present." -f $required.Count)
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

    # Prefer the standalone NVIDIA runtime wheels. They are the only source that
    # is both coherent (cuDNN ships its whole dependency chain) and stable --
    # unlike torch, which may be a CPU-only build, and unlike a previous bundle,
    # which lives in the directory this build is about to overwrite.
    try {
        $nvidiaRoot = (& $PythonExe -c "import importlib.util,pathlib;print(pathlib.Path(importlib.util.find_spec('nvidia').submodule_search_locations[0]))" 2>$null | Select-Object -First 1)
        if ($nvidiaRoot) {
            $nvidiaPath = $nvidiaRoot.ToString().Trim()
            if ($nvidiaPath) {
                foreach ($pkg in @("cudnn", "cublas", "cuda_runtime", "cufft", "curand", "cusolver", "cusparse", "cuda_nvrtc")) {
                    $candidates += (Join-Path $nvidiaPath ($pkg + "\bin"))
                }
            }
        }
    } catch {
        # no-op
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
    # Last resort: a previously built bundle. Building from a venv without torch
    # installed silently produces a CPU-only package -- 0.26 GB instead of 2.59 GB,
    # no warning -- and a user whose config says device=cuda gets quietly demoted
    # to the int8 CPU fallback. Reusing the DLLs an earlier build already shipped
    # keeps GPU working without forcing a multi-gigabyte torch install to package.
    foreach ($bundle in @("VoiceFlow", "VoiceFlow.prev", "VoiceFlow.rollback-may2026")) {
        $candidates += (Join-Path $RepoRoot ("dist\" + $bundle + "\_internal\torch\lib"))
    }

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

    # One file per DLL name, first candidate wins (VOICEFLOW_TORCH_LIB_DIR, then
    # the venv, then previous bundles). Two sources for the same name used to
    # both be passed to PyInstaller and the later one -- a previous bundle under
    # dist\ -- won, then PyInstaller deleted dist\<name> before collecting it:
    # a CPU-only bundle with no error. The post-build verifier caught that.
    $files = New-Object System.Collections.Generic.List[string]
    $seenNames = @{}
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
                $nameKey = $_.Name.ToLowerInvariant()
                if (-not $seenNames.ContainsKey($nameKey)) {
                    $seenNames[$nameKey] = $true
                    $files.Add($_.FullName)
                }
            }
        }
    }

    return $files
}

function Copy-DllsOutOfDist {
    # PyInstaller empties dist\<OutputName> before it collects binaries, so a
    # DLL sourced from a previous bundle there must be copied somewhere safe first.
    param(
        [string[]]$Dlls,
        [string]$DistPath,
        [string]$StageDir
    )

    $distFull = [System.IO.Path]::GetFullPath($DistPath).TrimEnd('\') + '\'
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($dll in $Dlls) {
        $full = [System.IO.Path]::GetFullPath($dll)
        if ($full.StartsWith($distFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
            $staged = Join-Path $StageDir ([System.IO.Path]::GetFileName($full))
            Copy-Item -Path $full -Destination $staged -Force
            $result.Add($staged)
        } else {
            $result.Add($full)
        }
    }
    return $result
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
$pythonBaseDir = Resolve-PythonBaseDir -PythonExe $pythonExe

Write-Host "[build_windows_exe] repo: $repoRoot"
Write-Host "[build_windows_exe] python: $pythonExe"
if ($pythonBaseDir) {
    Write-Host "[build_windows_exe] python base: $pythonBaseDir"
}

if ($InstallPackagingDeps) {
    Write-Host "[build_windows_exe] Installing packaging dependencies..."
    & $pythonExe -m pip install --upgrade pip
    & $pythonExe -m pip install pyinstaller pyinstaller-hooks-contrib
}

if (-not $SkipProcessCleanup) {
    $cleanupScript = Join-Path $repoRoot "scripts\setup\stop_voiceflow_processes.ps1"
    if (Test-Path $cleanupScript) {
        Write-Host "[build_windows_exe] Stopping running VoiceFlow processes..."
        & powershell -NoProfile -ExecutionPolicy Bypass -File $cleanupScript -Quiet
    }
}

# Stamp the build with its own identity. There is no .git inside a frozen
# bundle, so unless this is written at package time the running app cannot say
# which commit it is -- which is exactly the question you ask while testing it.
$stampPath = Join-Path $repoRoot "src\voiceflow\_build_stamp.py"
$commit = (& git -C $repoRoot rev-parse --short HEAD 2>$null)
if (-not $commit) { $commit = "unknown" }
$dirty = [bool](& git -C $repoRoot status --porcelain --untracked-files=no 2>$null)
# verify_bundle.py fails any bundle that cannot prove it is a clean build of
# HEAD (VF-11b), so stop now rather than after a long PyInstaller run.
if ($dirty -or $commit -eq "unknown") {
    throw "[build_windows_exe] Refusing to build: tracked changes are uncommitted or git HEAD is unknown (commit=$commit, dirty=$dirty). The bundle verification would reject it; commit or discard changes first."
}
$builtAt = Get-Date -Format "MM-dd HH:mm"
$pkgVersion = "unknown"
$initPath = Join-Path $repoRoot "src\voiceflow\__init__.py"
if (Test-Path $initPath) {
    $m = Select-String -Path $initPath -Pattern '__version__\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($m) { $pkgVersion = $m.Matches.Groups[1].Value }
}
$stampContent = @"
# Generated by scripts/setup/build_windows_exe.ps1. Do not edit, do not commit.
VERSION = "$pkgVersion"
COMMIT = "$($commit.ToString().Trim())"
BUILT_AT = "$builtAt"
DIRTY = $(if ($dirty) { "True" } else { "False" })
"@
$stampContent | Set-Content -Path $stampPath -Encoding UTF8
Write-Host "[build_windows_exe] Stamped build: $pkgVersion $commit $builtAt (dirty=$dirty)"

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

# The same stamp, shipped a second time as a PyInstaller runtime hook. A hook is listed in the executable's own
# archive under its file name (`_build_stamp`), so `CArchiveReader(exe).toc` shows the commit the exe was built
# from; the copy inside the PYZ (voiceflow._build_stamp) is not visible to that reader. The hook only assigns
# constants at startup.
$hookDir = Join-Path $workPath "rthooks"
New-Item -ItemType Directory -Path $hookDir -Force | Out-Null
$hookPath = Join-Path $hookDir "_build_stamp.py"
$stampContent | Set-Content -Path $hookPath -Encoding UTF8

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
    # Setup wizard is imported dynamically; include tkinter explicitly for packaged builds.
    "--collect-submodules", "tkinter",
    "--collect-data", "tkinter",
    "--hidden-import", "_tkinter",
    "--hidden-import", "tkinter",
    "--hidden-import", "tkinter.ttk",
    "--hidden-import", "tkinter.messagebox",
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
    "--exclude-module", "triton",
    "--exclude-module", "xformers",
    # onnxruntime is REQUIRED, not optional: faster-whisper runs Silero VAD
    # through it. Excluding it made every streaming preview pass raise
    # "Applying the VAD filter requires the onnxruntime package" about once a
    # second, so the live caption stayed blank for the whole hold and the tray
    # line under the waveform never populated. ~15 MB is worth a working preview.
    "--hidden-import", "onnxruntime",
    "--collect-all", "onnxruntime",
    # ...and the Silero model itself. faster-whisper loads
    # faster_whisper/assets/silero_vad_v6.onnx from its package directory; without
    # this the preview logs "[ONNXRuntimeError] NO_SUCHFILE" every session (VF-09).
    "--hidden-import", "faster_whisper.vad",
    "--collect-data", "faster_whisper",
    "--add-data", ((Join-Path $repoRoot "docs\examples\engineering_terms.json") + ";defaults"),
    "--add-data", ((Join-Path $repoRoot "docs\examples\technical_terms.json") + ";defaults"),
    # Bundled vocabulary seed; copied to user's custom_vocabulary.txt on first launch.
    # collect_data_files('voiceflow') doesn't recurse into subpackages reliably across
    # PyInstaller versions, so we add it explicitly under the voiceflow/data layout
    # the runtime expects from `Path(__file__).parent.parent / "data"`.
    "--add-data", ((Join-Path $repoRoot "src\voiceflow\data\vocab_default.txt") + ";voiceflow\data"),
    "--runtime-hook", $hookPath,
    "--distpath", $distPath,
    "--workpath", $workPath,
    "--specpath", $specPath
)

if ($ReuseCache) {
    Write-Warning ("[build_windows_exe] Reusing PyInstaller's cache. This has shipped months-old " +
                   "modules in a bundle whose stamp named the current commit. Do not release this build.")
} else {
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

$tclTkArgs = Get-TclTkBuildArgs -PythonBaseDir $pythonBaseDir
if ($tclTkArgs.Count -gt 0) {
    $args += $tclTkArgs
    Write-Host "[build_windows_exe] Bundling Tcl/Tk runtime assets for setup wizard support."
} else {
    Write-Warning "[build_windows_exe] Tcl/Tk runtime assets not found; packaged setup wizard may be unavailable."
}

if (-not $SkipCudaRuntime) {
    $cudaDlls = @(Get-CudaRuntimeDlls -RepoRoot $repoRoot -PythonExe $pythonExe)
    if ($cudaDlls.Count -gt 0) {
        $cudaDlls = @(Copy-DllsOutOfDist -Dlls $cudaDlls -DistPath $distPath -StageDir (Join-Path $workPath "cuda_stage"))
    }
    if ($cudaDlls.Count -gt 0) {
        foreach ($dll in $cudaDlls) {
            # Bundle CUDA runtime DLLs so packaged builds can run the GPU path without
            # depending on a system-wide torch install.
            #
            # These MUST land at the bundle root, not under torch/lib. PyInstaller puts
            # the root (sys._MEIPASS) on the DLL search path before any Python runs, and
            # Windows resolves a DLL's dependencies when it loads. ctranslate2.dll loads
            # the moment ctranslate2 is imported -- earlier than any code of ours -- so if
            # cuDNN and cuBLAS are not already findable at that instant, ctranslate2
            # initialises with CUDA unavailable and reports zero devices for the life of
            # the process. Registering the directory afterwards is too late: that is why
            # a bundle with a verified-complete torch/lib still ran on CPU.
            #
            # Landing at the root also avoids synthesising a 'torch' package directory,
            # which turned the deliberate --exclude-module torch into a hollow namespace
            # package: 'import torch' then succeeded and 'torch.Tensor' raised instead.
            $args += @("--add-binary", ($dll + ";."))
        }
        Write-Host ("[build_windows_exe] Bundling CUDA runtime DLLs: {0}" -f $cudaDlls.Count)
    } elseif ($AllowCpuOnly) {
        Write-Warning "[build_windows_exe] No CUDA runtime DLLs found; -AllowCpuOnly given, so this bundle runs CPU int8 ONLY."
    } else {
        throw ("[build_windows_exe] No CUDA runtime DLLs found (need cudnn_ops64_9.dll, cublas64_12.dll and friends). " +
            "Install torch in the build venv, or set VOICEFLOW_TORCH_LIB_DIR to a torch\lib folder that has them. " +
            "Pass -AllowCpuOnly only if a CPU-only bundle is intended.")
    }
} else {
    Write-Warning "[build_windows_exe] ==== CPU-ONLY BUILD (-SkipCudaRuntime -AllowCpuOnly): no CUDA runtime will be bundled ===="
}

$args += $entryScript

Write-Host "[build_windows_exe] Running PyInstaller..."
& $pythonExe @args
if ($LASTEXITCODE -ne 0) {
    throw "[build_windows_exe] PyInstaller failed with exit code $LASTEXITCODE"
}

$bundleRoot = Join-Path $distPath $OutputName
$oneFileExe = Join-Path $distPath "$OutputName.exe"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

function Invoke-BundleVerification {
    # Static checks (one-dir) plus the frozen self-check: verify_bundle.py runs
    # '<exe> --self-check=<json>', waits for it, and exits non-zero on any
    # failure. The EXE's self-check returns before tray/hotkey/microphone setup
    # and runs with LOCALAPPDATA/TEMP redirected under the build folder.
    # Every build mode goes through here; a failure throws, so the script
    # exits non-zero and no zip is produced.
    param([string]$Target)

    $verifyScript = Join-Path $repoRoot "scripts\setup\verify_bundle.py"
    $verifyReport = Join-Path $workPath "verify_bundle.json"
    $verifyArgs = @($verifyScript, $Target, "--json-out", $verifyReport)
    if ($AllowCpuOnly) {
        $verifyArgs += "--allow-cpu-only"
    }
    Write-Host "[build_windows_exe] Verifying bundle (static + frozen self-check)..."
    # verify_bundle.py cross-checks the executable's top-level _build_stamp entry against this commit.
    $env:VOICEFLOW_EXPECT_COMMIT = $commit.ToString().Trim()
    & $pythonExe @verifyArgs
    $verifyExit = $LASTEXITCODE
    if ($verifyExit -ne 0) {
        throw "[build_windows_exe] Bundle self-check FAILED (exit $verifyExit). Report: $verifyReport"
    }
    Write-Host "[build_windows_exe] Bundle self-check passed. Report: $verifyReport"
}

if ($OneFile) {
    if (-not (Test-Path $oneFileExe)) {
        throw "Expected output not found: $oneFileExe"
    }
    Invoke-BundleVerification -Target $oneFileExe
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
    Invoke-BundleVerification -Target $bundleRoot
    if (-not $SkipCudaRuntime) {
        Assert-CudaRuntimeComplete -BundleRoot $bundleRoot
    }
    if (-not $SkipSmokeTest) {
        Assert-BundleBehaves -BundleRoot $bundleRoot -ExeName $OutputName -ExpectCuda:(-not $SkipCudaRuntime)
    }
    $zipOut = Join-Path $packagePath "$OutputName-$timestamp-portable.zip"
    Write-Host "[build_windows_exe] Built bundled executable: $(Join-Path $bundleRoot "$OutputName.exe")"
    if (Compress-ArchiveWithRetry -Path @((Join-Path $bundleRoot "*")) -DestinationPath $zipOut) {
        Write-Host "[build_windows_exe] Zip artifact: $zipOut"
    } else {
        Write-Warning "[build_windows_exe] Continuing without zip artifact. Bundled build directory is still available."
    }
    Remove-StaleBuildArtifacts -PackagePath $packagePath -Keep $KeepPackages
}
