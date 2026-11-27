# VoiceFlow Build Guide (Windows)

## Prerequisites

- Python 3.9+
- Windows 10/11
- Microphone device

Optional:

- NVIDIA GPU with CUDA runtime for highest transcription speed

## Bootstrap Environment

CPU-focused:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\bootstrap_windows.ps1
```

GPU-focused:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\bootstrap_windows.ps1 -GpuVenv
```

## Validate Local Runtime

```powershell
python scripts\dev\quick_smoke_test.py
pytest -q tests\runtime
```

## Build Windows Executable

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\build_windows_exe.ps1 -OutputName VoiceFlow -Clean
```

Each build also writes a timestamped snapshot zip to `dist\packages` (`VoiceFlow-<date>-<time>-portable.zip` or `-onefile.zip`), about 2 GB each. By default the build keeps the two newest and deletes older ones. `-KeepPackages N` changes how many are kept, and `-KeepPackages 0` keeps all. Published release assets in that folder (`VoiceFlow-win64.exe`, `VoiceFlow-portable-win64.zip`, `SHA256SUMS.txt`) carry no timestamp and are never pruned.

### The build environment (one-time)

The build finds its Python without flags, in this order: `-PythonExe`, `.venv-build`, `.venv-gpu`, `venv`, the main checkout's `.venv-build` (when run from a git worktree), then `python` on PATH. Create `.venv-build` once, from the pinned `requirements-build.txt` (faster-whisper 1.2.1, ctranslate2, PyInstaller and the NVIDIA cuDNN/cuBLAS/NVRTC wheels, so no torch and no `VOICEFLOW_TORCH_LIB_DIR` are needed):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\bootstrap_windows.ps1 -BuildVenv
```

Worktrees reuse the main checkout's `.venv-build`; they do not each need one. Do not build with the system Python: its faster-whisper may be an older release, and its site-packages get bundled (3.5 GB instead of 2.2 GB).

Before PyInstaller starts, the build runs a preflight (seconds, stops nothing, builds nothing). Run it alone with `-PreflightOnly` (exit 0 pass, 1 fail). Each failure line names what is missing:

| Message | Meaning and fix |
|---|---|
| `Python '...' did not run or has no site-packages` | No usable build Python. Create `.venv-build` (command above) or pass `-PythonExe`. |
| `pyinstaller` / `ctranslate2` `is not installed` | Wrong environment. Use `.venv-build`. |
| `faster-whisper here has no assets\silero_vad_v6.onnx` | faster-whisper older than 1.2.1 (ships v5 encoder/decoder files); `verify_bundle.py` would fail the finished build. Use `.venv-build`. |
| `CUDA runtime DLLs not found (...)` | The nvidia wheels (or `VOICEFLOW_TORCH_LIB_DIR`) do not supply the listed DLLs; the bundle would run on CPU. Use `.venv-build`, or pass `-AllowCpuOnly` if a CPU-only bundle is intended. |

The VAD file name is read from `verify_bundle.py` (`VAD_RELATIVE`); the CUDA DLL list is shared by the preflight and the post-build check.

The build script stops stale VoiceFlow processes before packaging and bundles the setup wizard runtime assets needed by the packaged app.

The build **fails (non-zero exit)** unless the bundle is fit for daily use. After PyInstaller, in both one-dir and `-OneFile` mode, it runs `scripts\setup\verify_bundle.py`:

1. **Frozen self-check (the gate).** It runs `VoiceFlow.exe --self-check=<json>` and waits for it. That path returns before the tray, hotkeys or microphone are initialized. Inside the frozen interpreter it imports the app's modules from the bundle, confirms onnxruntime was loaded from the bundle, runs Silero VAD on a second of silence through the bundled onnxruntime (the exact call that failed in the field), and loads the CUDA runtime DLLs from the bundle's own `torch\lib` (PATH and venvs are ignored). The EXE runs with `LOCALAPPDATA`, `APPDATA`, `TEMP` and `USERPROFILE` pointed at `build\pyinstaller\self_check_sandbox` and a minimal `PATH`, so it cannot touch live app data or borrow DLLs from the build machine. Its report is `build\pyinstaller\frozen_self_check.json`.
2. **Static pre-filter (one-dir only).** Checks the files on disk: the VAD model (`_internal\faster_whisper\assets\silero_vad_v6.onnx`) loads as ONNX, onnxruntime and ctranslate2 natives exist, the CUDA runtime (`cudnn_ops64_9.dll`, `cublas64_12.dll`, `cublasLt64_12.dll`, `cudnn64_9.dll`) is under `_internal\torch\lib` and loads, and the app's modules are inside the PYZ.
3. **Build commit matches HEAD (both modes).** The bundle must be a build of the checkout's current commit. The commit the frozen EXE reports about itself (`build` in its report, read from the bundled `voiceflow._build_stamp`) is compared with `git rev-parse HEAD`. A different commit fails (`stale bundle ... rebuild`), so re-verifying an old bundle after new commits fails instead of passing silently. Normal (frozen) verification fails closed: a missing, malformed or `unknown` build identity, a dirty-tree build (`dirty` not exactly `false`), or no git HEAD is a FAIL, and the source-tree stamp is never used as a substitute. The build script refuses to start on a dirty tree for the same reason. Only `--static-only` (debugging, never acceptance evidence) falls back to `src\voiceflow\_build_stamp.py`; there a mismatch still fails, inconclusive cases warn, and the report marks the run as not acceptance evidence.

The combined report is written to `build\pyinstaller\verify_bundle.json`. CUDA DLLs come from torch in the build venv, or from `VOICEFLOW_TORCH_LIB_DIR` (any `torch\lib` folder that has them). A CPU-only bundle needs an explicit `-AllowCpuOnly` (with or without `-SkipCudaRuntime`); without it a missing CUDA runtime is an error, because a CPU-only bundle silently demotes a `device=cuda` config to int8. `-AllowCpuOnly` is passed through to the frozen check as `--self-check-allow-cpu-only`.

To re-check a bundle by hand, with VoiceFlow not otherwise running:

```powershell
python scripts\setup\verify_bundle.py dist\VoiceFlow --json-out build\pyinstaller\verify_bundle.json
# or run the frozen check directly
dist\VoiceFlow\VoiceFlow.exe --self-check=$env:TEMP\voiceflow_self_check.json
```

Exit code 0 means every check passed; the JSON lists each one.

Output:

- Bundle: `dist\VoiceFlow\`
- Package zip: `dist\packages\VoiceFlow-*-portable.zip`

Primary local test target:

- `dist\VoiceFlow\VoiceFlow.exe`

## Build One-File Executable

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\build_windows_exe.ps1 -OutputName VoiceFlow -OneFile -Clean
```

Use the one-file build for release validation, not the default inner-loop test cycle.
It is materially slower to rebuild than the bundled app.

## Recommended Local Validation Loop

1. Build the bundled executable.
2. Launch `dist\VoiceFlow\VoiceFlow.exe`.
3. If validating onboarding, use a clean config or reset the setup markers before launch.
4. Complete one setup save, one relaunch, and one real dictation/injection pass.
5. Only then build the one-file executable or installer artifacts.

## Installer Pipeline

Use:

- `scripts/setup/build_windows_installer.ps1`
- `packaging/windows/VoiceFlowSetup.iss`
- `scripts/setup/register_startup_shortcut.ps1` (optional Windows sign-in startup)

Detailed release flow is in `docs/guides/WINDOWS_SETUP_EXECUTABLE.md`.

## GitHub Release Pipeline (One-Click)

Workflow: `.github/workflows/build-release.yml`

What it does:

- Builds Windows artifacts on `main` and `v*` tags.
- Publishes rolling prerelease assets to `latest-main`.
- Publishes stable release assets (`make_latest: true`) for tagged versions.

Manual stable release from GitHub UI:

1. Open `Actions` -> `Windows Executable CI/CD` -> `Run workflow`.
2. Set:
   - `publish_tag_release=true`
   - `release_version=vX.Y.Z` (example: `v3.1.8`)
3. Run on `main`.

Published stable asset names (used by README download links):

- `VoiceFlow-win64.exe`
- `VoiceFlow-portable-win64.zip`
- `SHA256SUMS.txt`
