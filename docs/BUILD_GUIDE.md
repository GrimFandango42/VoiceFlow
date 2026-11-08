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

The build script stops stale VoiceFlow processes before packaging and bundles the setup wizard runtime assets needed by the packaged app.

The build **fails (non-zero exit)** unless the bundle is fit for daily use. After PyInstaller, in both one-dir and `-OneFile` mode, it runs `scripts\setup\verify_bundle.py`:

1. **Frozen self-check (the gate).** It runs `VoiceFlow.exe --self-check=<json>` and waits for it. That path returns before the tray, hotkeys or microphone are initialized. Inside the frozen interpreter it imports the app's modules from the bundle, confirms onnxruntime was loaded from the bundle, runs Silero VAD on a second of silence through the bundled onnxruntime (the exact call that failed in the field), and loads the CUDA runtime DLLs from the bundle's own `torch\lib` (PATH and venvs are ignored). The EXE runs with `LOCALAPPDATA`, `APPDATA`, `TEMP` and `USERPROFILE` pointed at `build\pyinstaller\self_check_sandbox` and a minimal `PATH`, so it cannot touch live app data or borrow DLLs from the build machine. Its report is `build\pyinstaller\frozen_self_check.json`.
2. **Static pre-filter (one-dir only).** Checks the files on disk: the VAD model (`_internal\faster_whisper\assets\silero_vad_v6.onnx`) loads as ONNX, onnxruntime and ctranslate2 natives exist, the CUDA runtime (`cudnn_ops64_9.dll`, `cublas64_12.dll`, `cublasLt64_12.dll`, `cudnn64_9.dll`) is under `_internal\torch\lib` and loads, and the app's modules are inside the PYZ.
3. **Build commit matches HEAD (both modes).** The bundle must be a build of the checkout's current commit. The commit the frozen EXE reports about itself (`build` in its report, read from the bundled `voiceflow._build_stamp`) is compared with `git rev-parse HEAD`; without one, the `src\voiceflow\_build_stamp.py` the build wrote is used. A different commit fails (`stale bundle ... rebuild`), so re-verifying an old bundle after new commits fails instead of passing silently. A dirty-tree build, an `unknown` commit, or no git only warns.

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
