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

Output:

- Bundle: `dist\VoiceFlow\`
- Package zip: `dist\packages\VoiceFlow-*-portable.zip`

## Build One-File Executable

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\build_windows_exe.ps1 -OutputName VoiceFlow -OneFile -Clean
```

## Installer Pipeline

Use:

- `scripts/setup/build_windows_installer.ps1`
- `packaging/windows/VoiceFlowSetup.iss`

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
   - `release_version=vX.Y.Z` (example: `v3.1.4`)
3. Run on `main`.

Published stable asset names (used by README download links):

- `VoiceFlow-win64.exe`
- `VoiceFlow-portable-win64.zip`
- `SHA256SUMS.txt`
