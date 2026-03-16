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
