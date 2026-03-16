# Windows Setup Executable Guide

## Goal

Provide a straightforward installer path for end users:
- download `VoiceFlow-Setup-<version>.exe`
- run installer
- launch VoiceFlow with the same defaults used in source mode

This packaging path is Windows-focused and targets the current runtime entrypoint:
`voiceflow.ui.cli_enhanced`.

## End User Install Flow

1. Download the latest installer from Releases:
   - `VoiceFlow-Setup-<version>.exe`
2. Run the installer.
3. Launch `VoiceFlow` from Start Menu or desktop shortcut.
4. On first run, complete setup:
   - click `Step 1: Run Hardware Check (Required)`
   - choose one profile
   - click `Save And Launch`
5. Hold `Ctrl+Shift` to dictate (default push-to-talk).
6. By default, VoiceFlow pastes on release without auto-sending Enter.

Config and logs still live in:
- `%LOCALAPPDATA%\LocalFlow\config.json`
- `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

If the primary log file is locked, VoiceFlow can fall back to:
- `%LOCALAPPDATA%\LocalFlow\logs\localflow-<pid>.log`

## Maintainer Build Flow

### Prerequisites

- Windows 10/11
- Python 3.9+
- project dependencies installed
- PyInstaller (`pyinstaller`, `pyinstaller-hooks-contrib`)
- Inno Setup 6 (`ISCC.exe`) for installer creation

### 1) Build Executable Bundle

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup\build_windows_exe.ps1 -Clean -InstallPackagingDeps
```

Notes:
- this is the primary local validation artifact
- the builder stops stale VoiceFlow processes before packaging
- the builder bundles Tcl/Tk runtime assets so the packaged setup wizard works

Output:
- `dist\VoiceFlow\VoiceFlow.exe`
- `dist\packages\VoiceFlow-<timestamp>-portable.zip`

### 2) Build Installer EXE

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup\build_windows_installer.ps1
```

Output:
- `dist\installer\VoiceFlow-Setup-<version>.exe`

By default, the installer build now reads the release version from `pyproject.toml`.
Pass `-AppVersion <version>` only when you intentionally need to override it.

If Inno Setup is not installed:
- install manually from <https://jrsoftware.org/isdl.php>
- or run installer build with `-InstallInnoSetup` (Chocolatey required)

## Packaging Files

- Entrypoint: `scripts/setup/voiceflow_exe_entry.py`
- Exe builder: `scripts/setup/build_windows_exe.ps1`
- Installer builder: `scripts/setup/build_windows_installer.ps1`
- Inno Setup script: `packaging/windows/VoiceFlowSetup.iss`

## Release Checklist

1. Build executable and installer.
2. Run smoke validation on a clean machine or clean config:
   - packaged exe opens setup wizard on first run
   - hardware check completes and one profile can be saved
   - relaunch reaches tray/runtime normally
   - dock/overlay appear
   - hotkey hold/release works
   - short dictation works without silent blank output
   - injection works in Notepad and VS Code
   - default release behavior does not auto-send Enter
3. Publish release assets via CI/CD (`.github/workflows/build-release.yml`):
   - push a `v*` tag, or
   - run workflow manually with:
     - `publish_tag_release=true`
     - `release_version=vX.Y.Z`
4. Confirm assets on the release:
   - `VoiceFlow-win64.exe`
   - `VoiceFlow-portable-win64.zip`
   - `SHA256SUMS.txt`
5. Verify README links:
   - `https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-win64.exe`
   - `https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-portable-win64.zip`
6. Update release notes with known limitations (Windows-first, unsigned binary warnings if applicable).

## Notes

- This packaging path does not bundle ASR model weights.
- On first use, VoiceFlow may download model assets depending on selected model/runtime cache state.
- Unsigned installers may trigger SmartScreen; code-signing is recommended for broad distribution.
- For local end-to-end testing, prefer `dist\VoiceFlow\VoiceFlow.exe` over batch launchers.
