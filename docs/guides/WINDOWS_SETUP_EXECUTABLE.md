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
4. Hold `Ctrl+Shift` to dictate (default push-to-talk).

Config and logs still live in:
- `%LOCALAPPDATA%\LocalFlow\config.json`
- `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

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

Output:
- `dist\VoiceFlow\VoiceFlow.exe`
- `dist\packages\VoiceFlow-<timestamp>-portable.zip`

### 2) Build Installer EXE

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup\build_windows_installer.ps1 -AppVersion 3.0.0
```

Output:
- `dist\installer\VoiceFlow-Setup-3.0.0.exe`

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
2. Run smoke validation on a clean machine:
   - tray appears
   - dock/overlay appear
   - hotkey hold/release works
   - injection works in Notepad and VS Code
3. Upload:
   - `VoiceFlow-Setup-<version>.exe`
   - optional portable zip from `dist\packages`
4. Update release notes with known limitations (Windows-first, unsigned binary warnings if applicable).

## Notes

- This packaging path does not bundle ASR model weights.
- On first use, VoiceFlow may download model assets depending on selected model/runtime cache state.
- Unsigned installers may trigger SmartScreen; code-signing is recommended for broad distribution.
