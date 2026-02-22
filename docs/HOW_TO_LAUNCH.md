# Launch VoiceFlow (Windows)

## Recommended Launchers

- `VoiceFlow_Quick.bat` (default)
- `VoiceFlow.bat` (console visible)
- `VoiceFlow_Silent.bat` (tray-first)

## First-Time Setup

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\bootstrap_windows.ps1 -GpuVenv
```

## Run

```powershell
.\VoiceFlow_Quick.bat
```

## Basic Verification

1. Tray icon appears.
2. Hold `Ctrl+Shift`, speak, release.
3. Text appears in Notepad.

## If Launch Fails

```powershell
python scripts\list_audio_devices.py
python scripts\dev\quick_smoke_test.py
```

Runtime log:

- `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`
