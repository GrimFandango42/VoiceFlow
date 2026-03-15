# Launch VoiceFlow (Windows)

## Recommended Launch Paths

- Local packaged bundle: `dist\VoiceFlow\VoiceFlow.exe`
- GitHub release download: `VoiceFlow-win64.exe`
- Portable release bundle: `VoiceFlow.exe` inside the portable zip

Use the packaged executable for day-to-day testing and normal Windows usage.
Batch launchers remain source/debug tools.

## First-Time Setup

1. Launch the packaged exe.
2. In setup wizard, click `Step 1: Run Hardware Check (Required)`.
3. Pick one profile: `Recommended`, `CPU Compatible`, or `GPU Balanced`.
4. Click `Save And Launch`.

## Relaunch Into Setup

- Right-click the tray icon and choose `Setup & Defaults`.
- For first-run regression testing, start from a clean `%LOCALAPPDATA%\LocalFlow\config.json` or reset:
  - `setup_completed=false`
  - `show_setup_on_startup=true`

## Local Source/Debug Launchers

Use these only when debugging source behavior:

- `VoiceFlow_Quick.bat`
- `VoiceFlow.bat`
- `VoiceFlow_Silent.bat`

## Basic Verification

1. Tray icon appears.
2. If first-run setup opens, complete the hardware check and save once.
3. Hold `Ctrl+Shift`, speak, release.
4. Overlay/dock react while recording.
5. Text appears in Notepad.
6. Default runtime pastes text without auto-sending Enter.

## If Launch Fails

```powershell
python scripts\list_audio_devices.py
python scripts\dev\quick_smoke_test.py
```

Runtime log:

- `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`
- fallback: `%LOCALAPPDATA%\LocalFlow\logs\localflow-<pid>.log`
