# VoiceFlow Launch Guide (Windows)

## Recommended Order

1. `VoiceFlow_Quick.bat` for normal day-to-day use.
2. `VoiceFlow.bat` when you want visible console logs.
3. `VoiceFlow_Silent.bat` for background/tray-first mode.
4. `tools\launchers\LAUNCH_CONTROL_CENTER.bat` for guided setup and diagnostics.

## One-Time Setup

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install --upgrade pip
pip install -r scripts\setup\requirements_windows.txt
```

Optional health check:

```powershell
python scripts\dev\quick_smoke_test.py
```

## Launch Commands

### Standard (console visible)

```powershell
.\VoiceFlow.bat
```

### Quick (recommended)

```powershell
.\VoiceFlow_Quick.bat
```

### Silent tray mode

```powershell
.\VoiceFlow_Silent.bat
```

### Control Center

```powershell
tools\launchers\LAUNCH_CONTROL_CENTER.bat
```

Or:

```powershell
python tools\VoiceFlow_Control_Center.py
```

## Manual Python Launch

From repo root:

```powershell
$env:PYTHONPATH = "$pwd\src"
python -m voiceflow.ui.cli_enhanced
```

Terminal/no-tray variant:

```powershell
$env:PYTHONPATH = "$pwd\src"
python -m voiceflow.ui.cli_enhanced --no-tray
```

## Basic Operation

1. Hold the push-to-talk hotkey (default: `Ctrl+Shift`).
2. Speak while holding.
3. Release to transcribe and inject text.

## If Launch Fails

Run:

```powershell
python scripts\list_audio_devices.py
python scripts\debugging\debug_hang_issue.py
python scripts\debugging\debug_nonetype_issue.py
```

Then relaunch with `VoiceFlow.bat` to capture console logs.

## Runtime Paths

- Config: `%LOCALAPPDATA%\LocalFlow\config.json`
- Logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

## Notes

- If elevated apps do not receive injected text, run VoiceFlow with matching permissions.
- If GPU behaves unexpectedly, set `VOICEFLOW_FORCE_CPU=1` and compare latency/stability.
