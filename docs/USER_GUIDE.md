# VoiceFlow User Guide

## Core Workflow

1. Focus your target app.
2. Hold push-to-talk (`Ctrl+Shift` by default).
3. Speak.
4. Release to transcribe and insert text.

## Tray Features

The tray menu controls:

- Code mode
- Injection mode (`Paste` vs `Type`)
- Auto-enter after paste
- Visual indicators and dock visibility
- Hotkey presets
- Recent history
- Correction review

## Model and Hardware Guidance

Default config is designed to work out of the box:

- `device=auto`
- `model_tier=quick`

Runtime behavior:

- CUDA available: GPU path with `float16`
- No CUDA: CPU path with `int8`

Optional tier overrides:

- `tiny`: lowest latency
- `quick`: default adaptive tier
- `balanced`: better quality with good speed (best on GPU)
- `quality`: best recognition, slower

## Personalization Features

VoiceFlow keeps personalized behavior enabled:

- Recent transcript history
- Correction review workflow
- Daily learning job from previous corrections
- Local engineering terms dictionary support

Daily learning commands:

```powershell
.\VoiceFlow_DailyLearning.bat
.\VoiceFlow_DailyLearning.bat --dry-run
```

Schedule daily learning:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup\register_daily_learning_task.ps1 -StartTime "08:00" -Force
```

## Config and Logs

- Config: `%LOCALAPPDATA%\LocalFlow\config.json`
- Logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

Injection reliability defaults:

- `inject_require_target_focus=true`
- `inject_refocus_on_miss=true`
- `inject_refocus_attempts=3`
- If final injection misses due focus drift, transcript is copied to clipboard for manual paste.

## Quick Troubleshooting

List audio devices:

```powershell
python scripts\list_audio_devices.py
```

If performance is unexpectedly slow:

1. Restart VoiceFlow.
2. Check `localflow.log` for `device=` and `compute=` values.
3. Confirm no older executable build is still running.

If transcription appears in terminal but not in your app:

1. Bring the target app back to foreground and paste (`Ctrl+V`).
2. Check for focus-stealing popups/notifications during key release.
3. Review `localflow.log` for `inject_focus_drift` events.
