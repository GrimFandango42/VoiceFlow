# VoiceFlow Launch Instructions (Guide)

This guide complements `docs/HOW_TO_LAUNCH.md` with a short validation sequence.

## Launch

Recommended:

```powershell
.\VoiceFlow_Quick.bat
```

If you need logs:

```powershell
.\VoiceFlow.bat
```

Control Center:

```powershell
tools\launchers\LAUNCH_CONTROL_CENTER.bat
```

## Validation Sequence

1. Notepad short dictation (3-5s).
2. VS Code medium dictation (8-12s).
3. Long dictation (20-40s with pauses).

Check for:
- no dropped text
- stable release-to-text latency
- expected punctuation/formatting
- correct target-window injection

## If Issues Appear

Run:

```powershell
python scripts\list_audio_devices.py
python scripts\debugging\debug_hang_issue.py
python scripts\debugging\debug_nonetype_issue.py
```

Then reproduce with `VoiceFlow.bat` and capture logs from:

- `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`
