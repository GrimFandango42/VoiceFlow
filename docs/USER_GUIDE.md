# VoiceFlow User Guide

## Who This Is For

This guide is for users running VoiceFlow as a desktop push-to-talk transcriber on Windows.

## First Run

1. Install dependencies (`scripts\setup\requirements_windows.txt`).
2. Start with `VoiceFlow_Quick.bat`.
3. Confirm tray icon appears.
4. Test a short dictation into Notepad.

## Core Workflow

1. Focus your target app (editor/chat/browser).
2. Hold push-to-talk (default: `Ctrl+Shift`).
3. Speak.
4. Release.
5. VoiceFlow injects the transcript into the active target.

## Tray Menu Controls

Primary toggles:
- Code mode
- Injection mode (paste vs type)
- Auto-enter
- Visual indicators
- Dock visibility
- Recent history panel
- Push-to-talk preset selector

## Hotkeys

Default push-to-talk:
- `Ctrl+Shift` (modifiers only)

Common presets available in tray:
- `Ctrl+Shift+Space`
- `Ctrl+Alt+Space`
- `Ctrl+Alt`
- `Ctrl+Space`
- `Alt+Space`

Additional runtime toggles:
- `Ctrl+Alt+C` (code mode)
- `Ctrl+Alt+P` (paste/type mode)
- `Ctrl+Alt+Enter` (auto-enter)

## Understanding Status

Typical status progression:
- `idle`
- `listening` (while holding)
- `processing` / `transcribing` (after release)
- `complete` (then auto-return to idle)

Tray and overlay both reflect these states.

## Accuracy and Speed Tuning

If you want lower latency:
- keep `latency_boost_enabled=true`
- keep pause compaction enabled
- prefer CUDA if available and stable

If you want higher consistency:
- reduce aggressive custom post-processing
- keep code mode enabled for technical dictation workflows

Config file:
- `%LOCALAPPDATA%\LocalFlow\config.json`

## Reliability Tips

- Keep one VoiceFlow runtime instance active.
- For long dictation, keep speaking naturally with short pauses.
- Use quiet mic input when possible.
- If text lands in the wrong app, re-focus target before release.

## Troubleshooting

Audio/device checks:

```powershell
python scripts\list_audio_devices.py
```

Debug tools:

```powershell
python scripts\debugging\debug_hang_issue.py
python scripts\debugging\debug_nonetype_issue.py
```

Run with console logs:

```powershell
.\VoiceFlow.bat
```

## Known Platform Scope

- Fully tuned/tested path: Windows.
- Linux/macOS: possible via fork, but not production-validated in this repo.

Forking notes:
- `docs/guides/FORKING_AND_PLATFORM_GUIDE.md`
