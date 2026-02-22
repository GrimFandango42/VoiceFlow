# VoiceFlow User Guide

## Core Workflow

1. Focus the target app.
2. Hold push-to-talk (`Ctrl+Shift` by default).
3. Speak.
4. Release to transcribe and insert text.

## UI Surfaces

VoiceFlow is intentionally tray-first:

- Tray menu: primary settings and actions.
- Overlay + dock: status and recent transcript visibility.
- Recent History + Correction Review: fast correction loop.

There is currently no separate "Command Center" window in the active runtime.

## Tray Settings Map

Use this as a visual click-path map:

| Goal | Click Path | Persists In Config |
|---|---|---|
| Toggle code mode | Tray -> `Code Mode` | Session toggle (runtime state) |
| Choose paste vs type injection | Tray -> `Injection` | `paste_injection` |
| Auto-press Enter after paste | Tray -> `Auto-Enter` | `press_enter_after_paste` |
| Show/hide visual indicators | Tray -> `Visual Indicators` | `visual_indicators_enabled` |
| Show/hide dock | Tray -> `Dock` | `visual_dock_enabled` |
| Change push-to-talk preset | Tray -> `PTT Hotkey` -> pick preset | `hotkey_*` fields |
| Open transcript history | Tray -> `Recent History` | n/a |
| Open correction workflow | Tray -> `Correction Review` | n/a |

Also available via hotkeys:

- `Ctrl+Alt+C`: toggle code mode
- `Ctrl+Alt+P`: toggle paste/type injection
- `Ctrl+Alt+Enter`: toggle auto-enter

## Accent and Personalization

VoiceFlow keeps personalization enabled:

- Recent transcript history
- Correction review workflow
- Daily learning from correction data
- Local engineering terms dictionary support

Fastest way to improve accent-specific output:

1. Open `Correction Review` from tray.
2. Correct recurring misses.
3. Let daily learning process those corrections.

Daily learning commands:

```powershell
.\VoiceFlow_DailyLearning.bat
.\VoiceFlow_DailyLearning.bat --dry-run
```

Schedule daily learning:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup\register_daily_learning_task.ps1 -StartTime "08:00" -Force
```

## Model and Hardware Defaults

Out-of-box defaults:

- `device=auto`
- `model_tier=quick`

Runtime behavior:

- CUDA available: GPU path with `float16`
- No CUDA: CPU path with `int8`

Optional tier overrides:

- `tiny`: lowest latency
- `quick`: default adaptive tier
- `balanced`: higher quality with good speed (best on GPU)
- `quality`: best recognition, slower

## Advanced Config and Logs

- Config: `%LOCALAPPDATA%\LocalFlow\config.json`
- Logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

Injection reliability defaults:

- `inject_require_target_focus=true`
- `inject_refocus_on_miss=true`
- `inject_refocus_attempts=3`
- If final injection misses due focus drift, transcript is copied to clipboard for manual paste.

For troubleshooting and quick issue triage, use [`docs/guides/FAQ.md`](guides/FAQ.md).
