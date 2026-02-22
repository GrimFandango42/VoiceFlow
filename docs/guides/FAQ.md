# VoiceFlow FAQ (Windows)

## Quick Click Paths

Use these first before editing config files manually.

| Need | Click Path |
|---|---|
| Change push-to-talk key | Tray -> `PTT Hotkey` |
| Toggle code formatting mode | Tray -> `Code Mode` |
| Switch paste vs typing injection | Tray -> `Injection` |
| Toggle auto-enter | Tray -> `Auto-Enter` |
| Open transcript history | Tray -> `Recent History` |
| Correct transcript mistakes | Tray -> `Correction Review` |
| Toggle status visuals | Tray -> `Visual Indicators` / `Dock` |

## Q: App transcribes but text does not insert into my target window.

A:

1. Click back into the target app and press `Ctrl+V` once.
2. Check if a popup/notification stole focus during key release.
3. Review `%LOCALAPPDATA%\LocalFlow\logs\localflow.log` for `inject_focus_drift`.

VoiceFlow keeps a clipboard fallback for focus-drift edge cases.

## Q: App is stuck in processing/transcribing.

A:

1. Confirm you are on `v3.1.5` or newer.
2. Fully exit VoiceFlow, then relaunch.
3. Confirm only one runtime instance is active.
4. Check log lines for active device routing:
   - `asr_engine_initialized ... device=... compute=...`

If this persists, capture the last 100 lines of `localflow.log` and include them in your issue report.

## Q: Long dictation is slower than expected.

A:

1. Keep `model_tier=quick` unless you intentionally need max quality.
2. Validate runtime route in logs (`device=cpu` or `device=cuda`).
3. Keep one active VoiceFlow instance.
4. Retry with a short and then long sample to compare timing.

## Q: How do I improve recognition for my accent or repeated terms?

A:

1. Use tray -> `Correction Review` for misses.
2. Keep adaptive learning enabled.
3. Run daily learning job:

```powershell
.\VoiceFlow_DailyLearning.bat
```

For deep tuning, see `docs/USER_GUIDE.md` and `docs/TECHNICAL_OVERVIEW.md`.

## Q: Is there a separate command-center settings window?

A:

Not in the current active runtime. Configuration is intentionally tray-first, plus overlay/dock and history/review panels.

## Q: Where are config, logs, and user-learning files?

A:

- Config: `%LOCALAPPDATA%\LocalFlow\config.json`
- Logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`
- Recent history: `%LOCALAPPDATA%\LocalFlow\recent_history_events.jsonl`
- Corrections: `%LOCALAPPDATA%\LocalFlow\transcription_corrections.jsonl`
- Adaptive patterns: `%LOCALAPPDATA%\LocalFlow\adaptive_patterns.json`
