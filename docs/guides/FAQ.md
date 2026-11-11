# VoiceFlow FAQ (Windows)

## Quick Click Paths

Use these first before editing config files manually.

| Need | Click Path |
|---|---|
| Open setup wizard | Tray -> `Setup & Defaults` |
| Change push-to-talk key | Tray -> `PTT Hotkey` |
| Toggle code formatting mode | Tray -> `Code Mode` |
| Switch paste vs typing injection | Tray -> `Injection` |
| Toggle auto-enter | Tray -> `Auto-Enter` |
| Get a recent dictation back | Tray -> `Recent` (click to copy), or `Alt+Shift+V` to re-paste the last one |
| Browse history / fix mistakes | Tray -> `Recent History`, `Correction Review` |
| Toggle status visuals | Tray -> `Visual Indicators` / `Dock` |

## Q: App transcribes but text does not insert into my target window.

A:

Nothing is lost: the transcript is saved to history before VoiceFlow tries to paste.

1. Click back into the target app and press `Alt+Shift+V` (re-paste the last transcript), or open tray -> `Recent` and click the entry to copy it, then press `Ctrl+V`. Entries that did not paste are marked `(not pasted)`.
2. Check if a popup/notification stole focus during key release.
3. Review `%LOCALAPPDATA%\VoiceFlow\logs\voiceflow.log` for `inject_focus_drift`.

By default the text goes to the window that had focus the moment you released the hotkey (`inject_target_policy = release`). If that window had closed, nothing is pasted anywhere; the text is in `Recent` and on the clipboard.

## Q: How do I cancel a recording?

A: Press `Esc` while holding the hotkey. The audio is discarded and nothing is transcribed. (`cancel_recording_key` in the config; empty disables it.)

## Q: Is VoiceFlow using my GPU?

A: Look for `asr_engine_initialized ... device=cuda compute=float16` in `voiceflow.log`. `device=cpu compute=int8` means the CUDA runtime was not found (the log also has `cuda_runtime_unavailable missing_dlls=...`): VoiceFlow needs `cublas64_12.dll` and `cudnn_ops64_9.dll` (CUDA 12 / cuDNN 9) in the venv's `torch\lib`, in `VOICEFLOW_TORCH_LIB_DIR`, or on `PATH`. The packaged app bundles them and its build fails without them. Check a bundle without launching the tray: `VoiceFlow.exe --self-check=report.json`.

## Q: Can it run next to Wispr Flow?

A: Yes. VoiceFlow's hold key is `Ctrl+Shift`, and its re-paste (`Alt+Shift+V`) and cancel (`Esc`) keys avoid `Ctrl+Alt`, which Wispr Flow and VoiceFlow's own toggles (`Ctrl+Alt+C/P/Enter`) use.

## Q: What leaves my machine?

A: Audio never does, and nothing is uploaded by default. The only optional cloud step is the nightly transcript sample, off unless you tick it in `Setup & Defaults`. Details: [Security and privacy](SECURITY_AND_PRIVACY.md#optional-nightly-cloud-analysis-off-by-default).

## Q: VoiceFlow keeps pressing Enter after each transcription.

A:

1. Open tray -> `Auto-Enter`.
2. Turn it off.
3. Retry one short dictation.

Default stable behavior is paste-only on release; auto-Enter is opt-in.

## Q: App is stuck in processing/transcribing.

A:

1. Confirm you are on a current stable build or a freshly rebuilt local bundle.
2. Fully exit VoiceFlow, then relaunch.
3. Confirm only one runtime instance is active.
4. Check log lines for active device routing:
   - `asr_engine_initialized ... device=... compute=...`

If this persists, capture the last 100 lines of `voiceflow.log` and include them in your issue report.

## Q: Long dictation is slower than expected.

A:

1. Keep `model_tier=quick` unless you intentionally need max quality.
2. Validate runtime route in logs (`device=cpu` or `device=cuda`).
3. Keep one active VoiceFlow instance.
4. Retry with a short and then long sample to compare timing.

## Q: The first dictation after a long break looks incomplete.

A:

1. Confirm you are on a current stable build.
2. Retry one natural sentence or paragraph to let the resume guardrails settle.
3. If it repeats, review `%LOCALAPPDATA%\VoiceFlow\logs\voiceflow.log` for `transcription_idle_resume_guard` around that attempt.

Current builds favor transcript completeness over pause compaction on the first longer post-idle utterance, then fall back to raw-audio retry if the result still looks clipped.

## Q: Setup wizard only lets me run hardware check first. Is that expected?

A:

Yes. In startup flow, Step 1 is intentionally required before Step 2:

1. Click `Step 1: Run Hardware Check (Required)`.
2. Wait for the check to complete.
3. Pick `Recommended`, `CPU Compatible`, or `GPU Balanced`.
4. Click `Save And Launch`.

Step 2 controls are locked/dimmed until Step 1 completes. (A screenshot of the window is in the [User Guide](../USER_GUIDE.md#setup--defaults).)

## Q: Transcription is fast but quality/formatting looks rough.

A:

1. Keep light typo cleanup enabled (`enable_light_typo_correction=true`).
2. Keep aggressive context rewrites off unless needed (`enable_aggressive_context_corrections=false`).
3. Verify destination-aware formatting is on (`destination_aware_formatting=true`).
4. Use `Correction Review` for recurring misses and run daily learning.

## Q: How do I improve recognition for my accent or repeated terms?

A:

1. Use tray -> `Correction Review` for misses.
2. Keep adaptive learning enabled.
3. Terms you correct twice are added to Whisper's vocabulary right away (`learned_hotwords.json`). Run the daily learning job for the rest:

```powershell
.\VoiceFlow_DailyLearning.bat
```

4. For repeated house-style terms, add `wrong -> correct` lines to `%LOCALAPPDATA%\VoiceFlow\custom_vocabulary.txt`, or local overrides in `engineering_terms.json`.

Current builds already normalize a few recurring coding-tool phrases such as `Claude Code` and `Claude Desktop`; use the local terms file for anything more specific to your accent or workflow.

For deep tuning, see `docs/USER_GUIDE.md` and `docs/TECHNICAL_OVERVIEW.md`.

## Q: Where do I change settings and review recent transcripts?

A:

Use the setup wizard for first-run defaults and the tray menu for day-to-day controls. Recent History and Correction Review are also available directly from the tray.

## Q: Where are config, logs, and user-learning files?

A:

- Config: `%LOCALAPPDATA%\VoiceFlow\config.json`
- Logs: `%LOCALAPPDATA%\VoiceFlow\logs\voiceflow.log`
- Fallback logs: `%LOCALAPPDATA%\VoiceFlow\logs\voiceflow-<pid>.log`
- Recent dictations (tray `Recent`, last 50): `%LOCALAPPDATA%\VoiceFlow\transcript_history.json`
- Recent-history panel events: `%LOCALAPPDATA%\VoiceFlow\recent_history_events.jsonl`
- Learned hotwords: `%LOCALAPPDATA%\VoiceFlow\learned_hotwords.json`
- Your vocabulary: `%LOCALAPPDATA%\VoiceFlow\custom_vocabulary.txt`
- Corrections: `%LOCALAPPDATA%\VoiceFlow\transcription_corrections.jsonl`
- Adaptive patterns: `%LOCALAPPDATA%\VoiceFlow\adaptive_patterns.json`
