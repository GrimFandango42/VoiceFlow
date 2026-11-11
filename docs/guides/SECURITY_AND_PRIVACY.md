# Security and Privacy Guide

This guide summarizes the practical security model for running VoiceFlow in day-to-day Windows environments.

## Security Model

- **Audio is processed on your machine.** Transcription runs locally (faster-whisper); there is no API call on the transcription path, and audio is never uploaded.
- **Nothing is uploaded by default.** The only feature that sends data off the machine is the optional nightly cloud analysis below, and it is off until you turn it on.
- User-scoped runtime data under `%LOCALAPPDATA%\VoiceFlow` (migrated automatically from the older `LocalFlow` folder name).
- When VoiceFlow runs from source with `dev.py`, the model runs in a second process that listens on `127.0.0.1` only (default port 8765, `VOICEFLOW_MODEL_SERVER_PORT`). It is not reachable from other machines.
- Guardrails on input validation, buffer handling, and injection sanitization.

## Data Stored Locally

Everything below stays on your machine.

| File (under `%LOCALAPPDATA%\VoiceFlow`) | What it holds |
|---|---|
| `config.json` | Settings |
| `logs\voiceflow.log` | Runtime log (timings and events; review before sharing) |
| `transcript_history.json` | The last 50 dictations: text, time, word count, paste outcome, target *process name* (never window titles). Written before the paste is attempted. **Tray → Recent → Clear history** deletes it. |
| `learned_hotwords.json` | Terms you corrected at least twice; added to Whisper's vocabulary hints. Independent of the cloud setting. |
| `recent_history_events.jsonl`, `transcription_corrections.jsonl` | Recent-history panel events and Correction Review feedback (bounded, rotated) |
| `adaptive_patterns.json`, `adaptive_audit.jsonl` | Learned replacement rules and their audit trail; records older than `adaptive_retention_hours` (default 72) are purged |
| `daily_learning_reports\` | One JSON report per nightly learning run |
| `pending_review.jsonl` | Rule suggestions from the nightly pass, waiting for your review (suggest-only) |
| `custom_vocabulary.txt` | `wrong -> correct` vocabulary rules, seeded once from a bundled default; yours to edit |
| `engineering_terms.json` | Your own terms (optional, you create it) |

## Optional nightly cloud analysis (off by default)

The nightly learning pass has one optional cloud step, **Setup & Defaults → "Send a daily sample of transcripts to Claude"**. It is off by default (`adaptive_ai_analysis_enabled = false`). When you turn it on, for the target date it sends to Anthropic via the Claude CLI (or Google Gemini if the CLI is missing):

- your transcripts, verbatim — up to 8 by default (configurable);
- the same number of your original/corrected correction pairs;
- the top word replacement pairs;
- recurring instruction themes;
- a snapshot of the learned adjustment rules.

Audio is never sent. The reply is used to suggest vocabulary and phrasing rules; suggestions are only queued for your review in `pending_review.jsonl` and are never applied automatically.

- The Claude CLI is invoked with `--safe-mode`, no tools, no MCP servers and no session persistence, and the prompt goes over stdin so transcript text never appears in a command line.
- If a managed (enterprise) Claude Code policy is present — a managed-settings file that declares hooks (including `managed-settings.d` fragments), or on Windows the `SOFTWARE\Policies\ClaudeCode` registry key under `HKLM` or `HKCU` — the Claude CLI step is skipped rather than run, because `--safe-mode` cannot be trusted to suppress managed hooks. On an organization-managed Claude account, server-delivered policy hooks could observe this prompt; this feature is intended for personal accounts.
- Each nightly report records `ai_learning_analysis.enabled`, so you can confirm after the fact what happened.
- Upgrading from a build where this was on by default resets it to off once (`cloud_learning_consent_version`).

## Operational Recommendations

1. Keep one active VoiceFlow runtime instance.
2. Run VoiceFlow with the same elevation level as your target app when injection is required.
3. Prefer `restore_clipboard=true` (the default) unless debugging injection issues.
4. Keep adaptive retention bounded (`adaptive_retention_hours`) for privacy hygiene.
5. Review local logs before sharing diagnostics.
6. The recent-transcripts list is plain text on disk. Clear it from the tray if you dictate something sensitive.

## Screenshot And Demo Hygiene

If you publish docs, bug reports, or release notes with images:

1. Do not publish screenshots that show real project names, editor tabs, taskbar items, account names, or desktop notifications.
2. Crop to the VoiceFlow window whenever possible.
3. Assume all images in a public repo are effectively permanent and review them with the same care as logs or config snippets.

The images in this repo are generated, not captured from a working desktop: `python scripts/capture_screenshots.py` runs the overlay, tray menu and setup window in a **demo mode** with no microphone, no global hotkeys, no paste and fixed demo text, with `%LOCALAPPDATA%` pointed at a temporary folder. Use it (or the same pattern) for new images.

## Scheduler Security Notes

The daily learning job uses Windows Task Scheduler and runs a local batch script:

- Task name: `VoiceFlow-DailyLearning`
- Command: `cmd.exe /c "...\VoiceFlow_DailyLearning.bat" --days-back 1`
- Scope: current Windows user, limited run level

Manage task:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup\register_daily_learning_task.ps1 -StartTime "08:00" -Force
powershell -ExecutionPolicy Bypass -File .\scripts\setup\unregister_daily_learning_task.ps1
```

## Launch Paths

- Packaged: `dist\VoiceFlow\VoiceFlow.exe`. The build verifies itself (`VoiceFlow.exe --self-check`), which runs before any tray, hotkey or microphone setup.
- Source: `python _app_entry.py` or `python dev.py`. Do not launch with `-m voiceflow.ui.cli_enhanced`: the single-instance guard mistakes the py.exe launcher's child for a duplicate and terminates it.
- The `.bat` launchers clean stale VoiceFlow processes before relaunching; use them for source debugging only.

## Related References

- `src/voiceflow/utils/validation.py`
- `src/voiceflow/integrations/inject.py`
- `src/voiceflow/core/history.py` (transcript history)
