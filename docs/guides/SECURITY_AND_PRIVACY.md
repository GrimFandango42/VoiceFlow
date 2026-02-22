# Security and Privacy Guide

This guide summarizes the practical security model for running VoiceFlow in day-to-day Windows environments.

## Security Model

- Local-first processing: transcription runs locally by default.
- No mandatory cloud dependency for core ASR.
- User-scoped runtime data under `%LOCALAPPDATA%\LocalFlow`.
- Guardrails on input validation, buffer handling, and injection sanitization.

## Data Stored Locally

- Runtime config: `%LOCALAPPDATA%\LocalFlow\config.json`
- Logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`
- Recent history: `%LOCALAPPDATA%\LocalFlow\recent_history_events.jsonl`
- Correction review: `%LOCALAPPDATA%\LocalFlow\transcription_corrections.jsonl`
- Adaptive learning:
  - `%LOCALAPPDATA%\LocalFlow\adaptive_patterns.json`
  - `%LOCALAPPDATA%\LocalFlow\adaptive_audit.jsonl`
- Daily learning reports: `%LOCALAPPDATA%\LocalFlow\daily_learning_reports\`

## Operational Recommendations

1. Keep one active VoiceFlow runtime instance.
2. Run VoiceFlow with the same elevation level as your target app when injection is required.
3. Prefer `restore_clipboard=true` unless debugging injection issues.
4. Keep adaptive retention bounded (`adaptive_retention_hours`) for privacy hygiene.
5. Review local logs before sharing diagnostics.

## Scheduler Security Notes

The daily learning job uses Windows Task Scheduler and runs a local batch script:

- Task name: `VoiceFlow-DailyLearning`
- Command: `cmd.exe /c "...\VoiceFlow_DailyLearning.bat" --days-back 1`
- Scope: current Windows user

Manage task:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup\register_daily_learning_task.ps1 -StartTime "08:00" -Force
powershell -ExecutionPolicy Bypass -File .\scripts\setup\unregister_daily_learning_task.ps1
```

## Recent Hardening Changes

- Launcher cleanup:
  - Active launch paths are `python -m voiceflow.ui.cli_enhanced` and `python voiceflow.py`.
  - Legacy batch launchers were removed from active `main`.
- Daily learning is explicit and auditable:
  - reports are written as local JSON artifacts for review.

## Related References

- `src/voiceflow/utils/validation.py`
- `src/voiceflow/integrations/inject.py`
