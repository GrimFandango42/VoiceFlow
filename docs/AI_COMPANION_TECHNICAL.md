# VoiceFlow Technical Playbook (AI Companion)

This file is a compact technical handoff for engineers and AI coding assistants.
Use this for implementation work, packaging, and regression checks.

## Runtime Model Path

- Primary ASR path: `faster-whisper` + `ctranslate2`
- Packaged app strategy:
  - Do not bundle `torch` in the executable.
  - Prefer `ctranslate2` CUDA checks for GPU readiness.
  - Register CUDA DLL search paths without importing `torch`.
  - Remove conflicting bundled `MSVCP140*.dll` from `_internal` after build.

## Key Files

- Runtime entry: `scripts/setup/voiceflow_exe_entry.py`
- ASR engine: `src/voiceflow/core/asr_engine.py`
- Main app loop: `src/voiceflow/ui/cli_enhanced.py`
- Build script (Windows exe): `scripts/setup/build_windows_exe.ps1`
- Daily learning task registration: `scripts/setup/register_daily_learning_task.ps1`

## Build And Launch Commands

```powershell
# Build executable bundle
powershell -ExecutionPolicy Bypass -File .\scripts\setup\build_windows_exe.ps1 -Clean

# Launch packaged app
.\dist\VoiceFlow\VoiceFlow.exe
```

## CI/CD Release Automation

- Workflow: `.github/workflows/build-release.yml`
- On every push to `main`:
  - Builds portable + one-file executable
  - Publishes rolling prerelease tag `latest-main`
  - Uploads `VoiceFlow-win64.exe` and `VoiceFlow-portable-win64.zip`
- On tag push `v*`:
  - Publishes versioned release
  - Uploads the same stable asset names + `SHA256SUMS.txt`

## Fast Regression Slice

```powershell
# Smoke test
python scripts\dev\quick_smoke_test.py

# Core regression tests
pytest -q tests\test_textproc.py tests\test_injector_logic.py tests\test_sanitization_and_rate.py
```

## Runtime Data Paths (Windows)

- Config: `%LOCALAPPDATA%\LocalFlow\config.json`
- Logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`
- Recent history: `%LOCALAPPDATA%\LocalFlow\recent_history_events.jsonl`
- Corrections: `%LOCALAPPDATA%\LocalFlow\transcription_corrections.jsonl`
- Daily learning output: `%LOCALAPPDATA%\LocalFlow\daily_learning_reports\`

## Known Failure Signatures

1. `WinError 1114 ... c10.dll`
- Cause: packaged `torch` DLL init failure through indirect import.
- Fix: keep `torch` excluded from packaged runtime path.

2. `APPCRASH ... MSVCP140.dll ... _internal\MSVCP140.dll`
- Cause: conflicting bundled VC++ runtime in PyInstaller output.
- Fix: remove bundled `MSVCP140*.dll` from `_internal` post-build.

3. Slow transcription after packaging
- Cause: GPU path fell back to CPU because CUDA DLLs were not discoverable.
- Fix: ensure ASR runtime registers external CUDA DLL search paths before model load.

## Change Safety Rules

- Prefer additive fixes to runtime guardrails over broad refactors.
- Validate packaged behavior, not only source-mode behavior.
- Keep user-facing install flow simple in `README.md`; put deep details in docs.
