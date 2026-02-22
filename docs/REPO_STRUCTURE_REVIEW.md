# Repository Structure Review

Date: 2026-02-21

## Current Root-Level Findings

The root contains user-facing launchers, build helpers, dev scripts, and historical artifacts together.
This increases noise for new users and reviewers.

Examples of root-level files that are not part of the normal user install experience:

- `quality_monitor.py`
- `test_quick_transcription.py`
- `tasks.md`
- multiple launch wrappers (`VoiceFlow*.bat`, `VoiceFlow_Tray.vbs`)

There are also local/dev artifacts that commonly appear in working copies:

- virtual environments (`venv`, `.venv-gpu`, `whisper_env`)
- build outputs (`build`, `dist`, `htmlcov`)
- local test/log directories (`logs`, `test_results`)

## Recommendation

Keep the runtime stable first, then do a staged cleanup in a separate pass:

1. Keep root focused on install and entry points:
- `README.md`
- `LICENSE`
- `Install_VoiceFlow.bat`
- `Bootstrap_Windows.bat`
- optionally one primary launcher wrapper

2. Move developer-only scripts to structured folders:
- diagnostics to `tools/diagnostics/`
- ad-hoc tests to `scripts/dev/` or `tests/manual/`
- planning docs (like `tasks.md`) to `docs/archive/`

3. Keep advanced operational details in docs:
- main user flow stays in `README.md`
- deep technical and AI-assistant guidance stays in `docs/AI_COMPANION_TECHNICAL.md`

## Why This Is Deferred

A full root cleanup can break local habits and existing shortcuts if done in the same pass as runtime fixes.
For this cycle, the safer path is:

- keep behavior stable
- improve onboarding docs now
- run structural cleanup as a dedicated follow-up change
