# Repository Structure

Date: 2026-04-06

## Active Surface

```
src/voiceflow/
  core/           Audio capture, ASR engine, streaming preview, text processing
  integrations/   Global hotkey listener, text injection
  ui/             Setup wizard, tray, overlay, CLI runtime orchestration
  utils/          Config persistence, logging, validation, process monitoring
  models/         Lightweight data structures (tray state, performance metrics)
  platform/       OS abstraction layer (factory, contracts, posix mock)
  ai/             Optional: adaptive learning, course correction, command mode

scripts/
  setup/          Bootstrap, build, installer, task registration scripts
  dev/            Quick smoke test and hotkey config check

tests/runtime/    Maintained regression suite (126 tests)
docs/             Onboarding, architecture, user guide, guides, archive
```

## Root-Level Launchers

| File | Purpose |
|------|---------|
| `VoiceFlow.bat` | Primary dev/debug launcher (console window) |
| `VoiceFlow_Quick.bat` | Fast launch without process cleanup preamble |
| `VoiceFlow_Silent.bat` | Silent batch launcher |
| `VoiceFlow_Tray.vbs` | No-console tray launcher (Windows taskbar pin) |
| `VoiceFlow_DailyLearning.bat` | Run batch learning job manually |
| `Install_VoiceFlow.bat` | First-time install helper |
| `Bootstrap_Windows.bat` | Wrapper around bootstrap_windows.ps1 |
| `_app_entry.py` | Dev entrypoint (bypasses single-instance guard) |
| `voiceflow.py` | Compatibility entrypoint |
| `dev.py` | Hot-reload dev watcher |

## What Was Removed (April 2026)

- `src/voiceflow/` root-level compat shims — 11 files re-exporting from subpackages with no active callers
- `src/voiceflow/core/audio.py` — 125-line stub superseded by `audio_enhanced.py`
- `src/voiceflow/utils/production_logging.py` — unused alternate logging module
- `src/voiceflow/stability/` — empty directory
- `tools/` — old dev-era control center, stability test runner, custom launchers
- `examples/implementations/` — pre-reorganization prototype scripts
- `start_dev.vbs` — personal hardcoded-path dev launcher

Historical content recoverable from git history.

## Why this structure

- Contributors land in `src/voiceflow/` with six clearly named subpackages
- No dead compat layer confusing import paths
- `docs/archive/` for completed plans; git history for deleted code
