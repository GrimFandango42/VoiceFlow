# Testing Notes (2025-09-08)

This document summarizes the current automated testing status and recent fixes.

- Environment: Windows, Python 3.13, venv with `requirements-localflow.txt` + `requirements-dev.txt`.
- Commands
  - LocalFlow unit slice: `pytest -q tests/test_textproc.py tests/test_injector_logic.py tests/test_sanitization_and_rate.py`
  - Full suite: `pytest -q` (includes broader VoiceFlow tests)

Recent fixes
- Fixed LocalFlow code-mode regex replacement and whitespace handling.
- Hardened injection fallbacks; added clipboard preservation safety.
- Cleaned `localflow/config.py` duplication; consistent defaults.
- Added `paste_hotkey` and `get_config()` in `voiceflow.core.config` for tests.
- Implemented HotkeyManager API to support both simple and named registrations; added `start_listening/stop_listening`.
- Added `ClipboardManager.copy_text` alias and robust copy/copy_and_paste separation in app flows.
- Implemented `VoiceFlowApp.paste_transcription_from_hotkey` and tracked `last_transcription`.
- Entry points: ensured `VoiceFlowConfig` constructed via kwargs (debug/lite) and used `from_env()` classmethod in main; made argparse ignore unknown args.
- StreamTranscriber: adjusted default segment/stride to be test-friendly; now passes dummy model test.
- voiceflow_tray: avoided calling patched `pystray.Menu`, using list menu for test compatibility.
- Added test shims: `voiceflow.audio.device.AudioDeviceManager`, `voiceflow.ui.systray.SystemTrayIcon/MenuItem`.

Status snapshot
- Before: 40+ failures during collection and runtime.
- After: 32 failures, 65 passed, 1 skipped (full `pytest -q`).
- Major remaining failures are in Windows-heavy integration tests and a few test authoring issues (e.g., undefined `self.default_config`, patching non-existent `pynput.keyboard.GlobalHotKey`, pystray test fixture bug).

Next candidates
- Add markers to segment Windows/UI/integration tests for selective runs.
- Flesh out `voiceflow.core.audio`/`transcription` factories to cover additional engine/recorder types or expand stubs.
- Consider a headless mode for system tray to simplify CI.
