# Testing Notes

## Scope

These notes describe practical validation for the current Windows-first VoiceFlow runtime.

## Recommended Local Validation

### 1. Environment smoke check

```powershell
python scripts\dev\quick_smoke_test.py
```

### 2. Fast regression slice

```powershell
pytest -q tests\test_textproc.py tests\test_injector_logic.py tests\test_sanitization_and_rate.py
```

### 3. Broader suite

```powershell
pytest -q
```

## Manual Runtime Matrix

Use these dictation scenarios for release validation:

1. Short utterance: 3-5 seconds.
2. Medium utterance: 8-12 seconds.
3. Long utterance: 20-40 seconds with pauses.

For each run, verify:
- no dropped text
- stable release-to-text latency
- correct target-window injection
- no sticky listening state after release
- overlay/tray behavior remains responsive

## High-Risk Areas

- hotkey press/release state machine
- live preview/checkpoint handling during hold
- focus handling around injection
- medium/long utterance latency tuning

## Helpful Diagnostics

```powershell
python scripts\list_audio_devices.py
python scripts\debugging\debug_hang_issue.py
python scripts\debugging\debug_nonetype_issue.py
```

Logs:
- `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

## Notes For Fork Maintainers

- Windows integration tests are more representative than generic unit tests for hotkey/injection behavior.
- If you change hotkey or injection internals, run manual validation in at least:
  - Notepad
  - VS Code
  - browser text inputs
