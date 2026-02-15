# VoiceFlow Test Guide

## Scope

This repository contains a large mix of test suites:
- active regression tests used in current development
- older/experimental suites retained for reference

Use the recommended command set below for reliable signal.

## Recommended Test Commands

### Fast health validation

```powershell
python scripts\dev\quick_smoke_test.py
```

### Focused regression slice

```powershell
pytest -q tests\test_textproc.py tests\test_injector_logic.py tests\test_sanitization_and_rate.py
```

### Broader suite

```powershell
pytest -q
```

## Test Categories

- `tests/unit/` - unit-focused tests (fastest signal)
- `tests/integration/` - integration and platform behaviors
- `tests/stability/` - long-running reliability tests
- `tests/performance/` - performance evaluation tools

## Notes

- Some legacy tests still reference historical module paths and may require migration.
- For runtime changes affecting hotkeys/injection, always run manual app checks in:
  - Notepad
  - VS Code
  - browser textareas

## Debugging Tips

```powershell
pytest -q -k "<pattern>"
pytest -q --maxfail=1
pytest -q tests\integration\windows
```
