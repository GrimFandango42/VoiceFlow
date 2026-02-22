# Tests

Active regression tests are in `tests/runtime/`.

## Run

```powershell
pytest -q tests\runtime
```

## Focused Transcription-Length Checks

```powershell
pytest -q tests\runtime\test_transcription_lengths.py
```

## Quick Runtime Smoke

```powershell
python scripts\dev\quick_smoke_test.py
```
