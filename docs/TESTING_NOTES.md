# Testing Notes

## Active Suite

Use the maintained runtime suite:

```powershell
pytest -q tests\runtime
```

## Quick Validation Loop

```powershell
python scripts\dev\quick_smoke_test.py
pytest -q tests\runtime\test_transcription_lengths.py
```

## Manual Dictation Matrix

Validate in Notepad and VS Code:

1. Short clip (3-6s)
2. Medium clip (10-20s)
3. Long clip (40-90s, with pauses/coughs)

Check:

- release-to-text latency
- transcript quality
- target-app injection reliability
- tray state returns to idle

## Logs

- `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

Look for:

- `transcription_engine`
- `transcription_timing`
- `asr_runtime_fallback` (should not appear in normal CUDA runs)
