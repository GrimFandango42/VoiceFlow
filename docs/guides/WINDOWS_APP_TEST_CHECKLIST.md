# Windows App Test Checklist

## 1) Launch and Health

1. Launch `VoiceFlow_Quick.bat` (or packaged exe).
2. Confirm tray icon appears.
3. Run `python scripts/dev/test_hotkey_config.py` and confirm default hotkey.
4. Confirm `%LOCALAPPDATA%\LocalFlow\logs\localflow.log` is updating.

## 2) Baseline Dictation

Run in Notepad first, then VS Code and one browser text area.

1. Short phrase (3-6 words): should feel near-instant.
2. Medium phrase (10-20 words): should stay responsive.
3. Long dictation (40+ seconds): should complete quickly after release.
4. Phrase with cough/pause/noise: verify transcript quality remains acceptable.

## 3) Runtime Expectations

Check log lines for:

- `asr_engine_initialized ... device=cuda|cpu`
- `transcription_engine path=... model=...`
- `transcription_timing total_ms=... asr_ms=...`

Flag for investigation if present:

- `asr_cuda_init_failed`
- `asr_runtime_fallback`

## 4) Personalization Features

1. Open `Recent History` from tray.
2. Open `Correction Review`.
3. Run daily learning manually:

```powershell
.\VoiceFlow_DailyLearning.bat --dry-run
```

## 5) Stress Pass

1. Dictate 20 short clips back-to-back.
2. Dictate 5 long clips back-to-back.
3. Confirm no stuck status, hangs, or lost injection.
