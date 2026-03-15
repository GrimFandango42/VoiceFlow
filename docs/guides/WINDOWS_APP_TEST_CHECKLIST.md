# Windows App Test Checklist

## 1) First-Run Setup Pass

1. Launch the packaged executable:
   - local bundle: `dist\VoiceFlow\VoiceFlow.exe`
   - or release asset: `VoiceFlow-win64.exe`
2. If testing onboarding, start with a clean `%LOCALAPPDATA%\LocalFlow\config.json` or reset setup markers first.
3. Confirm setup wizard opens.
4. Click `Step 1: Run Hardware Check (Required)`.
5. Pick one profile and click `Save And Launch`.
6. Confirm tray icon appears after runtime starts.
7. Confirm `%LOCALAPPDATA%\LocalFlow\logs\localflow.log` is updating.
8. If `localflow.log` is locked, confirm fallback logging works in `localflow-<pid>.log`.

## 2) Relaunch and Runtime Health

1. Fully exit VoiceFlow.
2. Relaunch the packaged exe.
3. Confirm tray icon appears without forcing setup again.
4. Open `Setup & Defaults` from tray and confirm the wizard can still be reopened.
5. Run `python scripts/dev/test_hotkey_config.py` and confirm default hotkey.

## 3) Baseline Dictation

Run in Notepad first, then VS Code and one browser text area.

1. Short phrase (3-6 words): should feel near-instant.
2. Medium phrase (10-20 words): should stay responsive.
3. Long dictation (40+ seconds): should complete quickly after release.
4. Phrase with cough/pause/noise: verify transcript quality remains acceptable.
5. Confirm default runtime behavior pastes text without auto-sending Enter.

## 4) Runtime Expectations

Check log lines for:

- `asr_engine_initialized ... device=cuda|cpu`
- `transcription_engine path=... model=...`
- `transcription_timing total_ms=... asr_ms=...`
- `hotkey_listener_started backend=...`

Flag for investigation if present:

- `asr_cuda_init_failed`
- `asr_runtime_fallback`
- repeated blank short clips without either transcript output or `blank_fast_retry_applied`

## 5) Personalization Features

1. Open `Recent History` from tray.
2. Open `Correction Review`.
3. Run daily learning manually:

```powershell
.\VoiceFlow_DailyLearning.bat --dry-run
```

## 6) Stress Pass

1. Dictate 20 short clips back-to-back.
2. Dictate 5 long clips back-to-back.
3. Confirm no stuck status, hangs, or lost injection.
