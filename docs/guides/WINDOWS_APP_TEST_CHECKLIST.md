# Windows App Test Checklist

Manual end-to-end pass for the packaged app. Automated tests are in [Testing notes](../TESTING_NOTES.md); this list covers what only a real microphone, desktop and GPU can show.

## 0) Is it the build I think it is?

1. Build with `scripts\setup\build_windows_exe.ps1` (it fails on a stale or broken bundle; see the [Build guide](../BUILD_GUIDE.md)).
2. Run `dist\VoiceFlow\VoiceFlow.exe --self-check=%TEMP%\voiceflow_self_check.json` with VoiceFlow not running; exit code 0 means all checks passed.
3. After launch, the dock shows **Updated MM-DD HH:MM**: confirm it matches the build you just made.

## 1) First-run setup

1. Start with a clean `%LOCALAPPDATA%\VoiceFlow\config.json` (or set `setup_completed=false`, `show_setup_on_startup=true`).
2. Launch `dist\VoiceFlow\VoiceFlow.exe` (or the release `VoiceFlow-win64.exe`).
3. Confirm the setup wizard opens; click `Step 1: Run Hardware Check (Required)`.
4. Pick one profile and click **Save and Launch VoiceFlow**.
5. Confirm the tray icon and the dock appear and `%LOCALAPPDATA%\VoiceFlow\logs\voiceflow.log` is updating. If it is locked, `logs\active_log_path.txt` points to the fallback log (`%TEMP%\VoiceFlow\voiceflow-<pid>.log`).
6. On a GPU machine the log shows `asr_engine_initialized ... device=cuda compute=float16`.

## 2) Relaunch

1. Exit from the tray and relaunch.
2. The tray icon appears without forcing setup again; tray → **Setup & Defaults** still opens the wizard.
3. `python scripts/dev/test_hotkey_config.py` reports the default hotkey.

## 3) Baseline dictation (Notepad, then VS Code and a browser text area)

1. Short phrase (3-6 words): near-instant.
2. Medium phrase (10-20 words): responsive.
3. Long dictation (40+ seconds, with pauses): completes quickly after release; pauses of 2.5 s or more show up as paragraph breaks.
4. A phrase with a cough or noise: quality stays acceptable; no phantom "Thank you." after a long silence.
5. Text is pasted without Enter.

## 4) Overlay, keys and history

1. While holding `Ctrl+Shift` the overlay shows a waveform, a **Listening** badge, the live caption and a timer (`7s`; `1:05` after a minute). On release the badge goes **Processing/Transcribing → Done**.
2. `Esc` during a recording discards it; nothing is pasted. `Ctrl+Shift+Esc` still opens Task Manager.
3. `Alt+Shift+V` re-pastes the last transcript at the cursor.
4. Tray → **Recent** lists the dictations; clicking one copies it. **Clear history** empties the list.
5. Start a dictation, close the target window before releasing: nothing is pasted, the transcript is in **Recent** (marked *not pasted*) and on the clipboard.
6. Say "new line", "new paragraph" and "bullet, buy milk" as their own phrases; confirm the line breaks and the `- Buy milk.` list line.
7. Run Wispr Flow (if you use it) alongside: its `Ctrl+Alt` hotkey and VoiceFlow's `Ctrl+Shift` do not interfere.

## 5) Runtime log expectations

Look for:

- `asr_engine_initialized ... device=cuda|cpu`
- `transcription_engine path=... model=...`
- `transcription_timing total_ms=... asr_ms=...`
- `hotkey_listener_started backend=...`

Investigate if present: `asr_cuda_init_failed`, `asr_runtime_fallback`, `cuda_runtime_unavailable`, repeated `audio_input_overflow`/`audio_queue_saturated`, repeated blank short clips without a transcript or `blank_fast_retry_applied`.

## 6) Personalization

1. Tray → **Recent History**, then **Correction Review**; correct the same term twice and confirm it appears in `%LOCALAPPDATA%\VoiceFlow\learned_hotwords.json`.
2. Run the nightly job by hand: `.\VoiceFlow_DailyLearning.bat --dry-run`.
3. With the cloud checkbox off (default), the nightly report records `ai_learning_analysis.enabled = false`.

## 7) Stress pass

1. 20 short clips back-to-back.
2. 5 long clips back-to-back.
3. No stuck status, hangs or lost injection; the tray returns to idle each time.
