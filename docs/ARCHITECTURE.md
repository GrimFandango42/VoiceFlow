# VoiceFlow Architecture

## Scope

How the Python runtime in this repository is put together: Windows-first push-to-talk recording, release-time transcription and text injection. This page also holds the repository layout, the configuration that matters, and the environment controls (it replaces the former `TECHNICAL_OVERVIEW.md` and `REPO_STRUCTURE_REVIEW.md`, now in [`archive/`](archive/)).

## Repository layout

```
src/voiceflow/
  core/           Audio capture, ASR engine, segmenter, streaming preview, text processing,
                  dictation formatting, transcript history, vocabulary, model server (+client)
  integrations/   Global hotkey listener, text injection
  ui/             Setup wizard, tray, overlay + dock + history panel, runtime orchestration
  utils/          Config persistence, logging, validation, build identity, process monitoring
  ai/             Adaptive learning, hotword learning, nightly learning, review queue,
                  course correction (optional; can be disabled)
  models/         Small shared data types (tray state, performance metrics)
  platform/       OS abstraction (factory, contracts, POSIX mock)
  data/           Bundled default vocabulary
scripts/
  setup/          Bootstrap, build, bundle verification, installer, task registration
  dev/            Smoke test, hotkey check, latency log analysis
  capture_screenshots.py   Demo-mode documentation screenshots
tests/runtime/    The regression suite (pytest; see TESTING_NOTES.md)
docs/             These documents (guides/, examples/, archive/, screenshots/)
packaging/windows Installer script and winget manifest template
dev.py            Hot-reload launcher (model server + app); _app_entry.py single-process entry
```

Root launchers: `VoiceFlow.bat` (debug, console), `VoiceFlow_Quick.bat` (no cleanup preamble), `VoiceFlow_Silent.bat` / `VoiceFlow_Tray.vbs` (no console), `VoiceFlow_DailyLearning.bat`, `Install_VoiceFlow.bat`, `Bootstrap_Windows.bat`, `start_source.bat`. See [How to launch](HOW_TO_LAUNCH.md).

## Runtime topologies

| Topology | Processes | Started by |
|---|---|---|
| Packaged | One: `VoiceFlow.exe` (PyInstaller one-dir or one-file), model loaded in-process, CUDA DLLs bundled | `dist\VoiceFlow\VoiceFlow.exe` |
| Source, single process | One: app + model | `python _app_entry.py` |
| Source, dev | Two: a **model server** (loads Whisper once, `127.0.0.1:8765`) and the **app** (UI, audio, hotkeys, restarted on each saved `.py`) | `python dev.py` |

The model server restarts only when `core/asr_engine.py`, `core/model_server.py` or `core/preloader.py` change, which is what makes hot reload fast. In the packaged app and in single-process mode the engine is in-process.

## Data flow

```text
Hold PTT (Ctrl+Shift)
  -> hotkey listener starts a recording; the overlay appears with a timer
  -> one shared microphone stream feeds a pre-roll buffer and the recording ring
  -> optional live caption (streaming preview) updates the overlay

Release (confirmed ~0.12 s later; recording continues ~0.35 s more, then a 0.25 s drain)
  -> target window is captured at the moment of release (inject_target_policy=release)
  -> audio finalised; recordings >= 20 s are cut at pauses (segmenter) and decoded piece by piece,
     silence gated by Silero VAD; shorter ones go through pause compaction / guards
  -> ASR decode (faster-whisper; hotwords + vocabulary prompt on every window)
  -> normalisation, spoken commands, filler/stutter cleanup, destination-aware formatting
  -> transcript saved to history BEFORE the paste
  -> injector pastes into the target (clipboard restored on a timer, off the critical path)
  -> overlay shows Done / Error; tray and dock return to idle
```

Timing budget and the knobs for each step: [Latency budget](LATENCY_BUDGET.md).

## Components

### UI (`ui/`)
- `cli_enhanced.py` - application lifecycle, hotkey registration, the transcription manager (worker with timeouts), session tracking, startup/shutdown, watchdog.
- `visual_indicators.py` - the overlay (waveform, status badge, caption, recording timer), the always-on dock (state + build date, History/Hide, draggable), and the history / correction-review panel. Runs its own Tk thread fed by a bounded command queue, so callers on other threads never touch Tk.
- `enhanced_tray.py` - tray icon and menu (toggles, **Recent**, **Setup & Defaults**, **PTT Hotkey** presets). The Recent submenu is rebuilt every time it opens.
- `setup_wizard.py` - first-run / "Setup & Defaults" window: hardware check, profiles, advanced overrides, the cloud-learning consent toggle.
- `visual_config.py` - overlay sizing, colours and persisted dock/history positions.

### Integrations (`integrations/`)
- `hotkeys_enhanced.py` - hold-to-record lifecycle, release confirmation (a one-shot timer plus a backup poller; "is the key still down" asks Windows via `GetAsyncKeyState`), tail buffer, synthetic-event suppression.
- `inject.py` - clipboard paste and typed injection, sanitisation, rate limiting, target-window capture and refocus, asynchronous clipboard restore.

### Core (`core/`)
- `audio_enhanced.py` - sounddevice capture; callbacks only copy a block onto a lock-free queue and a capture worker moves blocks into the ring, so a slow reader never stalls the audio thread.
- `asr_engine.py` - model tiers, CPU/CUDA selection and fallback, hotwords, decode entry points. `model_server.py` / `model_server_client.py` - the dev-mode server and its client.
- `segmenter.py` - pause-based cutting of long recordings; `silence_artifacts.py` - classifier for "Thank you."-style silence hallucinations; `audio_preprocessing.py` - compaction and guards.
- `streaming.py` - the live caption; `preloader.py` - background warm-up.
- `textproc.py`, `dictation_format.py` - cleanup passes, vocabulary rewrites, spoken commands (new line / new paragraph / bullet), filler and false-start removal.
- `history.py` - the local transcript history (last 50, atomic writes) behind the tray's Recent list and the re-paste key. `vocab.py` - Whisper prompt and the seeded `custom_vocabulary.txt`.
- `config.py` - the typed `Config` dataclass with every default.

### Utilities (`utils/`)
`settings.py` (config load/save/migration, bounded JSONL helpers), `logging_setup.py`, `build_info.py` (which build is this, from the bundle stamp, git or file time), `guardrails.py`, `validation.py`, `idle_aware_monitor.py` (hang and memory checks), `process_monitor.py`.

### Learning (`ai/`)
Optional and local by default. `adaptive_memory.py` (runtime rules from transcript deltas), `hotword_learning.py` (terms corrected twice become hotwords), `daily_learning.py` (nightly replay and report; the optional cloud step lives here and is off by default), `review.py` (suggestions queued for you, never auto-applied), `course_corrector.py` (delegates to `dictation_format`).

## Learning

1. **Runtime loop** - finalised transcript deltas go to `adaptive_memory`, producing bounded local replacement rules and token frequencies.
2. **Correction loop** - explicit corrections from Correction Review rank higher than auto-inferred ones, feed the live learner for the same session, and (twice-corrected terms) become Whisper hotwords in `learned_hotwords.json`.
3. **Nightly batch** - `daily_learning` replays history and corrections, writes `daily_learning_reports/`, and may queue suggestions in `pending_review.jsonl`. The cloud analysis step is opt-in; see [Security & Privacy](guides/SECURITY_AND_PRIVACY.md).

Signal weights: `daily_user_correction` > `daily_auto_analysis`; `manual_correction` applies immediately; `runtime_transcription` needs more repetition. Learning and audit records older than `adaptive_retention_hours` (default 72) are purged.

## State model

Visible states: `idle`, `listening`, `processing`, `transcribing`, `complete`, `error` - mirrored by the tray icon, the overlay badge (Listening / Processing / Transcribing / Done / Error) and the dock.

## Concurrency

Hotkey events are event-driven; ASR runs in a managed worker with timeouts so the UI never blocks; the overlay owns one Tk thread; audio callbacks are copy-only; post-processing and checkpoint work are kept off the capture path. Single-instance and duplicate-process guards prevent two hotkey listeners.

## Configuration that matters

Defined in `core/config.py`, persisted by `utils/settings.py` (which also migrates older values).

| Area | Fields |
|---|---|
| Model / device | `model_tier` (`quick`), `device` (`auto`), `compute_type`, `latency_boost_*`, `asr_hotwords` |
| Keys | `hotkey_ctrl/shift/alt/key`, `repaste_hotkey`, `cancel_recording_key`, `ptt_tail_buffer_seconds` |
| Long dictation | `segmented_transcription_enabled`, `silence_vad_gate_enabled`, `max_recording_seconds` (300), `chat_preserve_newlines` |
| Injection | `paste_injection`, `press_enter_after_paste`, `inject_target_policy` (`release`), `restore_clipboard`, `clipboard_restore_delay_ms` |
| History / learning | `history_max_items` (50), `learned_hotwords_*`, `adaptive_retention_hours`, `adaptive_ai_analysis_enabled` (false) |
| Audio | `audio_single_stream`, `audio_queue_max_seconds`, `audio_input_latency`, `stop_drain_seconds` |
| UI | `visual_indicators_enabled`, `visual_dock_enabled`, `audio_feedback_beeps`, `visual_animation_quality`, `visual_reduced_motion` |
| Setup | `setup_completed`, `show_setup_on_startup`, `setup_profile` |

Model tiers: `tiny` -> `tiny.en`; `quick` -> `small.en` (CPU) / `distil-large-v3` (CUDA); `balanced` -> the `distil-large-v3.5` profile, which loads the same faster-whisper distil-large-v3 weights; `quality` -> `large-v3`. CUDA needs `cublas64_12.dll` and `cudnn_ops64_9.dll`.

### Environment controls

| Variable | Effect |
|---|---|
| `VOICEFLOW_FORCE_CPU=1` | Force CPU execution |
| `VOICEFLOW_USE_GPU_VENV=0` | `.bat` launchers and the build prefer `venv` over `.venv-gpu` |
| `VOICEFLOW_TORCH_LIB_DIR`, `VOICEFLOW_CUDA_DLL_DIR` | Extra folders to search for the CUDA runtime DLLs |
| `VOICEFLOW_CUDA_PROBE_BUNDLE=0` | Do not probe `<checkout>\dist\VoiceFlow\_internal\torch\lib` (the tests set this) |
| `VOICEFLOW_MODEL_SERVER_ENABLED`, `_PORT`, `_LOAD_TIMEOUT` | Dev-mode model server (set by `dev.py`; default port 8765, load timeout 120 s) |
| `VOICEFLOW_SKIP_SETUP_UI=1` | Do not open the startup wizard |
| `VOICEFLOW_VOCABULARY_PATH` | Override `custom_vocabulary.txt` |
| `VOICEFLOW_TERMS_PATH`, `VOICEFLOW_TECHNICAL_TERMS_PATH` | Override the terms file (default `%LOCALAPPDATA%\VoiceFlow\engineering_terms.json`) |
| `VOICEFLOW_KEEP_CODE_MODE_DEFAULT=1` | Preserve the default code-mode behaviour |
| `VOICEFLOW_FEEDBACK_AUDIO`, `_DIR`, `_MAX_SECONDS`, `_RETENTION_MINUTES` | Debug audio capture (off by default) |

The nightly job's flags (`python -m voiceflow.ai.daily_learning`): `--days-back`, `--dry-run`, `--max-history-items`, `--max-correction-items`, `--print-json`.

## Persistence and observability

Data directory: `%LOCALAPPDATA%\VoiceFlow` (`~/.voiceflow` on non-Windows). The full list of files is in [Security & Privacy](guides/SECURITY_AND_PRIVACY.md#data-stored-locally). The log is `logs\voiceflow.log` (a fallback path is recorded in `logs\active_log_path.txt`). Useful lines: `asr_engine_initialized` (device and compute type), `transcription_engine`, `transcription_timing` (analyse with `scripts/dev/log_latency.py`), `asr_cuda_init_failed`, `asr_runtime_fallback`, `cuda_runtime_unavailable`, `segment_suppressed`, `longrun_health`.

## Build identity and the self-check

`utils/build_info.py` answers "which build is this?" from a stamp written by the build script (`src/voiceflow/_build_stamp.py`, never committed), falling back to git and then the file time; the dock shows only the build date. The packaged app also accepts `--self-check=<json>`, which imports the app's modules from the bundle, runs the VAD through the bundled onnxruntime and loads the bundled CUDA DLLs, then exits before any tray, hotkey or microphone setup. The build runs it and fails on any problem ([Build guide](BUILD_GUIDE.md)).

## Design principles

- Keep audio capture and ASR on the critical path only; keep overlay work off it.
- Full transcription at release is the source of truth; the live caption is only a preview.
- Save the transcript before the paste; never lose recognised text.
- Adaptive model/device selection with an announced fallback to CPU.
- Local first: nothing leaves the machine unless you opt in.

## Failure handling

Worker timeouts prevent indefinite hangs; the watchdog treats a recording as healthy while audio blocks keep arriving and flags it only after a 15 s stall or a 30-minute hold; a ring buffer bounds memory (a longer hold keeps the latest audio and logs `recording_ring_wrapped`); sanitisation and injection guards reduce malformed output; tray and overlay clean up on shutdown and restart.

## Platform adapter seams (for forks)

| Seam | Files |
|---|---|
| Hotkeys | `integrations/hotkeys_enhanced.py` (keep the start/stop callback contract) |
| Injection and focus | `integrations/inject.py` |
| Tray / menu | `ui/enhanced_tray.py` |
| Launch and packaging | `scripts/setup/*`, `packaging/windows/*`, `.github/workflows/*` |

Porting flow: confirm the terminal baseline (`core` + `ui/cli_enhanced.py`); replace the hotkey backend; replace injection; add a tray replacement or run trayless; run `pytest -q tests/runtime` and add OS-specific tests; validate short, medium and long dictation against the [latency budget](LATENCY_BUDGET.md); create OS-native bootstrap/build scripts. Details in [Forking guide](guides/FORKING_AND_PLATFORM_GUIDE.md).
