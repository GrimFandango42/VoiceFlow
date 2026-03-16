# VoiceFlow Technical Overview

## Active Runtime Entry Points

- `voiceflow.py` -> `voiceflow.ui.cli_enhanced:main`
- `src/voiceflow/ui/cli_enhanced.py` (main app loop)
- `src/voiceflow/ui/setup_wizard.py` (first-run setup + tray settings surface)
- `src/voiceflow/core/asr_engine.py` (ASR backend + model/device routing)

## Runtime Pipeline

1. Hotkey hold starts recording (`integrations/hotkeys_enhanced.py`).
2. Audio capture buffers at 16kHz (`core/audio_enhanced.py`).
3. On release, audio is compacted/guarded (`ui/cli_enhanced.py`).
4. ASR decode runs (`core/asr_engine.py`).
5. Text normalization and formatting (`core/textproc.py`).
6. Injection into target app (`integrations/inject.py`).
7. Tray/overlay status updates (`ui/enhanced_tray.py`, `ui/visual_indicators.py`).

## Config That Matters Most

Defined in `src/voiceflow/core/config.py` and persisted by `utils/settings.py`.

Performance-sensitive fields:

- `model_tier`
- `device`
- `compute_type`
- `latency_boost_enabled`
- `latency_boost_model_tier`
- `enable_pause_compaction`
- `pause_compaction_retry_*` (raw/chunked retry guardrails for sparse output)
- `idle_resume_guard_*` (first-utterance safety policy after long idle periods)
- `idle_resume_skip_pause_compaction*` (prefer raw completeness for the first long post-idle utterance)

Stability and behavior fields:

- `paste_injection`
- `press_enter_after_paste`
- `live_caption_enabled`
- `visual_indicators_enabled`
- `setup_completed`
- `show_setup_on_startup`
- `setup_profile`

## Tray vs Advanced Controls

- Primary user configuration surface: tray menu + overlay/dock panels.
- Primary interaction surfaces are the setup wizard, tray menu, overlay/dock, and history/review panels.
- Advanced tuning remains available through config/env/script controls below.

## Hardware Selection Strategy

- `device=auto` selects CUDA when available, otherwise CPU.
- `model_tier=quick` is adaptive:
  - CPU: `small.en`
  - CUDA: `distil-large-v3`

Compatibility switches:

- `VOICEFLOW_FORCE_CPU=1` to force CPU execution.
- `VOICEFLOW_USE_GPU_VENV=0` to avoid `.venv-gpu` preference in build scripts.

## Command-Line and Environment Controls

Main runtime entrypoint (`voiceflow.ui.cli_enhanced`) currently does not expose user-facing CLI flags.
Power-user controls are environment-based:

- `VOICEFLOW_FORCE_CPU=1`
  - Force CPU runtime selection.
- `VOICEFLOW_USE_GPU_VENV=0`
  - Launcher/build preference for `venv` over `.venv-gpu`.
- `VOICEFLOW_TERMS_PATH` / `VOICEFLOW_TECHNICAL_TERMS_PATH`
  - Override technical terms file path.
  - Default local path is `%LOCALAPPDATA%\LocalFlow\engineering_terms.json` when present.
- `VOICEFLOW_KEEP_CODE_MODE_DEFAULT=1`
  - Preserve default code mode behavior.
- `VOICEFLOW_FEEDBACK_AUDIO=1`
  - Enable feedback audio capture for debugging.
- `VOICEFLOW_FEEDBACK_AUDIO_DIR=<path>`
  - Override feedback audio output path.
- `VOICEFLOW_FEEDBACK_AUDIO_MAX_SECONDS=<float>`
  - Cap per-capture debug audio duration.
- `VOICEFLOW_FEEDBACK_AUDIO_RETENTION_MINUTES=<int>`
  - Retention window for debug audio files.

Daily learning script flags (`voiceflow.ai.daily_learning`):

- `--days-back`
- `--dry-run`
- `--max-history-items`
- `--max-correction-items`
- `--print-json`

## Continual Learning Runtime

- Runtime observation path:
  - `ui/cli_enhanced.py` records finalized transcript deltas into `AdaptiveLearningManager`.
- Batch refinement path:
  - `ai/daily_learning.py` mines recent history plus saved corrections and writes a bounded report.
- Persistence:
  - `%LOCALAPPDATA%\LocalFlow\adaptive_patterns.json`
  - `%LOCALAPPDATA%\LocalFlow\adaptive_audit.jsonl`
  - `%LOCALAPPDATA%\LocalFlow\daily_learning_reports\`

Signal weighting:

- `daily_user_correction` is higher-trust than `daily_auto_analysis`.
- `manual_correction` from correction review feeds the live runtime learner immediately.
- `runtime_transcription` remains active, but needs more repetition than explicit correction feedback to become sticky.
- Raw snippet storage is opt-in; the default release path keeps adaptive audit data leaner.
- Daily learning reports include an `adaptive_snapshot` with top active replacements and recent domain-token counts.

## Observability

Primary runtime log:

- `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

Useful event lines:

- `asr_engine_initialized`
- `transcription_engine`
- `transcription_timing`
- `asr_cuda_init_failed`
- `asr_runtime_fallback`

Log discovery helper:

- `%LOCALAPPDATA%\LocalFlow\logs\active_log_path.txt`
  - Points to the live log file when runtime falls back away from `localflow.log`.

## Runtime Test Suite

Active tests live in `tests/runtime/`.

Run all:

```powershell
pytest -q tests\runtime
```

Length-specific checks:

```powershell
pytest -q tests\runtime\test_transcription_lengths.py
```
