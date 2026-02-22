# VoiceFlow Technical Overview

## Active Runtime Entry Points

- `voiceflow.py` -> `voiceflow.ui.cli_enhanced:main`
- `src/voiceflow/ui/cli_enhanced.py` (main app loop)
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

Stability and behavior fields:

- `paste_injection`
- `press_enter_after_paste`
- `live_caption_enabled`
- `visual_indicators_enabled`

## Tray vs Advanced Controls

- Primary user configuration surface: tray menu + overlay/dock panels.
- No separate command-center window is active in the current runtime.
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

## Observability

Primary runtime log:

- `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

Useful event lines:

- `asr_engine_initialized`
- `transcription_engine`
- `transcription_timing`
- `asr_cuda_init_failed`
- `asr_runtime_fallback`

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
