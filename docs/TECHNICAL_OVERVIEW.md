# VoiceFlow Technical Overview

## What This Covers

This guide is the code-oriented companion to `docs/ARCHITECTURE.md`. It focuses on:

- runtime entrypoints
- key modules and responsibilities
- operational settings that affect speed/accuracy
- practical debugging and verification commands

## Runtime Entry Points

Primary runtime:
- `src/voiceflow/ui/cli_enhanced.py`

Launch scripts (Windows):
- `VoiceFlow.bat`
- `VoiceFlow_Quick.bat`
- `VoiceFlow_Silent.bat`
- `tools/launchers/LAUNCH_CONTROL_CENTER.bat`

Additional wrapper:
- `voiceflow.py` (profile-based launcher path)

## Core Runtime Sequence

1. `EnhancedPTTHotkeyListener` starts recording on hold.
2. `EnhancedAudioRecorder` captures 16 kHz mono audio.
3. Optional preview path (`StreamingTranscriber`) emits partial captions.
4. On release, the finalized buffer is submitted to ASR (`ModernWhisperASR`).
5. Text normalization and formatting runs (`textproc` + optional AI layer).
6. Injection path writes output into the target app (`ClipboardInjector`).
7. Tray/overlay state transitions to complete, then idle.

## Key Modules

### `src/voiceflow/core/config.py`

Holds runtime defaults:
- hotkey behavior (modifier-only default and tail buffer)
- ASR model tier/device/compute settings
- pause compaction and checkpoint controls
- visual indicator and injection behavior

### `src/voiceflow/utils/settings.py`

Persists config and applies compatibility migrations:
- config path: `%LOCALAPPDATA%\LocalFlow\config.json`
- migration of legacy pause-compaction values
- optional CUDA auto-preference when runtime checks pass

### `src/voiceflow/core/asr_engine.py`

ASR model orchestration:
- model tier selection
- device/compute mode behavior
- transcription calls used by both streaming and final paths

### `src/voiceflow/core/streaming.py`

Partial preview engine:
- bounded trailing audio window for stable partial cost
- periodic partial emissions during active hold
- optional final pass behavior on stop

### `src/voiceflow/integrations/hotkeys_enhanced.py`

Push-to-talk reliability layer:
- explicit key lifecycle tracking
- release confirmation debounce
- tail-buffer extension
- synthetic-event suppression to prevent false stops

### `src/voiceflow/integrations/inject.py`

Output delivery layer:
- sanitize outgoing text
- rate-limit injections
- choose between clipboard paste and direct typing
- optional safe target-window behavior for live checkpoint injections

### `src/voiceflow/ui/visual_indicators.py`

Visual feedback:
- listening/processing/transcribing/complete/error states
- dock and recent-history behavior
- amplitude-style signal visualization hooks

## Speed and Accuracy Controls

Most impactful fields in `Config`:
- `model_tier`, `model_name`
- `device`, `compute_type`
- `latency_boost_enabled`, `latency_boost_model_tier`
- `enable_pause_compaction` and related pause compaction fields
- `live_caption_enabled`
- `live_flush_during_hold` and `live_checkpoint_inject` (stability-sensitive)

Environment variables:
- `VOICEFLOW_FORCE_CPU=1`
- `VOICEFLOW_USE_GPU_VENV=0`

## Monitoring and Logging

- async app log: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`
- monitor warnings visible in console for high memory/hang risk
- runtime perf prints include:
  - audio duration
  - processing duration
  - realtime factor (RTF)
  - rolling/session averages

## Testing and Validation

Recommended local slice:

```powershell
python scripts\dev\quick_smoke_test.py
pytest -q tests\test_textproc.py tests\test_injector_logic.py tests\test_sanitization_and_rate.py
```

Broader pass:

```powershell
pytest -q
```

Hardware/audio sanity:

```powershell
python scripts\list_audio_devices.py
```

## Common Regression Areas

- duplicate process listeners causing hotkey instability
- focus drift during live/incremental injection attempts
- long-utterance latency regressions from config drift
- overlay logic accidentally coupled to ASR critical path

## Extension Guidance

- Keep ASR critical path minimal and deterministic.
- Add UI/animation features behind config flags.
- Avoid injecting text during active hold unless focus guarantees are strong.
- Add tests for any hotkey state machine changes before merging.
