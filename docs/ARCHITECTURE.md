# VoiceFlow Architecture

## Scope

This document describes the current VoiceFlow runtime architecture in this repository:

- Python application
- Windows-first desktop workflow
- push-to-talk recording with release-time transcription and text injection

It intentionally does not describe archived/legacy Tauri, React, or Rust designs.

## System Overview

VoiceFlow is a process-local pipeline with five major layers:

1. `ui`: tray + overlay + runtime orchestration
2. `integrations`: global hotkeys and text injection
3. `core`: audio capture, ASR, streaming preview, text processing
4. `utils`: config persistence, logging, validation, monitoring
5. `ai` (optional): course correction, command mode, adaptive learning

Primary runtime entrypoint:
- `src/voiceflow/ui/cli_enhanced.py`

## High-Level Data Flow

```text
Hold PTT
  -> hotkey listener enters recording state
  -> audio recorder buffers microphone samples
  -> optional streaming preview updates overlay

Release PTT
  -> recorder finalizes audio buffer
  -> transcription manager runs ASR job
  -> transcript normalization + formatting + optional AI cleanup
  -> injector writes text to active target
  -> tray/overlay status returns to idle
```

## Component Map

### UI Layer

- `src/voiceflow/ui/cli_enhanced.py`
  - top-level app lifecycle
  - transcription manager and session tracking
  - startup/shutdown handling and monitoring
- `src/voiceflow/ui/enhanced_tray.py`
  - tray icon status and menu actions
  - toggles for code mode, injection mode, dock visibility, PTT presets
- `src/voiceflow/ui/visual_indicators.py`
  - overlay status rendering
  - audio-reactive indicator updates
  - recent-history panel behavior

### Integration Layer

- `src/voiceflow/integrations/hotkeys_enhanced.py`
  - hold-to-record lifecycle
  - release confirmation debounce
  - tail-buffer handling to avoid sentence cutoff
  - synthetic event suppression for injection safety
- `src/voiceflow/integrations/inject.py`
  - clipboard paste and keyboard typing injection paths
  - sanitization and rate limiting
  - optional target-window capture/focus protection

### Core Layer

- `src/voiceflow/core/audio_enhanced.py`
  - low-latency microphone capture and buffering
- `src/voiceflow/core/asr_engine.py`
  - model tiering and transcription execution
  - CPU/CUDA runtime selection and fallbacks
- `src/voiceflow/core/streaming.py`
  - partial preview transcriptions while recording
  - bounded partial audio window for stability
- `src/voiceflow/core/textproc.py`
  - normalization and formatting
  - code-mode term mapping
- `src/voiceflow/core/preloader.py`
  - background model warm-up to reduce first-use latency

### Utility Layer

- `src/voiceflow/core/config.py`
  - runtime defaults and feature flags
- `src/voiceflow/utils/settings.py`
  - persisted config load/save and migration
- `src/voiceflow/utils/logging_setup.py`
  - async rotating file logs
- `src/voiceflow/utils/idle_aware_monitor.py`
  - hang/memory state checks for long-running sessions

### Optional AI Layer

- `src/voiceflow/ai/course_corrector.py`
- `src/voiceflow/ai/command_mode.py`
- `src/voiceflow/ai/adaptive_memory.py`

These are intentionally optional and can be disabled for speed-first operation.

## Runtime Concurrency Model

- Hotkey events and recording lifecycle are event-driven.
- ASR execution is isolated through a managed worker (`EnhancedTranscriptionManager`) to prevent UI blocking.
- Post-processing/checkpoint work is separated from critical capture state.
- Single-instance and duplicate-process guards are used to avoid competing hotkey listeners.

## State Model

Primary visible states:
- `idle`
- `listening`
- `processing`
- `transcribing`
- `complete`
- `error`

State transitions are reflected in both tray and overlay to keep behavior transparent.

## Configuration and Persistence

Windows paths:
- config: `%LOCALAPPDATA%\LocalFlow\config.json`
- logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

`settings.py` includes migration logic for legacy performance values to reduce medium/long dictation latency regressions.

## Performance Design Principles

- Keep audio capture and ASR on the critical path only.
- Keep overlay/animation work off the ASR critical path.
- Prefer release-time full transcription for reliability; use partials for preview only.
- Use adaptive model/device settings with safe fallback to CPU.

## Failure Handling

- Worker timeouts prevent indefinite hangs during transcription.
- Input sanitization and injection guards reduce malformed output risk.
- Idle-aware monitor surfaces memory and hang warnings for long sessions.
- Tray/overlay cleanup paths are present for shutdown/restart resilience.

## Platform Notes

- This architecture is validated for Windows.
- Linux/macOS ports need platform-specific replacements for:
  - global hotkeys
  - text injection semantics
  - tray/menu bar behavior
