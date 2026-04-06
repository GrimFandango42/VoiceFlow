# VoiceFlow Architecture

## Scope

This document describes the current VoiceFlow runtime architecture in this repository:

- Python application
- Windows-first desktop workflow (primary validated path)
- push-to-talk recording with release-time transcription and text injection

It focuses on the Python runtime that ships from this repository today.

## System Overview

VoiceFlow is a process-local pipeline with five major layers:

1. `ui`: setup wizard + tray + overlay + runtime orchestration
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
- `src/voiceflow/ui/setup_wizard.py`
  - first-run defaults wizard before runtime boot
  - hardware-aware default recommendations
  - advanced override toggles for power users
- `src/voiceflow/ui/enhanced_tray.py`
  - tray icon status and menu actions
  - toggles for code mode, injection mode, dock visibility, PTT presets
  - setup/defaults re-entry action for post-install tuning
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

## Platform Adapter Boundaries

These modules are the highest-value seams for macOS/Linux forks:

- Hotkey backend seam:
  - `src/voiceflow/integrations/hotkeys_enhanced.py`
  - Replace global key hook implementation while preserving start/stop callback contract.
- Injection backend seam:
  - `src/voiceflow/integrations/inject.py`
  - Replace target-window/focus capture and text insertion primitives.
- Tray/menu seam:
  - `src/voiceflow/ui/enhanced_tray.py`
  - Replace tray runtime integration for native menu-bar/tray behavior.
- Launch/packaging seam:
  - `scripts/setup/*`, `packaging/windows/*`, `.github/workflows/ci.yml`
  - Keep core runtime unchanged; fork setup/packaging path per OS.

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
- `src/voiceflow/ai/daily_learning.py`

These are intentionally optional and can be disabled for speed-first operation.

## Continual Learning Architecture

VoiceFlow currently has two learning loops:

1. Runtime loop
   - `ui/cli_enhanced.py` sends finalized transcript deltas into `ai/adaptive_memory.py`.
   - This produces bounded local replacement rules plus recent token frequency data.
2. Batch loop
   - `ai/daily_learning.py` replays saved correction-review feedback and recent history.
   - It promotes higher-trust user corrections faster than low-trust auto-analysis and writes auditable daily reports.

Current behavior:

- Correction review is the strongest input for accent and work-domain adaptation.
- Saved correction review now feeds the active runtime learner as a same-session signal instead of waiting entirely for the next batch pass.
- Runtime observations remain active for repeated organic misses.
- Daily reports expose both top learned replacement rules and recent domain-token signals.

Near-term roadmap:

- Expand from token-level replacement rules into short phrase and project-vocabulary patterns.
- Add a user-facing rule inspector so learned replacements can be reviewed, pinned, or removed from the tray UI.
- Add per-destination formatting preferences so terminal/chat/document outputs can learn different style expectations.

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

Default runtime data paths:
- Windows:
  - config: `%LOCALAPPDATA%\VoiceFlow\config.json`
  - logs: `%LOCALAPPDATA%\VoiceFlow\logs\voiceflow.log`
- Non-Windows fallback:
  - config: `~/.voiceflow/config.json`
  - logs: `~/.voiceflow/logs/voiceflow.log`

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
- Linux/macOS ports should preserve core ASR/audio/text pipeline and swap integration seams first.

## Porting Flow For Forks

1. Confirm baseline in terminal mode (`core` + `ui/cli_enhanced.py`) before any native UI work.
2. Implement hotkey backend replacement (`integrations/hotkeys_enhanced.py` seam).
3. Implement injection backend replacement (`integrations/inject.py` seam).
4. Add tray/menu replacement (`ui/enhanced_tray.py` seam) or run trayless first.
5. Run runtime tests (`pytest -q tests/runtime`) and add OS-specific integration tests.
6. Validate short/medium/long dictation manually against release-to-text latency targets.
7. Create OS-native bootstrap/build scripts, keeping core runtime unchanged.
