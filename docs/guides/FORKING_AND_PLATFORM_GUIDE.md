# Forking And Platform Guide

This guide is the practical handoff for developers who want to fork VoiceFlow and adapt it to their own workflow.

## Scope

- Primary target today: Windows desktop dictation with push-to-talk and text injection.
- Current strengths: short/medium/long dictation speed, stable release-to-text flow, good practical accuracy for LLM-assisted coding workflows.
- Current weak spots: cross-platform parity, some visual polish details, and deeper CI coverage for UI/integration behavior.

## Architecture Seams You Will Replace First

These are the code areas most forks should touch:

1. Hotkeys:
   - `src/voiceflow/integrations/hotkeys_enhanced.py`
2. Injection/focus behavior:
   - `src/voiceflow/integrations/inject.py`
3. Tray/menu runtime:
   - `src/voiceflow/ui/enhanced_tray.py`
4. OS bootstrap/packaging:
   - `scripts/setup/*`
   - `.github/workflows/build-release.yml`
   - `packaging/windows/*`

Keep these areas stable while porting:

- `src/voiceflow/core/*` (audio/asr/streaming/text)
- `src/voiceflow/ai/*` (optional enhancement layer)
- `src/voiceflow/utils/*` (config/logging/monitoring)

## Windows Baseline (Current Known-Good Path)

- This is the primary validated runtime.
- Setup wizard + tray controls are tuned around this flow.
- If CUDA is available, runtime can use GPU defaults automatically.

## Linux And macOS Porting Strategy

### WSL note

- WSL is useful for development tooling, tests, and model/runtime experimentation.
- For full desktop hotkey/injection/tray behavior, run a native desktop path (Windows/macOS/Linux host), not pure headless WSL.

### Native platform realities

- Linux:
  - X11 and Wayland behave differently. Do not assume one injection or hotkey path will cover both.
  - Plan for a clipboard-first fallback if native direct injection is restricted by compositor or desktop environment policy.
- macOS:
  - Expect Microphone, Accessibility, and Input Monitoring permission flows to be part of first-run UX.
  - Treat a signed app bundle, a documented manual permission path, or both as part of the porting story.
- Both:
  - Keep setup instructions explicit about permissions, tray lifecycle, and how users relaunch the packaged app.
  - Preserve the config format where possible so docs, learning files, and migration logic stay shared across forks.

### Step 1: Bring up core runtime in terminal mode

- Start with `voiceflow.ui.cli_enhanced` and disable tray/injection assumptions as needed.
- Validate ASR, audio capture, and text processing before native UX work.

### Step 2: Replace hotkey backend

- Implement global hotkey behavior for target platform/desktop environment.
- Keep callback contract intact: start recording on hold, stop on release.

### Step 3: Replace injection backend

- Implement platform-native insertion and target-focus semantics.
- Expect OS-specific permission constraints (macOS Accessibility, Wayland restrictions, etc.).

### Step 4: Rebuild tray/menu integration

- Map tray actions to native menu bar/status item conventions.
- Preserve core actions:
  - setup/defaults
  - code mode toggle
  - injection mode toggle
  - history/review entry points

### Step 5: Add platform packaging

- Create bootstrap/build scripts for your OS.
- Keep runtime config format stable to reduce fork drift.
- Recommended release targets:
  - macOS: app bundle plus notarized DMG or ZIP.
  - Linux: AppImage, distro packages, or a documented clipboard-first CLI mode if desktop integration is incomplete.

## Testing Guidance For Forks

### Quick runtime checks

- `pytest -q tests/runtime`
- `pytest -q tests/runtime/test_injector_logic.py tests/runtime/test_hotkeys_enhanced.py`

### Manual behavior checks

- Short dictation: 3-5 seconds.
- Medium dictation: 8-12 seconds.
- Long dictation: 20-40 seconds with pauses.
- Verify:
  - no text loss
  - release-to-text latency
  - acceptable punctuation/formatting
  - start/stop stability
  - focus/injection reliability

### Platform-specific checks

- Linux:
  - test X11 and Wayland separately
  - verify global hotkeys under your desktop environment
  - verify clipboard fallback behavior when direct injection is blocked
- macOS:
  - verify Accessibility/Input Monitoring permission flow
  - verify menu bar app lifecycle and clipboard behavior
  - verify packaged relaunch after permission grants and system restarts

## Config Notes For Forks

- Windows config path:
  - `%LOCALAPPDATA%\\VoiceFlow\\config.json`
- Non-Windows fallback config path:
  - `~/.voiceflow/config.json`

Performance-critical fields:

- `device`
- `compute_type`
- `model_tier`
- `pause_compaction_*`
- `latency_boost_*`

Compatibility override:

- `VOICEFLOW_FORCE_CPU=1`
