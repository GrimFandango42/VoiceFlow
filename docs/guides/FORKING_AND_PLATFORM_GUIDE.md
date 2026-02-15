# Forking And Platform Guide

This guide is the practical handoff for developers who want to fork VoiceFlow and adapt it to their own workflow.

## Scope

- Primary target today: Windows desktop dictation with push-to-talk and text injection.
- Current strengths: short/medium/long dictation speed, stable release-to-text flow, good practical accuracy for LLM-assisted coding workflows.
- Current weak spots: cross-platform parity, some visual polish details, and deeper CI coverage for UI/integration behavior.

## What Worked Well

- Keeping ASR/transcription separate from animation logic.
- CUDA migration for compatible systems (`device=cuda`, `compute_type=float16`).
- Pause compaction for medium/long utterances.
- Fast-path preview shutdown to reduce post-release delay.
- Conservative post-processing to preserve transcription quality while improving readability.

## What Did Not Work Well

- Mixing too many visual effects made animation feel random and reduced clarity.
- Intermediate flush injection during hold was fragile in some editors (focus and key-event side effects).
- Legacy config values (CPU + conservative long-audio settings) can silently cap performance if not migrated.

## Platform Support

## Windows (recommended)

- This is the main tested path.
- Hotkey capture and injection behavior are tuned for Windows interactions.
- Config defaults and launch scripts are Windows-first.
- If you have NVIDIA CUDA available, this repo now auto-migrates suitable legacy configs to GPU mode.

## Linux

- Possible, but not currently validated end-to-end.
- Key risks:
  - Global hotkey hooks vary by desktop environment.
  - Injection behavior differs between X11 and Wayland.
  - Tray/dock UX may not map directly.
- Recommended fork strategy:
  - First stabilize audio capture + ASR in terminal mode.
  - Then implement platform-native hotkeys/injection/tray path.

## macOS

- Possible, but not currently validated end-to-end.
- Key risks:
  - Accessibility/input permissions for text injection.
  - Global hotkey implementation differences.
  - Tray/menu bar behavior differences.
- Recommended fork strategy:
  - Start with terminal dictation + clipboard injection.
  - Add native integration after reliability is proven.

## Hardware Guidance

## Minimum practical

- CPU-only: works, but medium/long utterances will be slower.
- RAM: 8 GB recommended.
- Any stable microphone works; headset mics reduce room-noise variance.

## Recommended

- NVIDIA GPU with CUDA runtime available.
- 16 GB+ RAM for smoother multitasking.
- Dedicated microphone/headset for better consistency.

## Runtime Configuration Notes

- Config file: `%LOCALAPPDATA%\\LocalFlow\\config.json` (Windows).
- Important fields for speed:
  - `device`
  - `compute_type`
  - `pause_compaction_*`
  - `latency_boost_*`
- Force CPU when needed:
  - `VOICEFLOW_FORCE_CPU=1`

## Testing Guidance For Forks

## Fast checks

- Syntax sanity:
  - `python -m py_compile src/voiceflow/ui/visual_indicators.py src/voiceflow/ui/cli_enhanced.py src/voiceflow/core/streaming.py src/voiceflow/utils/settings.py`
- Unit slice:
  - `pytest -q tests/test_textproc.py tests/test_injector_logic.py tests/test_sanitization_and_rate.py`

## Behavioral checks

- Short dictation: 3-5 seconds.
- Medium dictation: 8-12 seconds.
- Long dictation: 20-40 seconds with pauses.
- Verify:
  - no text loss
  - release-to-text latency
  - acceptable punctuation/formatting
  - hotkey start/stop stability

## Forking Checklist

1. Decide platform target first (Windows vs Linux vs macOS).
2. Validate ASR model/device path on your hardware.
3. Stabilize hotkey + injection before visual enhancements.
4. Keep visuals decoupled from ASR critical path.
5. Add platform-specific tests for injection and global hotkeys.
6. Publish your own launcher scripts and setup notes for your OS.

## Suggested Next Improvements

- Add explicit runtime metrics panel (release latency, RTF, per-session averages).
- Add optional style presets for visuals (`minimal`, `classic`, `experimental`).
- Expand CI test matrix by platform and feature category.
- Improve long-utterance regression tests with fixture audio.
