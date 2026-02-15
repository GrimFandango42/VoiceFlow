# VoiceFlow Architecture Guide (Extended)

This document is the extended companion to `docs/ARCHITECTURE.md`.

## Runtime Profile

- Desktop push-to-talk transcription runtime
- Python process with tray + overlay UI
- local ASR inference with optional CUDA acceleration
- output injection into active application

## Runtime Path Summary

```text
PTT hold
  -> audio capture begins
  -> optional partial captions shown in overlay

PTT release
  -> audio finalized
  -> ASR transcription
  -> text normalization/formatting
  -> target-app injection
  -> state reset to idle
```

## Key Runtime Files

- `src/voiceflow/ui/cli_enhanced.py`
- `src/voiceflow/ui/enhanced_tray.py`
- `src/voiceflow/ui/visual_indicators.py`
- `src/voiceflow/core/asr_engine.py`
- `src/voiceflow/core/streaming.py`
- `src/voiceflow/core/audio_enhanced.py`
- `src/voiceflow/integrations/hotkeys_enhanced.py`
- `src/voiceflow/integrations/inject.py`

## Practical Design Constraints

- Prioritize release-to-text latency over complex live rewriting.
- Keep UI effects independent from ASR critical-path performance.
- Preserve target-window safety when experimenting with in-hold flush/injection.
- Maintain single-process listener behavior to prevent hotkey race conditions.

## Performance Notes

Current practical tuning themes:
- pause compaction for medium/long dictation
- model warm-up and fast-path model selection
- constrained streaming preview windows
- conservative AI post-processing defaults for speed

## Operational Paths

Windows defaults:
- config: `%LOCALAPPDATA%\LocalFlow\config.json`
- logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

Launchers:
- `VoiceFlow_Quick.bat` (recommended)
- `VoiceFlow.bat`
- `VoiceFlow_Silent.bat`
- `tools\launchers\LAUNCH_CONTROL_CENTER.bat`

## Further Reading

- `docs/TECHNICAL_OVERVIEW.md`
- `docs/HOW_TO_LAUNCH.md`
- `docs/guides/FORKING_AND_PLATFORM_GUIDE.md`
