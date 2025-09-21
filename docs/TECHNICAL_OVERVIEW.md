VoiceFlow: Technical Overview

Purpose
- Local, privacy-first voice transcription and workflow automation for Windows.
- Works in any focused application (VSCode, browsers, editors) by pasting or typing recognized text.
- Features advanced performance optimizations, visual indicators, and comprehensive guardrails.

High-level Architecture
- Control Center: GUI-based control interface for easy management and monitoring.
- Audio Capture: High-performance audio input stream at 16 kHz mono with optimized buffering.
- ASR Engine: `faster-whisper` with CUDA fp16 and performance optimizations for real-time transcription.
- Text Processing: Enhanced text formatting with smart capitalization, punctuation, and code mode support.
- Injection: Secure text injection via clipboard paste or keyboard simulation with restored clipboard.
- Visual Indicators: Real-time status indicators showing listening, processing, and completion states.
- Settings: Persistent configuration with comprehensive validation and safe defaults.
- Logging: Advanced logging system with performance monitoring and diagnostic capabilities.

Core Modules
- `voiceflow/core/config.py`: Comprehensive configuration system with validation and performance settings.
- `voiceflow/core/memory_optimized_audio.py`: High-performance audio capture with optimized memory usage.
- `voiceflow/core/advanced_performance_asr.py`: Production-ready ASR engine with performance monitoring.
- `voiceflow/core/textproc.py`: Enhanced text processing with smart formatting and code mode mapping.
- `voiceflow/integrations/inject.py`: Secure text injection with rate limiting and safety validations.
- `voiceflow/ui/enhanced_tray.py`: System tray interface with visual indicators and control options.
- `voiceflow/ui/visual_indicators.py`: Real-time visual feedback system for user awareness.
- `voiceflow/utils/logging_setup.py`: Advanced logging with performance tracking and diagnostics.
- `voiceflow/utils/validation.py`: Comprehensive validation and safety guardrails system.

Hotkeys
- Default PTT: Ctrl+Shift+Space (avoids conflicts with common setups).
- Presets from tray: Ctrl+Alt, Ctrl+Alt+Space, Ctrl+Space, Alt+Space, Ctrl+Shift+Space.
- Toggle hotkeys: Ctrl+Alt+C (code mode), Ctrl+Alt+P (paste vs type), Ctrl+Alt+Enter (send Enter).

ASR Choices
- Engine: `faster-whisper` on CUDA with `float16` (RTX 4080 recommended).
- Models: `small.en` for speed, `medium.en` for accuracy; `distil-large-v3` optional.
- Settings: `vad_filter=True`, `beam_size=1`, `temperature=0.0`.

Injection Path
- Paste: copy text to clipboard, send paste shortcut (`ctrl+v` default), restore previous clipboard.
- Type: simulate keystrokes; preferred for short/sensitive outputs via `type_if_len_le`.
- Sanitization: remove control chars (except tab/newline) and cap payload with `max_inject_chars`.
- Rate limit: `min_inject_interval_ms` prevents accidental flooding.

Security & Privacy
- Offline processing after first model download.
- Clipboard restoration minimizes exposure window; typing path avoids clipboard use altogether.
- Sanitization prevents control-char injection; truncation avoids huge accidental payloads.
- Logging records timings and statuses but does not log recognized text.

Performance Notes
- CUDA fp16 on 4080 yields low-latency; `small.en` reduces delay further for back-and-forth coding chats.
- Model warm-up occurs on first use to hide initial load latency.
- Async logging avoids blocking dictation.

Testing
- Unit tests (pytest): mapping, injection logic, sanitization, throttling.
- Scripts:
  - `scripts/check_mappings.py`: preview code-mode replacements.
  - `scripts/list_audio_devices.py`: enumerate inputs.
  - `scripts/bench_env.py`: environment snapshot.
- Test runner: `python run_tests.py --type unit` aggregates results if pytest is installed.

Extension Points
- Code mode: extend `localflow/textproc.py` mappings; consider making it data-driven (JSON/CSV) for language-specific presets.
- Injection: per-app policy layer (future) to choose paste vs type and Enter behavior by target application.
- ASR: switch engines (e.g., whisper.cpp) or add streaming partials for continuous dictation mode.
- UI: add a minimal status overlay for listen/transcribe states.
- Persistence: add per-profile configs (e.g., Coding, Writing) with quick switching.

