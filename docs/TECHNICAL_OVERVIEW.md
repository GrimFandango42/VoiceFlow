LocalFlow: Technical Overview

Purpose
- Local, privacy-first push-to-talk dictation for Windows.
- Works in any focused application (VSCode, browsers, editors) by pasting or typing recognized text.

High-level Architecture
- Hotkey Listener: global chord detection (modifier-only chords supported) to start/stop capture.
- Audio Capture: `sounddevice` input stream at 16 kHz mono buffers audio while PTT is held.
- ASR Engine: `faster-whisper` with CUDA fp16 transcribes buffered audio on release.
- Text Processing: optional “code mode” maps spoken phrases to coding symbols.
- Injection: injects text via clipboard paste or simulated typing; clipboard is restored.
- Tray: lightweight system tray for toggles and PTT hotkey presets.
- Settings: persisted JSON under `%LOCALAPPDATA%\LocalFlow\config.json`.
- Logging: async rotating log in `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`.

Modules
- `localflow/config.py`: dataclass with all runtime behavior flags (ASR, hotkeys, injection, code mode, tray).
- `localflow/audio.py`: microphone stream using `sounddevice` with a thread-safe frame buffer.
- `localflow/asr.py`: lazy-initialized Whisper model via `faster-whisper`; VAD filter and greedy decode by default; warm-up on load.
- `localflow/textproc.py`: code-mode mapping; replace phrases with symbols, normalize whitespace.
- `localflow/inject.py`: sanitized clipboard/typing injection with rate limiting and fallback.
- `localflow/hotkeys.py`: dynamic-chord PTT; reads current config on each event; supports modifier-only chords.
- `localflow/tray.py`: pystray-based tray with toggles and PTT presets; optional dependency.
- `localflow/logging_setup.py`: non-blocking logging via `QueueHandler` + `RotatingFileHandler`.
- `localflow/settings.py`: load/save config JSON in `%LOCALAPPDATA%\LocalFlow`.
- `localflow/cli.py`: application wire-up, toggles via hotkeys, tray, and logging.

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

