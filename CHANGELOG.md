# Changelog

All notable changes to VoiceFlow are documented here.

Format: [Semantic Versioning](https://semver.org). Dates are approximate release dates.

---

## [Unreleased]

### Fixed
- Animation fully broken: `_animate_waveform` returned early whenever `wave_bars` was empty
  (bars were removed in v3.1.8 but the guard was not updated)

### Added
- **Siri-style concentric breathing rings** — three concentric ovals centered on the waveform,
  each pulsing at a 120° phase offset. Ring radius and opacity respond to voiced energy,
  creating a living, reactive background layer behind the sine waves

### Changed
- Overlay canvas height reduced from 68 → 58 px; window height ceiling reduced from 182 → 160 px
- Status badge row padding tightened to zero, producing a more compact single-row footprint

---

## [3.1.8] — 2026-04

### Changed
- **Overlay layout**: tightened canvas height (80 → 68 px) and removed inter-element padding;
  removed equalizer bars and static pulse rings in favour of a clean sine-wave-only visual
- **Waveform animation**: heavier glow widths and larger orb for higher visual impact at smaller size
- **State colours**: blue for listening, amber for processing, green for transcribing/done —
  communicated through the waveform accent hue rather than a separate icon

### Added
- Audio start/stop confirmation beeps (subtle, configurable)
- Streaming context window extended to 8 s; Silero VAD filter applied to streaming preview
- `streaming_beam_size=2` — trades a small latency increase for noticeably more accurate previews

### Fixed
- Test mock alignment after model server refactor

---

## [3.1.7] — 2026-03

### Added
- Smooth fade-in / fade-out transitions for the overlay window (no jarring pop)
- Overlay remains visible through all active states (listening → processing → transcribing)
  rather than blinking out between phases
- Status badge row below waveform shows current phase text at a glance
- Streaming preview accuracy improved via `initial_prompt` context carryover between chunks

### Fixed
- Model server launch: `cwd=SRC_DIR` prevents the `voiceflow.py` root module from shadowing
  the `voiceflow` package during subprocess launch
- Missing `AudioPreprocessor` import in `cli_enhanced.py`

---

## [3.1.6] — 2026-03

### Added
- **Custom vocabulary file** (`custom_vocabulary.txt`) — list domain terms, product names, or
  names once; they are prioritised during transcription and cleanup
- **Audio preprocessing pipeline** — high-pass filter, RMS normalisation, and noise gate applied
  to captured audio before inference; reduces background hum and improves low-volume accuracy
- **Confidence-weighted learning** — correction signals are weighted by per-segment confidence
  scores so high-confidence divergences carry more learning weight than low-confidence guesses
- Two-process hot-reload dev launcher for faster iteration during development

### Fixed
- Two integration bugs in confidence-weighted learning merge

---

## [3.1.5] — 2026-02

### Added
- **Streaming VAD filter** (`vad_filter=True` on partial decodes) — suppresses hallucinations
  during silence pockets in the streaming preview
- Cap streaming audio buffer at 2× `partial_max_audio_seconds` to bound memory growth on
  very long dictations without stopping the stream
- CUDA idle-resume primer — sends a short speech-like buffer after a long idle period to
  re-warm the CUDA decode path before the user speaks

### Fixed
- Long-idle resume transcription: recovery path now retries the decode with a wider beam
  when the first attempt returns an empty result after a multi-minute pause
- Manual corrections now persisted to `transcription_corrections.jsonl` immediately so the
  next session starts with them already loaded
- User-correction min-count lowered and retention extended to 14 days

---

## [3.1.4] — 2026-01

### Added
- Adaptive learning loop strengthened: daily batch writes a replacement-rule snapshot plus a
  domain-token frequency report; saved corrections are promoted into the live runtime learner
  so the current session adapts before the next daily batch
- Setup wizard: hardware detection locked until the user explicitly runs the check; Step 2
  (profile selection) is disabled until Step 1 completes
- Live preview and setup UX polish pass

### Changed
- Claude-adjacent terminology handling (e.g. `Claude Code`, `Claude Desktop`) built into the
  cleanup rules without risky blanket substitutions
- Release executable named `VoiceFlow-win64.exe`; portable archive is `VoiceFlow-portable-win64.zip`

### Fixed
- Packaged startup sequencing hardened; log path discovery falls back gracefully when
  `%LOCALAPPDATA%` is unexpectedly missing

---

## [3.1.0] — 2025-12

### Added
- **Tray-first architecture** — all primary controls (setup wizard, settings, history,
  correction review) accessible from the system tray icon; no persistent window
- **Setup wizard** with one-click hardware detection and profile selection
- **Three-pass cleanup pipeline** — light typo correction, safe second pass, optional heavy
  rewrite (all independently toggleable)
- **Continual learning system** — local-only, session-level and daily-batch modes
- **History panel** — review recent transcriptions with inline correction editor
- **Correction review** — explicit feedback signals promoted into the learning loop
- Bottom-screen overlay with audio-reactive waveform animation
- Cross-platform porting guide for macOS / Linux community forks

---

## [3.0.0] — 2025-10

### Added
- faster-whisper backend replacing OpenAI Whisper; ~4× faster on CPU, GPU support via CTranslate2
- `Ctrl+Shift` push-to-talk hotkey with text injection into the active window
- Streaming partial transcription — live preview updates while holding the hotkey
- PyInstaller packaging → single-folder `dist\VoiceFlow\VoiceFlow.exe` with all dependencies bundled
- sounddevice / pyaudio capture with automatic device selection

---

[Unreleased]: https://github.com/GrimFandango42/VoiceFlow/compare/v3.1.8...HEAD
[3.1.8]: https://github.com/GrimFandango42/VoiceFlow/compare/v3.1.7...v3.1.8
[3.1.7]: https://github.com/GrimFandango42/VoiceFlow/compare/v3.1.6...v3.1.7
[3.1.6]: https://github.com/GrimFandango42/VoiceFlow/compare/v3.1.5...v3.1.6
[3.1.5]: https://github.com/GrimFandango42/VoiceFlow/compare/v3.1.4...v3.1.5
[3.1.4]: https://github.com/GrimFandango42/VoiceFlow/compare/v3.1.0...v3.1.4
[3.1.0]: https://github.com/GrimFandango42/VoiceFlow/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/GrimFandango42/VoiceFlow/releases/tag/v3.0.0
