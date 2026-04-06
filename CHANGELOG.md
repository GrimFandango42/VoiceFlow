# Changelog

All notable changes to VoiceFlow are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [3.2.1] — 2026-04-06

### Added
- **Spring physics waveform** — each of 28 bars has individual stiffness/damping; burst energy injected on speech onset with random velocity kicks
- **Sympathetic vibration** — neighboring bars mutually influence targets each frame, creating traveling ripple propagation
- **Spark particle system** — pool of 28 sparks spawned on burst onset and dripped continuously during speech; outward arcs from edge bars with drag and hangtime
- **Streaming preview quality** — filler words (uh/um/er) stripped in real-time; safe cleanup applied to live preview so it reads like final output
- **Corrected text during COMPLETE** — final cleaned text visible in preview overlay during the 2-second completion window
- **Focus hardening** — overlay re-lifts every 300 ms during active recording to survive UAC dialogs and notification banners

### Fixed
- **Launcher crash** — `_app_entry.py` bypasses false-positive single-instance detection caused by py.exe shim spawning real Python child with identical cmdline; `VoiceFlow.bat` updated to use it
- **Hint label blur** — transparent background on "Ctrl+Shift" label caused Windows compositing anti-aliasing artifacts at small font sizes; fixed to opaque panel surface
- **Memory growth on long sessions** — `queue.Queue(maxsize=500)` caps audio frame backlog during Whisper inference; high-frequency updates drop silently when full

### Changed
- Overlay max height reduced to 215 px (was 290 px)
- Preview box shows 3 comfortable lines of text
- Overlay positioned tighter to dock with reduced gap

---

## [3.2.0] — 2026-04-04

### Added
- **Ripple-ring animation** — center orb with expanding concentric rings; ring expansion rate and brightness respond to audio level in real time
- **Streaming preview overlay** — partial transcription visible while speaking, updates word-by-word
- **Audio preprocessing pipeline** — VAD filter, silence trimming, and chunk compaction before ASR
- **Adaptive learning daily reports** — nightly batch writes `daily_learning_reports/daily_learning_YYYY-MM-DD_*.json` summarizing learned patterns
- **Idle-aware monitoring** — hang detection and memory warning callbacks for 24/7 operation
- **Audio start/stop beeps** — brief confirmation tones on recording start and stop
- **Continual learning audit trail** — `adaptive_audit.jsonl` tracks every raw→final delta with learned pairs

### Changed
- **UI layout** — overlay now 108–144 px tall (was 142–182 px); wave canvas shrunk to 58 px; overlay-to-dock gap reduced to 2 px
- **Animation** — replaced cluttered bar+orb+spark+trail stack with clean ripple-ring design
- **Streaming context window** — expanded to 8 s with VAD filter for more accurate partial results
- **AGC scaling** — dynamic silence-floor estimation gives calmer idle visual and sharper speech reactivity
- **Cleanup defaults** — light typo correction and safe second-pass cleanup now on by default

### Fixed
- Duplicate-instance watchdog now correctly keeps oldest leaf process instead of newest
- Bootstrap-parent watchdog no longer fires spuriously on fast startup paths
- `transcription_corrections.jsonl` path now resolves correctly under `%LOCALAPPDATA%\LocalFlow\`
- Canvas items that fade to zero opacity are moved off-screen rather than drawn at size 0

### Removed
- Geometric node/arc motif animation
- Spark particle system
- Trailing sine-wave overlay
- "Space HUD" look with star field and arcs

---

## [3.1.8] — 2026-03-15

### Added
- GPU acceleration with CUDA 11.8+ support
- Setup wizard with hardware detection and profile selection
- Cold-start elimination via model pre-warming
- Text injection via Windows clipboard (pywin32)

### Changed
- Switched ASR backend to faster-whisper (Distil-Whisper Large v3.5)
- Tray redesigned as primary control surface

### Fixed
- Hotkey listener race condition on rapid press/release
- Overlay positioning on multi-monitor setups

---

## [3.0.0] — 2026-01-20

### Added
- Initial public release
- Push-to-talk with Ctrl+Shift hotkey
- Local whisper inference (no cloud)
- Basic tray icon and setup wizard
- Windows-only text injection
