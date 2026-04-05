# Changelog

All notable changes to VoiceFlow are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
