# Changelog

All notable changes to VoiceFlow are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — versions follow [Semantic Versioning](https://semver.org/).

---

## [3.1.8] — 2026-04-04

### Added
- Gradient orb animation: multi-layer bloom effect for the speaking indicator, replacing the flat single-oval design
- Concentric ripple rings that expand outward from the orb on voice activity — always visible, more dramatic when speaking
- Gradient orb breathes with a subtle idle pulse so the overlay feels alive even during silence

### Changed
- Fixed broken speaking animation: the waveform, orb, and spark particles now animate correctly (guard condition was blocking all animation when equalizer bars were removed)
- Tightened spacing between the transcription overlay and the dock bar from 10 px to 4 px
- Canvas height increased to 80 px to give the orb and ripple rings more vertical room
- Improved z-ordering of canvas layers: baseline → wave → rings → gradient → core → sparks

---

## [3.1.7] — 2026-03

### Added
- Audio start/stop beeps provide a brief acoustic confirmation of recording state
- State-differentiated waveform colors give clear visual feedback for listening vs. transcribing vs. processing phases

### Changed
- Overlay remains visible through all active states (listening, streaming, processing) — previously hid during transitions
- Smooth fade-in/fade-out transitions on overlay show/hide

---

## [3.1.6] — 2026-03

### Added
- Streaming context window expanded to 8 seconds with VAD (voice activity detection) filter for preview accuracy
- `streaming_beam_size=2` improves preview text quality with minimal latency cost
- Context carryover between streaming chunks reduces repeated words and mid-sentence restarts
- Custom vocabulary file support: add `custom_vocabulary.txt` to the config directory

### Fixed
- Model server launch: corrected working directory to prevent module shadowing
- Missing `AudioPreprocessor` import in `cli_enhanced.py`

---

## [3.1.5] — 2026-02

### Added
- Confidence-weighted learning: higher-confidence transcription segments receive stronger weight in the adaptive learner
- Enhanced daily learning reports with top learned replacements and frequent domain tokens

### Changed
- `adaptive_store_raw_text` defaults to `false` — raw transcript snippets opt-in only
- Explicit user corrections in Correction Review rank higher than auto-analysis in the learning system

---

## [3.1.4] — 2026-02

### Added
- Correction Review panel accessible from the tray: review recent transcriptions, approve or correct them, and feed corrections back into the adaptive learner
- Recent History panel shows the last N transcriptions with timestamps
- History panel can be expanded for longer review sessions or collapsed to a compact view

### Changed
- Continual learning is now observable: inspect learned patterns in `%LOCALAPPDATA%\LocalFlow\adaptive_patterns.json`
- Daily learning run writes a report to `%LOCALAPPDATA%\LocalFlow\daily_learning_reports\`

---

## [3.1.3] — 2026-01

### Added
- Setup wizard hardware detection: auto-detects GPU compute capability and recommends `tiny`, `base`, or `small` Whisper model
- Three startup profiles: `Recommended`, `CPU Compatible`, `GPU Balanced`
- Step 1 (hardware check) is required before Step 2 controls unlock — prevents misconfigured launches

### Changed
- Tray is now the primary control surface; setup wizard is reopenable from tray at any time
- First-run flow visually emphasizes Step 1 with a pulsing highlight; Step 2 is locked until check completes

---

## [3.0.0] — 2025-12

### Added
- Push-to-talk core: hold `Ctrl+Shift`, speak, release — text injected into active application
- faster-whisper backend for on-device inference (no cloud dependency)
- Tray icon with system tray integration via pystray
- Visual overlay with animated waveform — appears at bottom of screen during recording
- Dock bar: always-visible status indicator above the system taskbar
- Two text injection modes: clipboard paste (default) and simulated keystrokes
- Three post-processing passes: light typo correction, safe second pass, opt-in heavy cleanup
- `press_enter_after_paste=false` default — text appears without submitting forms
- Hotkey configuration via tray menu

---

## Notes

- macOS and Linux are community fork targets; the core runtime is Windows-only at this time.
- The `%LOCALAPPDATA%\LocalFlow\` directory stores all user data: config, learned patterns, and history.
- Downgrading: the config schema is forward-compatible within a major version. Rollback to a prior release tag should work without clearing config.
