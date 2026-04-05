# Changelog

All notable changes to VoiceFlow are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [3.1.8] - 2026-04-04

### Added

- Streaming live preview with VAD (voice activity detection) filtering to suppress noise artifacts during silence (`ac6c421`).
- Streaming context window expanded to 8 seconds, improving word-level accuracy on longer utterances (`ac6c421`).
- Streaming preview accuracy improved via context carryover: the final transcript from the previous utterance is passed as `initial_prompt` to the streaming decoder (`8739c29`).
- `streaming_beam_size=2` for preview decode path, balancing accuracy against latency (`d3d37ca` — note: commit hash from log is `dd70f5a`).
- Audio confirmation beeps on recording start and stop using `winsound`, providing eyes-free feedback during dictation (`e6d2785`).
- Custom vocabulary file support: place a `custom_vocabulary.txt` in the config directory to bias Whisper toward your domain terms (`66e8e0a`).
- Audio preprocessing pipeline: high-pass filter, RMS normalization, and noise gate applied before ASR (`276b148`).
- Two-process hot-reload dev launcher: model server runs in a separate process so the main app can reload without re-initializing Whisper (`8d20ac4`).
- Confidence-weighted learning enhancements: correction signals are weighted by ASR confidence before being promoted into adaptive patterns (`cd7a77f`, `e60c57d`).

### Changed

- Overlay layout tightened and speaking animation modernized for cleaner visual presentation (`74c997c`).
- Overlay remains visible across all active states (recording, processing, injecting) with a persistent status badge (`258d33b`).
- Overlay window uses smooth fade-in and fade-out transitions instead of hard show/hide (`3d37ca` — `258d33b`).
- Waveform indicator colors are now state-differentiated: distinct colors for recording, processing, and idle phases (`05f445e`).

### Fixed

- `AudioPreprocessor` import missing from `cli_enhanced.py` causing startup failure when preprocessing was enabled (`1345f15`).
- Model server launch failed when the working directory was not set to `SRC_DIR`, causing a module shadow collision with `voiceflow.py` at the repo root (`4265b23`).
- Two bugs in the confidence-weighted learning merge (`99ecdfe`).
- Test mock alignment after learning refactor (`811fcad`).

---

## [3.1.x] - prior releases

Earlier changes are tracked in git history. Run `git log --oneline` from the repository root to browse them.

---

[3.1.8]: https://github.com/GrimFandango42/VoiceFlow/releases/tag/v3.1.8
