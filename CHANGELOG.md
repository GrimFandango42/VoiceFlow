# Changelog

All notable changes to VoiceFlow are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versions follow [Semantic Versioning](https://semver.org/).

---

## [3.2.0] — 2026-04-04

### Added

- **Ripple-orb animation** — the overlay now features a centered pulsing orb with three concentric ripple rings that radiate outward as you speak. Rings stagger in phase (120° apart) for a smooth Siri-style pulse. At idle the orb breathes gently; under speech it expands and the rings push outward with burst energy.
- **Streaming VAD filter** — voice activity detection now gates the streaming preview, suppressing spurious words during silence between phrases.
- **8-second streaming context window** — expands the rolling context fed to the streaming decoder from 4s to 8s, reducing mid-utterance word drift.
- **Streaming beam size 2** — improved partial-transcription accuracy with minimal latency increase.
- **Context carryover** — the previous utterance is passed as `initial_prompt` to the next streaming chunk, reducing first-word errors on short follow-up phrases.
- **Audio beeps** — distinct start/stop tones confirm recording has begun and ended.
- **Audio preprocessing pipeline** — high-pass filter, RMS normalisation, and noise gate applied before inference to improve accuracy in noisy environments.
- **Custom vocabulary** — add domain-specific words to `custom_vocabulary.txt` in the config directory to bias the decoder toward them.
- **Confidence-weighted learning** — the continual-learning system now weights correction signals by recognition confidence, promoting high-confidence corrections more aggressively.
- **Smooth overlay transitions** — fade-in on recording start, fade-out on completion.
- **State-differentiated waveform colors** — the overlay accent color shifts by state: blue (listening), amber (processing), green (transcribing/done).
- **Status badge** — small badge in the overlay shows the current state label.
- **Streaming preview** — partial transcription words stream into the overlay in real time while you speak.

### Changed

- **Overlay spacing compressed** — reduced canvas height, padding, and margins so the overlay hugs the dock/tray bar more tightly.
- **Overlay stays visible** through all active states (listening → processing → transcribing) and hides only on IDLE/COMPLETE.
- **Animation guard fixed** — the waveform animation previously exited immediately because it required equalizer bars (which were disabled). Now it runs correctly on every frame.
- Orb no longer travels left-to-right; it stays horizontally centered and bobs vertically with amplitude.
- Wave amplitude and sine-wave frequency now respond to spectral features (low/mid/high bands, spectral centroid).
- Spark particles are smaller and less distracting — they ride the sine wave path rather than drifting freely.

### Fixed

- Model server launch failure when `voiceflow.py` shadowed the package name during subprocess spawn.
- Missing `AudioPreprocessor` import in `cli_enhanced.py`.
- Test mock mismatch for audio-level update path.
- Two bugs in confidence-weighted learning integration.

---

## [3.1.8] — 2026-03 *(previous stable)*

- Continual learning: daily batch analysis writes an adaptive snapshot with top learned replacements.
- Correction review panel accessible from tray for explicit user feedback.
- Three-pass text cleanup: light typo correction, safe second pass (both on by default), heavy rewrite (opt-in).
- Setup wizard with hardware detection and startup profile selection.
- History panel with filter (All / Live / Corrections / Retries) and expandable items.
- Tray-first design — no main window, all surfaces are right-click accessible.
- Platform abstraction layer for future macOS/Linux porting.

---

## [3.0.0] — 2025 *(major rewrite)*

- Migrated from single-file script to `src/voiceflow/` package layout.
- Switched transcription backend to faster-whisper.
- Added Tkinter overlay with animated waveform.
- Added `pystray` tray integration.
- Added global hotkey listener via `keyboard` library.
- Added Win32 `SendInput` text injection.
