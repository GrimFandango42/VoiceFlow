# VoiceFlow Roadmap

This document captures the current priorities based on a competitive landscape review (April 2026) against WhisperWriter, OpenWhispr, Amical, OmniDictate, and Purfview/whisper-standalone-win.

The short version: VoiceFlow's architecture is ahead of every comparable open-source tool. The gap is entirely **presentation and first-run experience**.

---

## Status of the Ecosystem

| Project | Stars | What they do better |
|---------|-------|---------------------|
| [WhisperWriter](https://github.com/savbell/whisper-writer) | ~1k | Simpler setup, more visible |
| [OpenWhispr](https://github.com/OpenWhispr/openwhispr) | ~2.3k | Polished installer, cross-platform |
| [Amical](https://github.com/amicalhq/amical) | ~1.1k | Context-aware per active app, modern UI |
| [OmniDictate](https://github.com/gurjar1/OmniDictate) | ~118 | NSIS installer, voice punctuation |
| VoiceFlow | ~2 | Everything else |

VoiceFlow has streaming preview, pause compaction, three-tier text cleanup, adaptive learning, non-speech guard, and a cold-start eliminator. None of the comparable tools have all of these. The discoverability gap is fixable.

---

## Priority 1 — First Impression (High Return, Low Effort)

### Demo GIF in README
A screen recording showing: hold hotkey → animation plays → text appears in VS Code. This converts visitors to users more than any feature description. WhisperWriter's README has one. VoiceFlow's doesn't.

### "Wispr Flow alternative" framing
The comparison table is there but undersells it. Wispr Flow is $120/year and cloud-based. VoiceFlow is free, local, and privacy-preserving. That positioning should be in the first sentence of the README, not buried.

### "Works in VS Code / Slack / Notepad / anywhere" framing
Users want to know their specific app works before they download. A short compatibility matrix or a line like "injects into any Windows app including VS Code, Slack, Notepad, browsers, and terminals" converts better than a general feature list.

---

## Priority 2 — Installation Experience (High Return, Moderate Effort)

### Explicit first-run model download flow
The setup wizard runs a hardware check but doesn't show a progress dialog when the model is downloading from Hugging Face cache. Users on slow connections or with firewall restrictions hit a 30-second silent wait with no feedback.

Target: a modal showing "Downloading distil-large-v3 (350 MB)..." with a real progress bar, a cancel option, and a clear error if the download fails. This is the single highest-return UX improvement in the space.

### Separate runtime from model in the installer
The current PyInstaller bundle is ~826 MB. Most of that is torch + CTranslate2. The model itself is downloaded at runtime but the DLLs are bundled.

The pattern that works (used by OpenWhispr, Handy, whisper-standalone-win): ship a small runtime zip (~100 MB, Python embeddable + CTranslate2 + faster-whisper + sounddevice), download the model on first launch with a progress bar. Total install footprint identical, but the initial download is small.

### Winget submission
One YAML manifest file. `winget install GrimFandango42.VoiceFlow` as a discovery path. Comparable tools like Handy are already in the winget catalog.

---

## Priority 3 — Runtime Model Swap (Meaningful Differentiation)

VoiceFlow's `core/model_server.py` already maintains a persistent model process. The infrastructure for hot model swapping exists.

Target: a tray menu item "Switch model → [Quick | Balanced | Quality]" that POSTs to the model server and reloads without restarting the app. No comparable open-source tool does this. It directly addresses the "I want to use the small model for quick notes and the large model for long dictation" use case.

---

## Priority 4 — Context-Aware Behavior (Longer Term)

Amical's standout feature is reading the active application name and adjusting behavior — different cleanup rules for a code editor vs. an email client vs. a chat app.

VoiceFlow already has `destination_aware_formatting` and `infer_destination_profile` in `textproc.py`. The gap is extending that profile detection to more app categories and making it configurable from the tray.

---

## Priority 5 — Community Infrastructure

### Discord server
Costs nothing. Creates the appearance of an active community before one actually exists. Stage-Whisper, OpenWhispr, and Whispering all have one. User feedback gathered in Discord becomes the input for the adaptive learning system.

### GitHub Actions release publishing
Currently releases are created manually. A `build-release.yml` workflow that builds and publishes the PyInstaller bundle on tag push would signal project health and remove the manual step from the release process.

---

## Things Already Handled Well — Don't Revisit

- **int8 quantization on CTranslate2** — already optimal for the GPU path
- **VAD** — VoiceFlow uses a custom non-speech guard (crest-factor + voiced-frame ratio) rather than the raw Silero integration. More sophisticated than every comparable tool.
- **Model server for persistent loading** — better than every open-source peer
- **Streaming preview with real-time cleanup** — WhisperWriter doesn't have it; OmniDictate's "real-time" is actually a full retranscription loop
- **Pause compaction for long dictation** — unique in the space
- **Three-tier text cleanup** — no comparable tool has this
- **Adaptive learning loop** — no comparable tool has anything equivalent
- **24/7 idle stability** — idle-aware monitor, queue cap, focus hardening

---

## Model Tier Note

The research found that `distil-large-v3.5` (currently the BALANCED tier) is ~1.5x faster than `distil-large-v3` (currently the QUICK GPU tier) at nearly identical WER for short-form utterances. Swapping the QUICK GPU mapping to v3.5 would make QUICK both faster and equivalent in quality to the current BALANCED tier. Worth evaluating after the presentation priorities above are addressed.
