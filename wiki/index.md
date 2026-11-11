# VoiceFlow Wiki

Maintainer notes for the VoiceFlow project: a dev log, design decisions, known issues and UI preferences.
The user-facing and technical documentation lives in [`docs/`](../docs/README.md); this folder does not repeat it.

## Pages

- [log.md](log.md) — Chronological development record (early entries are historical snapshots)
- [architecture.md](architecture.md) — Pointer to the architecture doc plus the two-process dev setup
- [known-issues.md](known-issues.md) — Open bugs and limitations
- [ui-preferences.md](ui-preferences.md) — Visual/UX preferences for the overlay
- [decisions.md](decisions.md) — Key design decisions and rationale

## Quick reference

- **Run (dev, GPU, hot reload)**: `.venv-gpu\Scripts\python.exe dev.py`
- **Run (packaged)**: `dist\VoiceFlow\VoiceFlow.exe` (verify with `--self-check=report.json`)
- **Push-to-talk**: hold `Ctrl+Shift`; `Esc` cancels; `Alt+Shift+V` re-pastes the last transcript
- **Models**: default `quick` tier = `small.en` on CPU, `distil-large-v3` on CUDA
- **VAD**: Silero VAD (bundled with faster-whisper)
- **Data**: `%LOCALAPPDATA%\VoiceFlow`
