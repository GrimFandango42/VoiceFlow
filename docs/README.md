# VoiceFlow Documentation Index

- Quick Start: VoiceFlow (Windows)
  - See `USER_GUIDE.md` for end-user setup, hotkeys, and tray usage.
- Technical Overview
  - `docs/TECHNICAL_OVERVIEW.md`
- Windows Setup and Troubleshooting
  - `docs/WINDOWS_SETUP_GUIDE.md`
  - `docs/WSL_AUDIO_GUIDE.md`
- Testing
  - Unit tests (default): `pytest -q` runs tests under `tests/unit`.
  - Integration/Windows tests: run explicitly from `tests/integration`.
  - Notes: `docs/TESTING_NOTES.md`
- Improvement Reports and Analyses
  - Various deep-dive docs in `docs/` (e.g., AUDIO_QUALITY_IMPROVEMENTS, MCP guides).

## Project Structure

- `src/voiceflow/`: Core application modules (core, UI, integrations, utils)
- Entry points: Available via Control Center or direct Python execution
- `tests/`
  - `unit/`: fast, platform‑agnostic unit tests (default)
  - `integration/`: Windows/UI/integration suites (run explicitly)
- `scripts/`: utility scripts (environment checks, audio device listing, etc.)
- `tools/`: VoiceFlow Control Center and launcher utilities
- `docs/`: this folder (overview, setup, testing, analyses)

## Running Tests

- Default unit set: `pytest -q`
- Full integration set: `pytest tests/integration -q`
- Windows‑only tests: `pytest tests/integration/windows -q`

