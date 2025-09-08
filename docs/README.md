# Documentation Index

- Quick Start: LocalFlow (Windows)
  - See `README_LOCALFLOW.md` for end-user setup, hotkeys, and tray usage.
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

## Project Structure (Simplified)

- `localflow/`: Minimal Windows push‑to‑talk app (LocalFlow MVP)
- `voiceflow/`: Full application modules (core, UI, app)
- Entry points: `voiceflow_main.py`, `voiceflow_lite.py`, `voiceflow_debug.py`, `voiceflow_tray.py`
- `tests/`
  - `unit/`: fast, platform‑agnostic unit tests (default)
  - `integration/`: Windows/UI/integration suites (run explicitly)
- `scripts/`: utility scripts (environment checks, audio device listing, etc.)
- `docs/`: this folder (overview, setup, testing, analyses)

## Running Tests

- Default unit set: `pytest -q`
- Full integration set: `pytest tests/integration -q`
- Windows‑only tests: `pytest tests/integration/windows -q`

