# Contributing to VoiceFlow

Thanks for your interest. VoiceFlow is a Windows-first local transcription tool — contributions that improve reliability, accuracy, or usability are most welcome.

## Before You Start

Read `CLAUDE.md` for project architecture, conventions, and what's in active development. Check open issues to avoid duplicating work.

## What Makes a Good Contribution

- **Bug fixes** with a clear reproduction case
- **Performance improvements** to transcription latency or memory usage
- **New hotkey or injection targets** with test coverage
- **UI refinements** that don't increase overlay visual weight
- **Accuracy improvements** to the adaptive learning system

What to avoid without discussion first: reworking the overlay from scratch, adding cloud dependencies, switching audio libraries, changing the data directory structure (migration required).

## Setup

```bash
git clone https://github.com/GrimFandango42/VoiceFlow.git
cd VoiceFlow

# Create and activate venv (CPU-only is fine for most work)
python -m venv venv
venv\Scripts\activate

pip install -e ".[dev]"

# Run tests
pytest tests/
```

For GPU development, create `.venv-gpu` with your CUDA-compatible torch build and faster-whisper.

## Development Workflow

1. Fork and clone the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make changes with tests where applicable
4. Run `ruff check src/` and `mypy src/` — fix any issues
5. Run `pytest tests/` — all tests must pass
6. Open a PR against `main`

## Dev Launch

```bash
# Always use _app_entry.py for dev launches — not -m voiceflow.ui.cli_enhanced
python _app_entry.py
```

The `-m voiceflow.ui.cli_enhanced` form triggers a false-positive in the single-instance guard when the py.exe shim is in use. See `VoiceFlow.bat` for the canonical launcher.

## Code Style

- Python 3.9+ compatible
- Type annotations on all public functions
- Google-style docstrings on public classes and methods
- `ruff` for formatting and lint, `mypy` for types
- Max line length: 88

## Testing

```bash
pytest tests/                          # full suite
pytest tests/ -m "not slow"           # skip slow tests
pytest tests/ -k "test_transcription" # specific tests
pytest tests/ --cov=src               # with coverage
```

Tests are in `tests/runtime/`. Prefer unit tests for pure logic; integration tests for audio capture and injection require real hardware and are marked `@pytest.mark.audio`.

## Pull Request Guidelines

- One feature or fix per PR
- Include a clear description of what changed and why
- Reference any related issues with `Fixes #123`
- Screenshots or recordings welcome for UI changes
- Don't publish screenshots containing real desktop context (taskbars, account names, personal data) — see `docs/guides/SECURITY_AND_PRIVACY.md`

## Reporting Bugs

Use the bug report issue template. Include:
- Windows version and Python version
- GPU/CPU mode (check tray tooltip)
- Log file excerpt from `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`
- Steps to reproduce

## Questions

Open a Discussion rather than an issue for general questions.
