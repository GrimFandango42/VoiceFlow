# Contributing to VoiceFlow

Thanks for your interest. VoiceFlow is a Windows-first local transcription tool — contributions that improve reliability, accuracy, or usability are most welcome. This is the only contributing guide; `docs/` links here.

## Before You Start

Read `CLAUDE.md` for project architecture, conventions, and what's in active development, and the [Architecture](docs/ARCHITECTURE.md) page for how the pieces fit. Check open issues to avoid duplicating work.

## What Makes a Good Contribution

- **Bug fixes** with a clear reproduction case
- **Performance improvements** to transcription latency or memory usage (see the [latency budget](docs/LATENCY_BUDGET.md))
- **New hotkey or injection targets** with test coverage
- **UI refinements** that don't increase overlay visual weight
- **Accuracy improvements** to the adaptive learning system

What to avoid without discussion first: reworking the overlay from scratch, adding cloud dependencies (nothing may leave the machine by default), switching audio libraries, changing the data directory structure (migration required).

## Setup

```bash
git clone https://github.com/GrimFandango42/VoiceFlow.git
cd VoiceFlow

# Create and activate a venv (CPU-only is fine for most work)
python -m venv .venv
.venv\Scripts\activate

pip install -e ".[dev]"

# Run tests
pytest tests/
```

For GPU development create `.venv-gpu` (`scripts\setup\bootstrap_windows.ps1 -GpuVenv`) and install a CUDA 12 build of PyTorch into it so the CUDA 12 / cuDNN 9 DLLs are found (see the README GPU note).

## Development Workflow

1. Fork and clone the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make changes with tests where applicable
4. Run `ruff check src/` — this is the CI lint gate (a correctness-focused rule set). `mypy` is configured in `pyproject.toml` but is advisory, not gated.
5. Run `pytest tests/` — all tests must pass
6. If you changed user-visible behaviour, update the docs (see below) and the CHANGELOG
7. Open a PR against `main`

## Dev Launch

```bash
# Hot reload, model in its own process (use the GPU venv for CUDA):
.venv-gpu\Scripts\python.exe dev.py

# Single process, no watcher:
python _app_entry.py
```

Always launch through `_app_entry.py` (or `dev.py`), never `-m voiceflow.ui.cli_enhanced`: the single-instance guard mistakes the py.exe launcher's child for a duplicate and ends it. See [How to launch](docs/HOW_TO_LAUNCH.md) and `VoiceFlow.bat`.

## Code Style

- Python 3.9+ compatible
- Type annotations on all public functions
- Google-style docstrings on public classes and methods
- `ruff` for lint, `mypy` for types (advisory)
- Line length: 88 (not enforced by the CI rule set; keep it close)

## Testing

```bash
pytest tests/                          # full suite (tests/runtime)
pytest tests/ -m "not audio and not gui and not slow"   # what CI runs
pytest tests/ -k "test_transcription"  # specific tests
pytest tests/ --cov=src                # with coverage
```

Tests live in `tests/runtime/`. Prefer unit tests for pure logic; tests that need a microphone or a display are marked `@pytest.mark.audio` / `@pytest.mark.gui`. The suite runs against a temporary data directory and never touches your real `%LOCALAPPDATA%\VoiceFlow`. More in [Testing notes](docs/TESTING_NOTES.md).

For end-to-end validation use the packaged bundle (`dist\VoiceFlow\VoiceFlow.exe`) rather than the batch launchers.

## Documentation

- Keep `README.md` short; details go in `docs/USER_GUIDE.md` or `docs/ARCHITECTURE.md`. Do not add a second copy of anything — link instead.
- `python scripts/check_docs.py` checks every relative link, image path and anchor (it also runs in the test suite).
- Screenshots are generated, never captured from a real desktop: `python scripts/capture_screenshots.py` renders the overlay, tray menu and setup window in a demo mode (no microphone, no hotkeys, no paste, fixed demo text). Re-run it after a UI change and commit the images it overwrites. Delete images nothing references.
- Superseded documents move to `docs/archive/` with a one-line pointer at the top.

## Pull Request Guidelines

- One feature or fix per PR
- Include a clear description of what changed and why
- Reference any related issues with `Fixes #123`
- Screenshots or recordings welcome for UI changes — use the demo-mode script above, and don't publish images containing real desktop context (taskbars, account names, personal data); see `docs/guides/SECURITY_AND_PRIVACY.md`

## Reporting Bugs

Use the bug report issue template. Include:
- Windows version and Python version
- GPU/CPU mode (the log line `asr_engine_initialized` shows `device=cuda` or `device=cpu`)
- Log file excerpt from `%LOCALAPPDATA%\VoiceFlow\logs\voiceflow.log` (review it before sharing)
- Steps to reproduce

## Questions

Open a Discussion rather than an issue for general questions.
