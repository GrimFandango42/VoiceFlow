# Contributing to VoiceFlow

Thanks for contributing.

This project is currently optimized for a Python, Windows-first desktop transcription workflow. Contributions that improve stability, speed, and usability in that context are most valuable.

## Before You Start

1. Check existing issues/PRs.
2. Open an issue for larger behavior changes.
3. Keep changes scoped and testable.

## Development Setup

```powershell
git clone https://github.com/YOUR_USERNAME/voiceflow.git
cd voiceflow
python -m venv venv
.\venv\Scripts\activate
pip install --upgrade pip
pip install -r scripts\setup\requirements_windows.txt
```

Optional:

```powershell
pip install -e .
```

## Run Checks

Minimum before opening a PR:

```powershell
python scripts\dev\quick_smoke_test.py
pytest -q tests\test_textproc.py tests\test_injector_logic.py tests\test_sanitization_and_rate.py
```

For broader validation:

```powershell
pytest -q
```

## Areas Where Regressions Happen Most

- hotkey press/release lifecycle
- focus/injection behavior in editors (VS Code, terminals, browser textareas)
- medium/long dictation latency
- tray/overlay interactions interfering with capture/injection

If you touch these areas, include explicit test notes in the PR.

## Code Guidelines

- Follow existing Python style and naming.
- Keep changes local and avoid broad refactors unless requested.
- Add comments only where logic is non-obvious.
- Do not couple visual effects to ASR critical-path code.

## Documentation Expectations

If behavior changes, update relevant docs in the same PR:
- `README.md`
- `docs/HOW_TO_LAUNCH.md`
- `docs/USER_GUIDE.md`
- `docs/ARCHITECTURE.md` or `docs/TECHNICAL_OVERVIEW.md` (if structural)

## Commit Message Guidance

Use short imperative summaries, for example:
- `Improve long dictation release latency`
- `Fix hotkey release edge case in VS Code`
- `Update launch docs for current batch scripts`

## Pull Request Checklist

- [ ] Change is scoped and explained.
- [ ] Related docs were updated.
- [ ] Minimum checks were run locally.
- [ ] Risks/regressions are called out.
- [ ] Screenshots/log snippets included when UI/runtime behavior changed.

## Platform Scope

- Windows is the main validated target.
- Cross-platform contributions are welcome, but should clearly mark OS-specific behavior and include test instructions.
