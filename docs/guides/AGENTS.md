# Repository Guidelines

## Project Structure & Module Organization
- `src/voiceflow/` holds core runtime modules; `core` for audio pipeline, `ui` for tray/control center, `integrations` for hotkeys, `utils` for shared helpers.
- `tests/` mirrors runtime layers with `unit`, `integration`, `e2e`, `performance`, plus harness scripts (`run_e2e_tests.py`, `reports/`).
- `scripts/` offers maintenance and dev helpers; prefer `scripts/dev/quick_smoke_test.py` and `scripts/testing` harness before release.
- `docs/` and `assets/` provide contributor references and UI media; update diagrams when touching architecture.

## Build, Test, and Development Commands
- `pip install -e ".[dev,test]"` installs editable package with tooling; run after cloning.
- `make test-unit`, `make test-integration`, `make test-comprehensive` invoke curated pytest suites (see `Makefile` for options).
- `pytest` respects strict markers and coverage via `pytest.ini`; e.g. `pytest tests/e2e -m e2e`.
- `pre-commit install` followed by `pre-commit run --all-files` ensures lint, type, and formatting parity locally.

## Coding Style & Naming Conventions
- Python 3.9+ only; keep modules and functions snake_case, classes PascalCase, constants SCREAMING_SNAKE_CASE.
- Enforce type hints; CI runs `mypy` with strict settings, so add `typing.cast` instead of `# type: ignore` unless justified.
- Format with `black` (line length 88) and lint with `ruff check src tests`; fix warnings before submitting.
- Keep docstrings Google-style per `ruff` pydocstyle config; tests may omit docstrings by design.

## Testing Guidelines
- Co-locate new tests under the matching suite; mirror package path to keep fixtures discoverable.
- Targeted commands: `pytest tests/unit -m unit`, `pytest --maxfail=1 --ff` for focused reruns, `make test-performance` before shipping latency work.
- Expect >=90% coverage; HTML reports land in `htmlcov/` thanks to default `--cov-report=html`.
- Use provided fixtures in `tests/conftest.py` and synthetic audio assets under `tests/test_assets/` for reproducible runs.

## Commit & Pull Request Guidelines
- Follow history style: concise, uppercase lead-in (`FEATURE: Improve Streaming Buffer`) plus context; include issue key when available.
- Squash WIP commits locally; keep final diff logically grouped and lint-clean.
- PRs must summarize behavior change, outline test evidence, and attach relevant screenshots/logs (coverage, performance graphs).
- Link to docs updates or raise follow-up issues when a change impacts `docs/` or launch scripts.
