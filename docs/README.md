# VoiceFlow Documentation

This index points to the current, maintained documentation set for the Python-based VoiceFlow runtime.

## Start Here

- Project overview: `../README.md`
- Launch guide: `HOW_TO_LAUNCH.md`
- End-user workflow: `USER_GUIDE.md`

## Core Technical Docs

- Architecture: `ARCHITECTURE.md`
- Technical overview: `TECHNICAL_OVERVIEW.md`
- Testing notes: `TESTING_NOTES.md`
- Build and packaging notes: `BUILD_GUIDE.md`
- Contribution workflow: `CONTRIBUTING.md`

## Platform and Forking

- Forking and platform adaptation: `guides/FORKING_AND_PLATFORM_GUIDE.md`
- Windows launch checklist: `guides/WINDOWS_APP_TEST_CHECKLIST.md`
- App-specific validation scenarios: `guides/APPLICATION_SPECIFIC_TEST_SCENARIOS.md`

## Reports and Historical Material

- Current reports: `reports/`
- Performance analyses: `analysis/`
- Archived historical docs: `archive/`
- Legacy export artifacts: `VoiceFlow_Architecture_Guide.pdf` and `VoiceFlow_Architecture_Guide.txt` (reference only)

## Repository Layout (Relevant For Onboarding)

- `src/voiceflow/` - runtime code (`core`, `integrations`, `ui`, `utils`, `ai`)
- `scripts/` - setup, diagnostics, and development tooling
- `tools/` - launcher utilities and Control Center
- `tests/` - unit, integration, performance, and stability suites

## Recommended Validation Commands

- Smoke check: `python scripts/dev/quick_smoke_test.py`
- Fast regression slice: `pytest -q tests/test_textproc.py tests/test_injector_logic.py tests/test_sanitization_and_rate.py`
- Broader suite: `pytest -q`

