# Repository Audit - 2026-02-15

## Objective

Perform a practical cleanup pass focused on:
- preserving the currently stable transcription runtime
- reducing confusion from stale scripts/docs
- improving onboarding and forkability

## What Was Reviewed

- Runtime launch surface (`VoiceFlow*.bat`, `tools/launchers/*`, `voiceflow.py`)
- Control Center launch/health flow
- Setup and smoke scripts
- Core documentation index and onboarding docs

## Key Findings

1. Historical `localflow` references remained in several utility scripts.
2. `LAUNCH_SMART.bat` referenced outdated module paths and setup paths.
3. Legacy health-check scripts had stale imports and could fail despite a healthy runtime.
4. Control Center health-check callback behavior treated failures as success.
5. Installation path was functional but not streamlined for fork-first onboarding.

## Changes Applied

### Runtime and launch cleanup
- Updated `tools/launchers/LAUNCH_SMART.bat` to:
  - use repository-root paths
  - call `scripts\setup\setup_voiceflow.py` correctly
  - launch `VoiceFlow_Quick.bat`
- Updated `tools/launchers/LAUNCH_TRAY.bat` to use canonical quick launcher.
- Updated `tools/launchers/LAUNCH_TERMINAL.bat` to use `voiceflow.py --no-tray`.

### Setup and diagnostics cleanup
- Added `scripts/setup/bootstrap_windows.ps1`.
- Added root helper launcher: `Bootstrap_Windows.bat`.
- Updated `scripts/setup/setup_voiceflow.py`:
  - repo-root path handling
  - removed obsolete `RealtimeSTT` dependency branch
  - updated next-step guidance
- Updated `scripts/dev/quick_smoke_test.py` dependency checks to current stack.
- Replaced legacy health-check scripts with wrappers to `quick_smoke_test`:
  - `scripts/dev/health_check.py`
  - `scripts/dev/health_check_simple.py`
- Rewrote `scripts/dev/verify_visual_system.py` to current module paths.
- Fixed stale imports in utility scripts:
  - `scripts/bench_env.py`
  - `scripts/check_mappings.py`
  - `scripts/smoke.py`

### Documentation alignment
- Added executable feasibility guide:
  - `docs/guides/WINDOWS_EXECUTABLE_EVALUATION.md`
- Updated docs index to include bootstrap and executable guide.
- Updated README quick-start to include bootstrap path.

## Intentional Non-Changes

- No removal of `archive/` or broad test deletions in this pass.
- No runtime ASR/hotkey behavior changes were introduced.
- No animation/transcription pipeline modifications in this cleanup pass.

## Recommended Next Cleanup Wave

1. Move clearly obsolete developer scripts into `archive/` with a changelog note.
2. Define an "active test matrix" and mark non-core suites as opt-in.
3. Add CI job for the smoke check + curated regression slice.
4. Add packaging pipeline (PyInstaller) once functional parity is validated.
