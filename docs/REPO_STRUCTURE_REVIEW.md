# Repository Structure

Date: 2026-02-22

## Active Surface (kept lean)

- `src/voiceflow/` - runtime package
  - `core/` audio + ASR pipeline
  - `integrations/` hotkeys + injection
  - `ui/` tray + CLI runtime
  - `utils/` config/logging/guardrails
  - `ai/` optional local enhancement layer
- `scripts/setup/` - bootstrap/build/install automation
- `scripts/dev/` - active lightweight checks
- `tests/runtime/` - maintained regression suite
- `docs/` - current onboarding + technical docs

## Archived/Removed Surface

The following categories were moved out of the active development path:

- Assistant/framework scaffolding files
- Spec-planning artifacts (`specs/`)
- Legacy runtime/test scripts and deprecated docs
- Unused model/stability modules not referenced by active runtime

Historical material remains under `archive/`.

## Why this structure

- Faster onboarding for contributors
- Lower maintenance overhead
- Reduced risk of leaking local/assistant-specific tooling
- Clear separation between active runtime and historical reference content
