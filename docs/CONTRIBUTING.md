# Contributing to VoiceFlow

## Scope

VoiceFlow is a Windows-first local transcription app. Prioritize:

- release-to-text latency
- transcription quality
- hotkey/injection reliability
- simple install and launch UX

## Setup

```powershell
git clone https://github.com/GrimFandango42/VoiceFlow.git
cd VoiceFlow
powershell -ExecutionPolicy Bypass -File scripts\setup\bootstrap_windows.ps1 -GpuVenv
```

## Minimum Checks Before PR

```powershell
python scripts\dev\quick_smoke_test.py
pytest -q tests\runtime
```

## Coding Notes

- Keep ASR critical path lean.
- Preserve local-first behavior by default.
- Prefer focused changes over broad refactors.
- Update docs in the same PR when behavior changes.
- Keep screenshots and demo assets sanitized. Do not commit images that expose a real desktop, personal workspace details, or unrelated applications.

## PR Checklist

- [ ] Change is scoped and explained.
- [ ] Runtime tests pass locally.
- [ ] Docs updated (if needed).
- [ ] Screenshots/assets are cropped, staged, or redacted if any UI imagery is included.
- [ ] Risks/regressions called out.
