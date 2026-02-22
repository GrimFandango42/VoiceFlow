# VoiceFlow

VoiceFlow is a Windows-first, local push-to-talk transcription app.
Hold a hotkey, speak, release, and text is injected into your active app.

## Download (Windows)

- Executable (`VoiceFlow-win64.exe`): `https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-win64.exe`
- Portable zip (`VoiceFlow-portable-win64.zip`): `https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-portable-win64.zip`
- Latest release page: `https://github.com/GrimFandango42/VoiceFlow/releases/latest`

If a direct link returns `404` right after a release publish, open the latest release page and download the asset manually.

## Quick Start

1. Launch `VoiceFlow.exe`.
2. Hold `Ctrl+Shift`.
3. Speak, then release.
4. Confirm text appears in Notepad/your editor.

If nothing is inserted, open `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`.
If a popup steals focus during release, VoiceFlow now copies the transcript to clipboard as a fallback.

## Hardware + Model Defaults

VoiceFlow is preconfigured to auto-select sensible runtime settings:

- `device=auto`: tries CUDA first, falls back to CPU.
- `model_tier=quick`: adaptive:
  - CUDA: `distil-large-v3` (`float16`)
  - CPU: `small.en` (`int8`)

Recommended tiers if you want to override:

| Hardware | Recommended Tier | Why |
|---|---|---|
| Older CPU-only laptop | `tiny` or `quick` | Lowest latency |
| Modern CPU-only desktop | `quick` | Good latency/quality balance |
| NVIDIA GPU (CUDA) | `quick` or `balanced` | Fast and high quality |
| Accuracy-first workflows | `quality` | Best recognition, slower |

Config file:
- `%LOCALAPPDATA%\LocalFlow\config.json`

Injection guardrail defaults:
- `inject_require_target_focus=true`
- `inject_refocus_on_miss=true`
- `inject_refocus_attempts=3`

## Personalization Features (Kept)

- Recent history panel
- Correction review and daily learning
- Custom engineering terms dictionary
- Code mode + destination-aware formatting

These are still part of the active runtime; cleanup did not remove them.

## Local Data Paths

- Config: `%LOCALAPPDATA%\LocalFlow\config.json`
- Logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`
- Recent history: `%LOCALAPPDATA%\LocalFlow\recent_history_events.jsonl`
- Corrections: `%LOCALAPPDATA%\LocalFlow\transcription_corrections.jsonl`
- Adaptive patterns: `%LOCALAPPDATA%\LocalFlow\adaptive_patterns.json`

## Developer Setup

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\bootstrap_windows.ps1 -GpuVenv
```

Run tests:

```powershell
pytest -q tests\runtime
```

## Packaging

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\build_windows_exe.ps1 -OutputName VoiceFlow -Clean
```

## Docs

- Docs index: `docs/README.md`
- User guide: `docs/USER_GUIDE.md`
- Build guide: `docs/BUILD_GUIDE.md`
- Architecture: `docs/ARCHITECTURE.md`

## License

MIT. See `LICENSE`.
