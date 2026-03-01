# VoiceFlow

VoiceFlow is a Windows-first local push-to-talk transcription app.
Hold a hotkey, speak, release, and text is injected into your active app.

## Download (Latest Stable)

[![Latest Release](https://img.shields.io/github/v/release/GrimFandango42/VoiceFlow?display_name=tag&style=for-the-badge)](https://github.com/GrimFandango42/VoiceFlow/releases/latest)
[![Windows EXE](https://img.shields.io/badge/Windows-Download%20EXE-0078D4?style=for-the-badge&logo=windows)](https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-win64.exe)
[![Windows Portable ZIP](https://img.shields.io/badge/Windows-Portable%20ZIP-005A9C?style=for-the-badge&logo=windows)](https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-portable-win64.zip)

| Platform | Status | Download |
|---|---|---|
| Windows | Supported | [Latest release assets](https://github.com/GrimFandango42/VoiceFlow/releases/latest) |
| macOS | Community fork target | [Porting guide](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) |
| Linux | Community fork target | [Porting guide](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) |

## 60-Second Start

1. Run `VoiceFlow-win64.exe` (or `VoiceFlow.exe` from the portable zip).
2. On first run, click `Step 1: Run Hardware Check (Required)` in setup wizard.
3. Choose a startup profile (`Recommended`, `CPU Compatible`, or `GPU Balanced`).
4. Click `Save And Launch`.
5. Focus Notepad (or your target app).
6. Hold `Ctrl+Shift`, speak, then release.
7. Confirm text appears in the target app.

## Configuration UX

VoiceFlow is tray-first by design.

- Launchers clean stale VoiceFlow processes before each relaunch.
- First-run setup wizard recommends defaults from detected hardware.
- First-run startup visually emphasizes Step 1 hardware check and locks Step 2 until check completes.
- First-run startup requires choosing a profile after hardware evaluation.
- Primary settings are available from the tray menu (no JSON editing required for normal use).
- Setup wizard can be reopened from tray (right-click tray icon) via `Setup & Defaults`.
- Setup wizard includes `Run Hardware Check` to quickly re-detect GPU/CPU defaults.
- Recent History and Correction Review are available from the tray for fast feedback loops.
- Current runtime does not include a separate "Command Center" window. The active control surfaces are tray + overlay/dock + history/review panels.

## Transcription Quality Defaults

- Runtime enables a lightweight typo/spelling cleanup pass by default (`enable_light_typo_correction=true`).
- Runtime applies a safe second-pass cleanup by default (`enable_safe_second_pass_cleanup=true`).
- Optional heavier cleanup stays opt-in (`enable_heavy_second_pass_cleanup=false`).
- Aggressive context rewrites are opt-in (`enable_aggressive_context_corrections=false`) to reduce over-correction risk.
- Destination-aware formatting remains enabled by default for readability.
- Visual animation quality defaults to adaptive mode (`visual_animation_quality=auto`, `visual_target_fps=28`).

## Stable Baseline

Known good rollback: [Latest stable release](https://github.com/GrimFandango42/VoiceFlow/releases/latest) (pin specific tags for strict reproducibility).

## Documentation

- [Start Here](docs/README.md)
- [User Guide (tray settings + personalization)](docs/USER_GUIDE.md)
- [FAQ / Quick Troubleshooting](docs/guides/FAQ.md)
- [Build and Packaging](docs/BUILD_GUIDE.md)
- [Technical Overview](docs/TECHNICAL_OVERVIEW.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Forking + Platform Porting](docs/guides/FORKING_AND_PLATFORM_GUIDE.md)

## License

MIT. See `LICENSE`.
