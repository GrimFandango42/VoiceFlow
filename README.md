# VoiceFlow

VoiceFlow is a Windows-first local push-to-talk transcription app.
Hold a hotkey, speak, release, and text is injected into your active app.

## Download (Latest Stable)

[Download Windows EXE](https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-win64.exe)

[Download Portable ZIP](https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-portable-win64.zip)

[Open Latest Release Page](https://github.com/GrimFandango42/VoiceFlow/releases/latest)

## 60-Second Start

1. Run `VoiceFlow-win64.exe` (or `VoiceFlow.exe` from the portable zip).
2. In setup wizard, keep `Recommended` defaults and click `Save And Launch`.
3. Focus Notepad (or your target app).
4. Hold `Ctrl+Shift`, speak, then release.
5. Confirm text appears in the target app.

## Configuration UX

VoiceFlow is tray-first by design.

- First-run setup wizard recommends defaults from detected hardware.
- Primary settings are available from the tray menu (no JSON editing required for normal use).
- Setup wizard can be reopened from tray via `Setup & Defaults`.
- Recent History and Correction Review are available from the tray for fast feedback loops.
- Current runtime does not include a separate "Command Center" window. The active control surfaces are tray + overlay/dock + history/review panels.

## Stable Baseline

Known good rollback: [`v3.1.5`](https://github.com/GrimFandango42/VoiceFlow/releases/tag/v3.1.5) (published February 22, 2026).

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
