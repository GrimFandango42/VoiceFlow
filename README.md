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

1. Run `VoiceFlow-win64.exe` from Releases, or `dist\VoiceFlow\VoiceFlow.exe` for local packaged testing.
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
- Local end-to-end testing should use the packaged bundle executable: `dist\VoiceFlow\VoiceFlow.exe`.
- Batch launchers remain useful for source debugging, not as the default daily test path.
- Setup wizard includes `Run Hardware Check` to quickly re-detect GPU/CPU defaults.
- Recent History and Correction Review are available from the tray for fast feedback loops.
- Core control surfaces are the setup wizard, tray menu, overlay/dock, and history/review panels.
- Public docs should use cropped or staged VoiceFlow UI captures only; do not publish screenshots that expose real desktop apps, tabs, taskbars, or personal workspace context.

## Transcription Quality Defaults

- Runtime enables a lightweight typo/spelling cleanup pass by default (`enable_light_typo_correction=true`).
- Runtime applies a safe second-pass cleanup by default (`enable_safe_second_pass_cleanup=true`).
- Optional heavier cleanup stays opt-in (`enable_heavy_second_pass_cleanup=false`).
- Aggressive context rewrites are opt-in (`enable_aggressive_context_corrections=false`) to reduce over-correction risk.
- Destination-aware formatting remains enabled by default for readability.
- Default release behavior pastes text on release without auto-sending Enter (`press_enter_after_paste=false`).
- Visual animation quality defaults to adaptive mode (`visual_animation_quality=auto`, `visual_target_fps=28`).
- The first long dictation after extended idle favors completeness over aggressive pause compaction.

## Continual Learning

- Runtime adaptive learning stays local and observes recurring transcript-to-final-text deltas.
- Explicit correction signals are treated as higher-trust than auto-analysis, so accent/workflow corrections promote faster than speculative cleanup rules.
- Saved correction-review feedback is promoted back into the active runtime learner, so the current session can adapt before the next daily batch run.
- Built-in terminology cleanup already biases common coding-tool phrasing such as `Claude Code` and `Claude Desktop` without forcing risky blanket `cloud -> Claude` rewrites.
- Raw transcript snippet storage is opt-in (`adaptive_store_raw_text=false` by default).
- Daily learning writes a report plus an adaptive snapshot with top learned replacements and frequent recent domain tokens.
- Inspect `%LOCALAPPDATA%\LocalFlow\adaptive_patterns.json` and `%LOCALAPPDATA%\LocalFlow\daily_learning_reports\` to see what is sticking.
- Add personal/work-domain overrides in `%LOCALAPPDATA%\LocalFlow\engineering_terms.json` if you want a local terminology file on top of the built-in rules.

## Stable Local Test Loop

1. Build the bundle with `scripts\setup\build_windows_exe.ps1`.
2. Launch `dist\VoiceFlow\VoiceFlow.exe`.
3. If validating onboarding, start from a clean config or reopen `Setup & Defaults` from tray.
4. Verify one short `Ctrl+Shift` dictation and one target-app injection before calling the build stable.
5. Reserve one-file exe rebuilds for release validation; they are significantly slower than the bundle build.

## Stable Baseline

Known good rollback: [Latest stable release](https://github.com/GrimFandango42/VoiceFlow/releases/latest) (pin specific tags for strict reproducibility).

## Documentation

- [Start Here](docs/README.md)
- [User Guide (tray settings + personalization)](docs/USER_GUIDE.md)
- [FAQ / Quick Troubleshooting](docs/guides/FAQ.md)
- [Build and Packaging](docs/BUILD_GUIDE.md)
- [Technical Overview](docs/TECHNICAL_OVERVIEW.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security + Privacy Operations](docs/guides/SECURITY_AND_PRIVACY.md)
- [Forking + Platform Porting](docs/guides/FORKING_AND_PLATFORM_GUIDE.md)

## License

MIT. See `LICENSE`.
