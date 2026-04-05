# VoiceFlow

**Local push-to-talk transcription for Windows.** Hold `Ctrl+Shift`, speak, release — text lands in your active app. No cloud, no subscription, no latency tax.

<p align="center">
  <a href="https://github.com/GrimFandango42/VoiceFlow/releases/latest">
    <img src="https://img.shields.io/github/v/release/GrimFandango42/VoiceFlow?display_name=tag&style=for-the-badge&label=Latest" alt="Latest Release">
  </a>
  <a href="https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-win64.exe">
    <img src="https://img.shields.io/badge/Windows-Download%20EXE-0078D4?style=for-the-badge&logo=windows" alt="Download EXE">
  </a>
  <a href="https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-portable-win64.zip">
    <img src="https://img.shields.io/badge/Windows-Portable%20ZIP-005A9C?style=for-the-badge&logo=windows" alt="Portable ZIP">
  </a>
</p>

---

## What It Does

VoiceFlow uses [faster-whisper](https://github.com/SYSTRAN/faster-whisper) to transcribe your speech locally — no data leaves your machine. A minimal overlay appears at the bottom of your screen while you dictate, then vanishes. The result is injected directly into whatever app has focus: email, code editor, browser text field, Slack, anything.

**Key properties:**

- Entirely offline — Whisper runs on your CPU or GPU
- Tray-resident — zero chrome when not recording
- Adaptive — learns your vocabulary and phrasing over time
- Fast — streaming preview appears before you release the hotkey

## Platform Support

| Platform | Status |
|---|---|
| Windows 10 / 11 | Supported |
| macOS | Community fork target — see [porting guide](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) |
| Linux | Community fork target — see [porting guide](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) |

---

## Quick Start

1. Download `VoiceFlow-win64.exe` from the [latest release](https://github.com/GrimFandango42/VoiceFlow/releases/latest).
2. On first launch, the setup wizard opens automatically. Click **Run Hardware Check** to detect your CPU/GPU profile.
3. Select a startup profile — **Recommended** works for most machines.
4. Click **Save and Launch**.
5. Open any app with a text field (Notepad, browser, IDE).
6. Hold `Ctrl+Shift`, speak, then release.
7. Text appears at the cursor.

That's it. The tray icon is your main control surface from here.

---

## Features

### Transcription
- Real-time streaming preview as you speak
- Three cleanup passes: light typo correction (on), safe second pass (on), heavy rewrite (opt-in)
- Destination-aware formatting — adjusts capitalization and punctuation by target app
- Custom vocabulary file for domain-specific terms

### Continual Learning
- Watches transcript-to-final-text deltas across sessions
- Explicit user corrections are promoted faster than inferred patterns
- All learning is local — stored in `%LOCALAPPDATA%\LocalFlow\`
- Daily batch run writes a learning report with top adaptations
- Raw audio never stored; only text deltas, opt-in

### UI
- Fluid waveform overlay with Siri-style reactive animation
- Streaming live-caption strip shows words as they arrive
- Colour signals current state: blue for listening, amber for processing, green for transcribing
- History panel with correction review — accessible from the tray

### Configuration
- All primary settings available from the tray menu (no config file required for normal use)
- Hardware profiles: `Recommended`, `CPU Compatible`, `GPU Balanced`
- Animation quality: adaptive by default, configurable for low-power machines

---

## Settings Reference

Key defaults (configurable via tray → Settings):

| Setting | Default | Notes |
|---|---|---|
| `enable_light_typo_correction` | `true` | Fast spelling pass |
| `enable_safe_second_pass_cleanup` | `true` | Conservative rewrite |
| `enable_heavy_second_pass_cleanup` | `false` | Opt-in — more aggressive |
| `enable_aggressive_context_corrections` | `false` | Opt-in — full context rewrite |
| `press_enter_after_paste` | `false` | Auto-send on release |
| `visual_animation_quality` | `auto` | `low` / `balanced` / `high` / `auto` |
| `visual_target_fps` | `28` | Reduce on older hardware |
| `adaptive_store_raw_text` | `false` | Opt-in raw snippet storage |

---

## Building from Source

```bash
# Clone and set up
git clone https://github.com/GrimFandango42/VoiceFlow.git
cd VoiceFlow
python -m venv venv
venv\Scripts\activate
pip install -e ".[dev]"

# Run in dev mode (no packaging)
python voiceflow.py

# Run tests
pytest tests/

# Build distributable EXE
scripts\setup\build_windows_exe.ps1
# Output: dist\VoiceFlow\VoiceFlow.exe
```

For a full build walkthrough see [BUILD_GUIDE.md](docs/BUILD_GUIDE.md).

---

## Testing

The source launchers (`VoiceFlow.bat`, `start_dev.vbs`) are for debugging only. End-to-end validation should use the packaged bundle:

```
dist\VoiceFlow\VoiceFlow.exe
```

Run `pytest tests/` for the unit suite. See [TESTING_NOTES.md](docs/TESTING_NOTES.md) for the full test strategy.

---

## Learning Data

Adaptive data lives in `%LOCALAPPDATA%\LocalFlow\`:

| File | Contents |
|---|---|
| `adaptive_patterns.json` | Current replacement rules |
| `daily_learning_reports\` | Per-day batch reports |
| `engineering_terms.json` | Your custom terminology overrides |
| `transcription_corrections.jsonl` | Saved correction-review feedback |

---

## Documentation

| Doc | Contents |
|---|---|
| [docs/README.md](docs/README.md) | Start here |
| [USER_GUIDE.md](docs/USER_GUIDE.md) | Tray settings and personalization |
| [FAQ.md](docs/guides/FAQ.md) | Troubleshooting |
| [BUILD_GUIDE.md](docs/BUILD_GUIDE.md) | Build and packaging |
| [TECHNICAL_OVERVIEW.md](docs/TECHNICAL_OVERVIEW.md) | Architecture deep-dive |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component map |
| [SECURITY_AND_PRIVACY.md](docs/guides/SECURITY_AND_PRIVACY.md) | Privacy model |
| [FORKING_AND_PLATFORM_GUIDE.md](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) | Porting to macOS/Linux |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

---

## License

MIT. See [LICENSE](LICENSE).
