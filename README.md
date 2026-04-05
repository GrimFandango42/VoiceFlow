# VoiceFlow

**Local push-to-talk transcription for Windows.** Hold a hotkey, speak, release — your words appear in whatever app you're using. No cloud. No subscription. Runs on your hardware.

[![Latest Release](https://img.shields.io/github/v/release/GrimFandango42/VoiceFlow?display_name=tag&style=for-the-badge)](https://github.com/GrimFandango42/VoiceFlow/releases/latest)
[![Windows](https://img.shields.io/badge/Windows-Supported-0078D4?style=for-the-badge&logo=windows)](https://github.com/GrimFandango42/VoiceFlow/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

---

## What It Does

1. Hold `Ctrl+Shift` (configurable)
2. Speak
3. Release — text appears in your active application

VoiceFlow injects the transcribed text directly using the clipboard or keystroke simulation, whichever the app supports best.

## Features

- **Fully local** — Whisper inference via [faster-whisper](https://github.com/SYSTRAN/faster-whisper), nothing leaves your machine
- **Tray-first** — lives in the system tray, stays out of your way
- **Live audio visualization** — animated overlay shows recording state and voice activity in real time
- **Adaptive text cleanup** — lightweight post-processing corrects common transcription errors; learns your vocabulary over time
- **Hardware-aware setup** — auto-detects GPU/CPU at first run and recommends the right Whisper model
- **Hotkey injection** — works in virtually any Windows application (Notepad, VS Code, browsers, Slack, etc.)
- **Correction workflow** — review and confirm recent transcriptions from the tray; corrections feed back into the learning system
- **No internet required** — after initial model download, runs completely offline

## Installation

### Windows (Recommended)

Download the pre-built executable from the [latest release](https://github.com/GrimFandango42/VoiceFlow/releases/latest):

| File | Description |
|---|---|
| `VoiceFlow-win64.exe` | Single-file installer, easiest to get started |
| `VoiceFlow-portable-win64.zip` | Portable bundle, no installation needed |

Run the executable. On first launch, a setup wizard walks you through hardware detection and model selection.

### From Source (Windows)

```bash
git clone https://github.com/GrimFandango42/VoiceFlow.git
cd VoiceFlow
python -m venv venv
venv\Scripts\activate
pip install -e ".[dev]"
python voiceflow.py
```

Requires Python 3.9+ and, for GPU acceleration, a CUDA-compatible NVIDIA GPU with appropriate drivers.

### macOS / Linux

VoiceFlow is Windows-first. macOS and Linux ports are community targets — see the [porting guide](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) if you want to contribute platform support.

## Quick Start

1. On first run, the setup wizard opens automatically.
2. Click **Run Hardware Check** — this detects your GPU/CPU and recommends a model.
3. Select a profile (`Recommended`, `CPU Compatible`, or `GPU Balanced`) and click **Save And Launch**.
4. Focus any app (Notepad works well for testing).
5. Hold `Ctrl+Shift`, speak a sentence, then release.
6. The transcribed text appears in the focused app.

The tray icon is the main control surface after setup. Right-click it to access settings, history, and correction review.

## Configuration

All settings are accessible from the tray menu — no config file editing required for normal use.

| Goal | Tray Path |
|---|---|
| Reopen setup wizard | `Setup & Defaults` |
| Change push-to-talk hotkey | `PTT Hotkey` |
| Toggle code-mode formatting | `Code Mode` |
| Choose paste vs. keystroke injection | `Injection` |
| Show/hide the visual overlay | `Visual Indicators` |
| Show/hide the dock bar | `Dock` |
| View recent transcriptions | `Recent History` |
| Review and correct transcriptions | `Correction Review` |

For a full settings reference, see the [User Guide](docs/USER_GUIDE.md).

## How It Works

VoiceFlow uses [faster-whisper](https://github.com/SYSTRAN/faster-whisper) for on-device speech recognition. Audio is captured from your microphone while the push-to-talk hotkey is held, then processed in two phases:

1. **Streaming preview** — a short context window gives a live text preview during recording
2. **Final pass** — the full audio chunk is transcribed on release, followed by optional text cleanup passes

Text is injected into the active application via clipboard paste or simulated keystrokes depending on the app and your configured injection mode.

The adaptive learning system watches the difference between raw transcriptions and your corrections over time, building a personal vocabulary map stored locally in `%LOCALAPPDATA%\LocalFlow\`.

## Building from Source

```bash
# Windows — PowerShell
.\scripts\setup\build_windows_exe.ps1

# Result: dist\VoiceFlow\VoiceFlow.exe  (bundle)
#         dist\VoiceFlow-win64.exe       (single-file)
```

See [BUILD_GUIDE.md](docs/BUILD_GUIDE.md) for full build and packaging instructions.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) before opening a pull request.

Quick guidelines:
- Run `pytest tests/` before submitting — all tests must pass
- Follow existing code style (Ruff for Python formatting)
- For significant changes, open an issue first to discuss the approach
- Platform ports (macOS, Linux) are especially welcome — see [FORKING_AND_PLATFORM_GUIDE.md](docs/guides/FORKING_AND_PLATFORM_GUIDE.md)

## Documentation

| Document | Description |
|---|---|
| [User Guide](docs/USER_GUIDE.md) | Tray settings, hotkeys, correction workflow |
| [FAQ](docs/guides/FAQ.md) | Common issues and quick fixes |
| [Build Guide](docs/BUILD_GUIDE.md) | Building and packaging |
| [Technical Overview](docs/TECHNICAL_OVERVIEW.md) | Runtime architecture, config keys |
| [Architecture](docs/ARCHITECTURE.md) | Component design and data flow |
| [Security & Privacy](docs/guides/SECURITY_AND_PRIVACY.md) | What data is stored and where |
| [Platform Porting](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) | Forking guide for non-Windows platforms |

## License

MIT. See [LICENSE](LICENSE).
