# VoiceFlow

**Local push-to-talk transcription for Windows.** Hold a hotkey, speak, release — text is injected directly into whatever app is in focus. No cloud. No subscription. Runs entirely on your machine.

[![Latest Release](https://img.shields.io/github/v/release/GrimFandango42/VoiceFlow?display_name=tag&style=flat-square)](https://github.com/GrimFandango42/VoiceFlow/releases/latest)
[![Windows](https://img.shields.io/badge/platform-Windows-0078D4?style=flat-square&logo=windows)](https://github.com/GrimFandango42/VoiceFlow/releases/latest)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

---

## What It Does

VoiceFlow sits in your system tray. Hold `Ctrl+Shift`, dictate, release. Your words appear in the focused window — email, Slack, VS Code, Notepad, anywhere. The overlay shows a live animated waveform while you speak and displays a streaming preview of the transcription in real time.

Everything runs locally using [faster-whisper](https://github.com/guillaumekynast/faster-whisper). No audio leaves your machine.

## Features

- **Push-to-talk** — `Ctrl+Shift` (configurable) triggers recording; release to transcribe
- **Live animated overlay** — a centered pulsing orb with ripple rings reacts to your voice in real time
- **Streaming preview** — partial transcription appears as you speak, confirmed on release
- **Direct text injection** — pastes into whatever app has focus, no clipboard hijacking
- **Local-only inference** — faster-whisper runs on CPU or CUDA GPU, fully offline
- **Adaptive hardware profiles** — setup wizard detects your GPU/CPU and picks the right Whisper model and compute type
- **Continual learning** — VoiceFlow learns from your corrections and recurring phrasing over time
- **Tray-first design** — no main window; all settings and history are one right-click away
- **Three-pass text cleanup** — light typo fix (default), safe second pass (default), heavy rewrite (opt-in)
- **Correction review** — review and correct recent transcriptions from the tray
- **History panel** — searchable, filterable transcript log accessible from the tray

## Download

| Platform | Status | Download |
|---|---|---|
| Windows 10/11 | Supported | [Latest release](https://github.com/GrimFandango42/VoiceFlow/releases/latest) |
| macOS | Community fork target | [Porting guide](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) |
| Linux | Community fork target | [Porting guide](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) |

Grab `VoiceFlow-win64.exe` from the releases page for the standalone installer, or `VoiceFlow-portable-win64.zip` for a portable folder you can run anywhere.

## Quick Start (Windows)

1. Download `VoiceFlow-win64.exe` from [Releases](https://github.com/GrimFandango42/VoiceFlow/releases/latest) and run it.
2. On first launch the setup wizard opens. Click **Run Hardware Check** — this detects your GPU/CPU and recommends a Whisper model.
3. Pick a startup profile (`Recommended`, `CPU Compatible`, or `GPU Balanced`) and click **Save And Launch**.
4. VoiceFlow appears in the system tray (bottom-right).
5. Click into Notepad (or any text field).
6. Hold `Ctrl+Shift`, speak a sentence, then release.
7. Your words appear in the focused window.

That's it. Right-click the tray icon to access settings, history, and correction review.

## Running from Source

Requirements: Python 3.9+, Git, Windows 10/11.

```bash
git clone https://github.com/GrimFandango42/VoiceFlow.git
cd VoiceFlow

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -e .

# Run
python voiceflow.py
```

On first run the setup wizard will guide you through hardware detection and profile selection.

## Building a Standalone EXE

```bash
# Activate venv first
venv\Scripts\activate

# Build (uses PyInstaller via Makefile wrapper)
make build

# The output is at dist\VoiceFlow\VoiceFlow.exe
```

See [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) for full build and packaging details.

## Configuration

All core settings are accessible from the tray icon — no JSON editing required for normal use. Right-click the tray icon and choose **Setup & Defaults** to reopen the setup wizard at any time.

Key settings (all configurable from the tray):

| Setting | Default | Notes |
|---|---|---|
| Hotkey | `Ctrl+Shift` | Configurable to any key combo |
| Startup profile | Auto-detected | CPU Compatible / Recommended / GPU Balanced |
| Text cleanup | Light + Safe passes on | Heavy rewrite is opt-in |
| Auto-press Enter | Off | Enable for single-line inputs like search bars |
| Animation quality | Auto | Auto / High / Balanced / Low |
| Theme | Dark | Dark / Light |

Advanced users can edit `%LOCALAPPDATA%\LocalFlow\config.json` directly. See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for the full settings reference.

### Personal Terminology

Add work-specific words that Whisper frequently mishears to `%LOCALAPPDATA%\LocalFlow\engineering_terms.json`:

```json
{
  "corrections": {
    "my company": "MyCompany",
    "voice flow": "VoiceFlow"
  }
}
```

## Architecture Overview

```
voiceflow.py               Entry point; wires everything together
src/voiceflow/
  core/
    asr_engine.py          faster-whisper inference wrapper
    audio.py               sounddevice capture loop
    streaming.py           Streaming VAD + partial transcription
    textproc.py            Three-pass text cleanup pipeline
  ui/
    visual_indicators.py   Overlay window + ripple-orb animation
    tray.py                System tray icon and menu
    setup_wizard.py        First-run hardware detection UI
  integrations/
    hotkeys.py             Global hotkey listener (keyboard lib)
    inject.py              Text injection via Win32 SendInput
  ai/
    adaptive_memory.py     Continual learning from corrections
    daily_learning.py      Daily batch pattern analysis
```

VoiceFlow uses a single background thread for inference and a separate Tkinter thread for the UI. The overlay communicates with the inference thread via a thread-safe command queue. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Overlay Animation

The status overlay displays a **centered pulsing orb** with three concentric ripple rings. At idle it breathes softly. When you speak, the orb expands and the rings radiate outward in staggered phases — similar to Siri's voice indicator. A sine wave flows behind the orb and reacts to frequency content (bass vs. treble). The animation color shifts between states: blue when listening, amber when processing, green when writing.

## Running Tests

```bash
venv\Scripts\activate
pytest tests/
```

For coverage:

```bash
pytest tests/ --cov=src/voiceflow --cov-report=term-missing
```

See [docs/TESTING_NOTES.md](docs/TESTING_NOTES.md) for the full testing philosophy and integration test setup.

## macOS / Linux Porting

VoiceFlow is Windows-first. The core transcription pipeline (`core/`) is platform-agnostic Python. The platform-specific parts are:

- **Text injection** — uses Win32 `SendInput` via ctypes (`integrations/inject.py`)
- **Global hotkeys** — uses the `keyboard` library, which requires root on Linux
- **Tray icon** — uses `pystray`, which works on macOS/Linux but may need `AppIndicator` on GNOME
- **Audio capture** — uses `sounddevice`, which is cross-platform

A `platform/` abstraction layer (`src/voiceflow/platform/`) is in place. See [docs/guides/FORKING_AND_PLATFORM_GUIDE.md](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) for a step-by-step guide to porting.

## Contributing

Contributions are welcome. Please read [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) before opening a PR.

The short version:

1. Fork and clone the repo.
2. Create a feature branch: `git checkout -b feat/my-feature`.
3. Make your changes, add tests if applicable.
4. Run `pytest tests/` and confirm nothing breaks.
5. Open a pull request with a clear description of what changed and why.

For larger changes, open an issue first to discuss the approach.

## Documentation

| Doc | What it covers |
|---|---|
| [User Guide](docs/USER_GUIDE.md) | All tray settings, personalisation, continual learning |
| [Build Guide](docs/BUILD_GUIDE.md) | Building the EXE and release packaging |
| [Architecture](docs/ARCHITECTURE.md) | Component design and data flow |
| [Technical Overview](docs/TECHNICAL_OVERVIEW.md) | Runtime config, inference pipeline, tuning |
| [Security & Privacy](docs/guides/SECURITY_AND_PRIVACY.md) | What data stays local, what doesn't |
| [FAQ](docs/guides/FAQ.md) | Common issues and fixes |
| [Porting Guide](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) | macOS / Linux porting notes |
| [CHANGELOG](CHANGELOG.md) | Version history |

## License

MIT. See [LICENSE](LICENSE).
