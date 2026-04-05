# VoiceFlow

**Local push-to-talk transcription for Windows.** Hold a hotkey, speak, release — transcribed text is injected directly into any active application. No cloud, no subscription, no latency after the first load.

[![Latest Release](https://img.shields.io/github/v/release/GrimFandango42/VoiceFlow?display_name=tag&style=for-the-badge)](https://github.com/GrimFandango42/VoiceFlow/releases/latest)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows)](https://github.com/GrimFandango42/VoiceFlow/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

---

## What is VoiceFlow?

VoiceFlow runs entirely on your machine using [faster-whisper](https://github.com/SYSTRAN/faster-whisper) (Distil-Whisper Large v3.5 by default). There is no API call on the transcription path — audio goes in, text comes out locally, and is injected into whatever window you have focused.

It ships with a continual-learning system that adapts to your accent and vocabulary over time, a streaming preview that shows partial transcription while you speak, and a tray-first UI that stays out of the way when you're not using it.

---

## Quick Start

### Requirements

- Windows 10 or 11 (64-bit)
- 4 GB RAM minimum; 8 GB+ recommended for GPU mode
- NVIDIA GPU with CUDA 11.8+ for GPU acceleration (optional but recommended)

### Install

**Option A — Packaged EXE (recommended)**

1. Download `VoiceFlow-win64.exe` from the [latest release](https://github.com/GrimFandango42/VoiceFlow/releases/latest).
2. Run it. Windows may show a SmartScreen warning — click **More info → Run anyway**.
3. On first launch the setup wizard opens. Click **Run Hardware Check**, choose a profile, and click **Save and Launch**.

**Option B — From source**

```bash
git clone https://github.com/GrimFandango42/VoiceFlow.git
cd VoiceFlow
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
cd src
python -m voiceflow.ui.cli_enhanced
```

> **GPU users:** use `.venv-gpu` with `pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118` before the editable install.

### First use

1. The setup wizard opens on first launch. Run the hardware check to auto-select CPU or GPU mode.
2. Click **Save and Launch**.
3. Focus any text field (Notepad, VS Code, a browser input, anything).
4. Hold **Ctrl+Shift**, speak, then release.
5. Transcribed text appears at your cursor.

---

## Features

- **Hold-to-record** with configurable hotkey (`Ctrl+Shift` default)
- **Local inference** — faster-whisper, no internet required after model download
- **GPU acceleration** — CUDA path for NVIDIA GPUs; automatic CPU fallback
- **Streaming preview** — partial transcription visible while speaking
- **Continual learning** — adapts to your accent and domain vocabulary over time
- **Text injection** — pastes directly into the active application
- **Tray-first UI** — stays out of the way; right-click tray for settings
- **Three cleanup passes** — light typo fix (on), safe second pass (on), heavy rewrite (opt-in)
- **History & correction** — review recent transcriptions, submit corrections from tray
- **Cold-start elimination** — model pre-warmed before first keypress

---

## Architecture Overview

```
voiceflow/
├── core/
│   ├── asr_engine.py        # faster-whisper inference, model tier selection
│   ├── audio.py             # sounddevice capture, VAD, chunking
│   ├── streaming.py         # streaming partial results
│   ├── textproc.py          # cleanup passes, destination-aware formatting
│   └── config.py            # typed config dataclass
├── ui/
│   ├── cli_enhanced.py      # main entry point, hotkey listener, orchestration
│   ├── visual_indicators.py # overlay + dock UI (tkinter)
│   ├── enhanced_tray.py     # system tray (pystray)
│   └── setup_wizard.py      # first-run wizard (tkinter)
├── ai/
│   ├── adaptive_memory.py   # continual learning, pattern extraction
│   ├── daily_learning.py    # nightly batch learning pass
│   └── course_corrector.py  # real-time correction pipeline
└── platform/
    └── factory.py           # platform injection abstraction (Windows: pywin32)
```

The hotkey listener captures audio into a ring buffer, passes it through VAD, then calls the ASR engine. Text flows through the cleanup pipeline and is injected via the platform layer. The UI receives status updates over a thread-safe command queue.

---

## Platform Support

| Platform | Status |
|----------|--------|
| Windows 10/11 | Fully supported |
| macOS | Community fork — see [FORKING_AND_PLATFORM_GUIDE.md](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) |
| Linux | Community fork — see [FORKING_AND_PLATFORM_GUIDE.md](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) |

---

## Configuration

Most settings are available through the setup wizard (right-click tray → **Setup & Defaults**). Config is stored at `%LOCALAPPDATA%\LocalFlow\config.json`.

Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `device` | auto | `cuda` or `cpu` |
| `model_tier` | `balanced` | `quick`, `balanced`, `quality` |
| `enable_light_typo_correction` | `true` | Light cleanup pass |
| `enable_safe_second_pass_cleanup` | `true` | Second cleanup pass |
| `enable_heavy_second_pass_cleanup` | `false` | Aggressive rewrite (opt-in) |
| `press_enter_after_paste` | `false` | Auto-submit after paste |

---

## Continual Learning

VoiceFlow observes the delta between raw transcripts and final text. Recurring corrections are promoted into adaptive replacement rules.

- Rules are stored locally in `%LOCALAPPDATA%\LocalFlow\adaptive_patterns.json`
- Daily learning runs a nightly batch pass; reports land in `%LOCALAPPDATA%\LocalFlow\daily_learning_reports\`
- Explicit corrections via the History panel rank higher than auto-inferred rules
- Add personal terminology in `%LOCALAPPDATA%\LocalFlow\engineering_terms.json`

---

## Contributing

1. Fork the repo and create a feature branch from `main`.
2. Set up the dev environment:
   ```bash
   pip install -e ".[dev]"
   ```
3. Run the test suite before and after your changes:
   ```bash
   pytest tests/ -x -q
   ```
4. Keep UI changes in `visual_indicators.py`; keep ASR changes in `core/`. Do not mix layers.
5. Test with the packaged bundle (`dist\VoiceFlow\VoiceFlow.exe`) for end-to-end validation.
6. Open a pull request against `main` with a description of what changed and why.

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for the full guide.

---

## License

MIT — see [LICENSE](LICENSE).
