# VoiceFlow

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-pytest-green.svg)](https://pytest.org/)

VoiceFlow is a local, push-to-talk transcription app for Windows. It records while a hotkey is held, transcribes on release, and injects text into your active application (editor, terminal, browser, chat client).

Primary goals:
- fast release-to-text turnaround
- stable behavior for short and long dictation
- local-first privacy (no required cloud service for ASR)

## Current State

- Platform: Windows-first (actively tested and tuned on Windows).
- Engine: `faster-whisper` with CPU and optional CUDA acceleration.
- UI: system tray + overlay indicators + optional Control Center.
- Focus area: reliable dictation workflow for coding and technical writing.

For cross-platform forks (Linux/macOS), read `docs/guides/FORKING_AND_PLATFORM_GUIDE.md`.

## Quick Start (Windows)

1. Clone and create a virtual environment.

```powershell
git clone https://github.com/yourusername/voiceflow.git
cd voiceflow
python -m venv venv
.\venv\Scripts\activate
```

2. Install dependencies.

```powershell
pip install --upgrade pip
pip install -r scripts\setup\requirements_windows.txt
```

Alternative one-step bootstrap:

```powershell
.\Bootstrap_Windows.bat
```

3. Launch VoiceFlow.

```powershell
.\VoiceFlow_Quick.bat
```

## Launch Options

| Mode | Command | When to use |
|---|---|---|
| Standard | `VoiceFlow.bat` | Normal use with visible console output |
| Quick | `VoiceFlow_Quick.bat` | Daily use, no extra pause on exit |
| Silent tray | `VoiceFlow_Silent.bat` | Minimized/background workflow |
| Control Center | `tools\launchers\LAUNCH_CONTROL_CENTER.bat` | Setup, diagnostics, and guided launch |

Manual launch (no batch files):

```powershell
$env:PYTHONPATH = "$pwd\src"
python -m voiceflow.ui.cli_enhanced
```

## Basic Usage

1. Start VoiceFlow.
2. Hold the push-to-talk hotkey (default: `Ctrl+Shift`).
3. Speak while holding.
4. Release to transcribe and inject text to the active target.

Tray menu includes toggles for:
- code mode
- paste vs type injection
- auto-enter
- visual indicators/dock
- push-to-talk preset selection

## Architecture At A Glance

```
src/voiceflow/
  core/          audio capture, ASR, streaming preview, text processing
  integrations/  hotkeys and text injection
  ui/            tray controller, overlay indicators, CLI runtime
  utils/         settings, logging, monitoring, validation
  ai/            optional correction/command/adaptive learning layer
```

Runtime entrypoint for day-to-day use:
- `src/voiceflow/ui/cli_enhanced.py`

See:
- `docs/ARCHITECTURE.md`
- `docs/TECHNICAL_OVERVIEW.md`

## Configuration, Logs, and Data Paths (Windows)

- Config: `%LOCALAPPDATA%\LocalFlow\config.json`
- Logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

Environment overrides:
- `VOICEFLOW_FORCE_CPU=1` to force CPU mode
- `VOICEFLOW_USE_GPU_VENV=0` to prefer `venv` over `.venv-gpu` in launchers

## Testing

Quick checks:

```powershell
python scripts\dev\quick_smoke_test.py
pytest -q tests\test_textproc.py tests\test_injector_logic.py tests\test_sanitization_and_rate.py
```

Broader run:

```powershell
pytest -q
```

More testing details: `docs/TESTING_NOTES.md`.

## Troubleshooting

If audio or transcription is not behaving as expected:

```powershell
python scripts\list_audio_devices.py
python scripts\debugging\debug_hang_issue.py
python scripts\debugging\debug_nonetype_issue.py
```

If tray/overlay state looks stale, restart VoiceFlow and verify only one runtime is active:

```powershell
.\VoiceFlow_Quick.bat
```

## Documentation Map

- `docs/README.md` - full docs index
- `docs/HOW_TO_LAUNCH.md` - launch modes and diagnostics
- `docs/USER_GUIDE.md` - usage and settings
- `docs/ARCHITECTURE.md` - architecture and data flow
- `docs/TECHNICAL_OVERVIEW.md` - module-level implementation notes
- `docs/guides/FORKING_AND_PLATFORM_GUIDE.md` - for contributors/fork maintainers
- `docs/guides/WINDOWS_EXECUTABLE_EVALUATION.md` - executable packaging tradeoffs and plan

## License

MIT License. See `LICENSE`.
