# VoiceFlow — Windows Push-to-Talk Transcription

## Overview

VoiceFlow is a Windows-first local push-to-talk transcription app (v3.1.8). Hold `Ctrl+Shift`, speak, release — text is injected into the active application. Tray-first design, no cloud dependency.

**IMPORTANT: This is an active dev project. Do NOT auto-evaluate or run the application unless explicitly asked.**

## Tech Stack

- **Language:** Python 3.9+ (packaging via Hatchling, distributes as standalone EXE)
- **Core:** faster-whisper (local inference), sounddevice/pyaudio (audio capture), keyboard (hotkeys), pystray (tray)
- **GUI:** Tkinter-based tray/overlay UI
- **Packaging:** PyInstaller → `dist/VoiceFlow/VoiceFlow.exe`
- **Tests:** pytest + coverage

## Project Layout

```
src/                  Python source package
  voiceflow/
    core/             Transcription engine, audio capture, learning
    ui/               Tray, overlay, setup wizard, history panels
    utils/            Helpers
scripts/              Automation scripts
tests/                pytest test suite
docs/                 Design docs and guides
dist/VoiceFlow/       Packaged EXE (do not edit directly)
```

## Key Commands

```bash
# Activate venv
venv\Scripts\activate  # Windows

# Run in dev mode (no packaging)
python voiceflow.py

# Run packaged build
dist\VoiceFlow\VoiceFlow.exe

# Run tests
pytest tests/

# Build packaged EXE
python -m PyInstaller ...  # see Makefile
make build
```

## Architecture Notes

- Tray is the primary control surface — setup wizard, settings, history/correction review are all accessed from tray right-click menu
- Setup wizard runs hardware detection on first launch to choose CPU/GPU profile
- Three text cleanup passes: light typo correction (on by default), safe second pass (on by default), heavy cleanup and aggressive context rewrite (opt-in only)
- Continual learning system: local-only, watches transcript→final-text deltas, explicit user corrections rank higher than auto-analysis
- Launcher `.bat` files clean stale processes before relaunch — use these for dev iteration, not the EXE directly

## Testing Philosophy

- Test with the packaged bundle `dist\VoiceFlow\VoiceFlow.exe` for end-to-end validation, not the batch launchers
- Batch launchers are for source debugging only
- Do NOT publish screenshots showing real desktop context (apps, taskbars, personal data)

## Active Development Context

Check `docs/` and open GitHub issues for current priorities. The project is in active development — read existing code before proposing changes to understand current patterns.
