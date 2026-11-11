# VoiceFlow — Windows Push-to-Talk Transcription

> `AGENTS.md` and `CLAUDE.md` are intentionally identical (one for each assistant family). Edit both together.

## Overview

VoiceFlow is a Windows-first local push-to-talk transcription app (v3.2.1). Hold `Ctrl+Shift`, speak, release — text is pasted into the active application. Tray-first design, no cloud dependency (one optional, off-by-default nightly cloud step; see `docs/guides/SECURITY_AND_PRIVACY.md`).

**IMPORTANT: This is an active dev project. Do NOT auto-evaluate or run the application unless explicitly asked.**

## Tech Stack

- **Language:** Python 3.9+ (packaging via Hatchling, distributes as standalone EXE)
- **Core:** faster-whisper / ctranslate2 (local inference), sounddevice (audio capture), keyboard (hotkeys), pystray (tray)
- **GUI:** Tkinter overlay, dock, history panel and setup wizard
- **Packaging:** PyInstaller → `dist/VoiceFlow/VoiceFlow.exe`
- **Tests:** pytest (`tests/runtime`), ruff lint gate in CI

## Project Layout

```
src/voiceflow/
  core/             ASR engine, audio capture, segmenter, text processing, history, vocabulary
  integrations/     Hotkeys and text injection
  ui/               Tray, overlay + dock + history panel, setup wizard, runtime orchestration
  ai/               Learning (adaptive, hotwords, nightly), review queue
  utils/            Config, logging, build identity, monitoring
scripts/            setup/ (build, bootstrap, verify_bundle), dev/, capture_screenshots.py, check_docs.py
tests/runtime/      pytest suite
docs/               User guide, architecture, build/launch guides, guides/, archive/, screenshots/
dist/VoiceFlow/     Packaged EXE (build output; do not edit directly)
```

## Key Commands

```bash
# Dev, GPU, hot reload (model in its own process); use .venv-gpu for CUDA
.venv-gpu\Scripts\python.exe dev.py

# Dev, single process
python _app_entry.py          # never `python -m voiceflow.ui.cli_enhanced` (single-instance guard)

# Tests / lint (what CI runs)
pytest tests/ -m "not audio and not gui and not slow"
ruff check src/

# Docs
python scripts/check_docs.py          # links, image paths, anchors
python scripts/capture_screenshots.py # regenerate docs/screenshots (demo mode, Windows desktop)

# Build the packaged EXE (verifies itself; fails on a stale or broken bundle)
powershell -ExecutionPolicy Bypass -File scripts\setup\build_windows_exe.ps1 -OutputName VoiceFlow -Clean

# Check a bundle without the mic/tray/hotkeys
dist\VoiceFlow\VoiceFlow.exe --self-check=report.json
```

## Architecture Notes

- Tray is the primary control surface — setup wizard, settings, recent dictations, history/correction review are all reached from the tray right-click menu. The dock and overlay show state; the dock also shows the build's "Updated" date.
- Keys: `Ctrl+Shift` hold to record, `Esc` cancels, `Alt+Shift+V` re-pastes the last transcript; `Ctrl+Alt+C/P/Enter` are toggles. Avoid `Ctrl+Alt` for new keys (Wispr Flow and the toggles use it).
- Every final transcript is saved to history (`core/history.py`) before the paste is attempted; `inject_target_policy` decides which window gets the text.
- Long recordings (≥ 20 s) are cut at pauses and decoded piece by piece, with a Silero VAD gate; spoken commands and conservative cleanup live in `core/dictation_format.py`.
- Three text cleanup passes: light typo correction (on by default), safe second pass (on by default), heavy cleanup and aggressive context rewrite (opt-in only).
- Continual learning is local-only; explicit user corrections rank higher than auto-analysis; twice-corrected terms become Whisper hotwords. Cloud transcript analysis is opt-in and off by default.
- Launcher `.bat` files clean stale processes before relaunch — use them for source debugging, not the EXE.

## Testing Philosophy

- Test with the packaged bundle `dist\VoiceFlow\VoiceFlow.exe` for end-to-end validation, not the batch launchers
- Batch launchers are for source debugging only
- The test suite repoints `%LOCALAPPDATA%` to a temp folder; keep it that way
- Do NOT publish screenshots showing real desktop context (apps, taskbars, personal data); generate them with `scripts/capture_screenshots.py`

## Active Development Context

Check `docs/` (start at `docs/README.md`), `CHANGELOG.md`, `ROADMAP.md` and open GitHub issues for current priorities. The project is in active development — read existing code before proposing changes to understand current patterns.
