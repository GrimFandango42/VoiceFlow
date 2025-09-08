# VoiceFlow / LocalFlow (Windows)

Local, push‑to‑talk speech‑to‑text for Windows. This repo includes a minimal “LocalFlow” experience (hold a hotkey, speak, release to paste) and a fuller “VoiceFlow” application with a modular core and optional tray UI.

This project is intended for personal use and experimentation. It is not productized; expect rough edges. If you want to fork and adapt it, the code is structured to make that practical.

License: MIT (see `LICENSE`).

## Status

- Scope: Windows‑first, personal/experimental use.
- Models: Uses faster‑whisper (CTRANSLATE2) locally; first run downloads the selected model.
- Hardware: Works on CPU; performs best with NVIDIA CUDA (fp16).
- Stability: The core LocalFlow path is stable for day‑to‑day personal usage; broader Windows integration (tray + advanced flows) is still evolving.

## Core Features

- Push‑to‑talk dictation: hold a hotkey to capture, release to transcribe and paste/type into the focused app.
- Code mode: optional spoken‑symbol mapping (e.g., “open bracket” → `[`), with simple spacing cleanup.
- Injection modes: paste (clipboard + shortcut) or direct typing; clipboard can be restored after paste.
- Tray toggles: optional system tray UI for changing PTT presets and toggles (if `pystray` + `Pillow` are installed).

## What’s Tested (High Level)

- Unit tests (default):
  - Text processing (spoken symbols → characters)
  - Injection sanitization and rate‑limiting
  - Entry points (lite/debug/main) import and call patterns
  - Streaming transcriber worker behavior (dummy model)
- Integration/Windows tests (opt‑in):
  - App orchestration, hotkey registration, clipboard behavior
  - System tray menu wiring and Windows helpers
  - Windows APIs and process management (require Windows context/admin)

By default `pytest -q` runs the fast unit set. Integration and Windows tests are grouped separately and are not run by default.

## Quick Start (LocalFlow)

LocalFlow is the minimal experience focused on personal dictation.

1) Install (Windows)

- Double‑click `LAUNCH_LOCALFLOW.bat` (creates `venv`, installs deps, runs app), or:

```powershell
py -3 -m venv venv
venv\Scripts\python -m pip install --upgrade pip
venv\Scripts\python -m pip install -r requirements-localflow.txt -r requirements-dev.txt
venv\Scripts\python -m localflow.cli
```

2) Use

- Hold `Ctrl+Shift+Space` to speak; release to transcribe and paste.
- Tray (optional): if `pystray`/`Pillow` are installed, a tray icon exposes presets (e.g., switch to `Ctrl+Alt` chord) and toggles.

3) Configure

- Edit `localflow/config.py` or use the tray presets.
- Config is also saved under `%LOCALAPPDATA%\LocalFlow\config.json` when you change toggles.
- Notable options:
  - `model_name`: `small.en` by default; consider `medium.en` for quality.
  - `device` / `compute_type`: `cuda` + `float16` for NVIDIA; fallback to `cpu` works with `int8/float32`.
  - `paste_injection`, `paste_shortcut`, `press_enter_after_paste`
  - `code_mode_default`, `code_mode_lowercase`
  - `type_if_len_le`: prefer typing for short outputs to reduce clipboard exposure

## Quick Start (VoiceFlow app)

- Production: `python voiceflow_main.py` (or run via system tray with `voiceflow_tray.py`)
- Lite: `python voiceflow_lite.py` (CPU‑friendly defaults)
- Debug: `python voiceflow_debug.py` (verbose logging; streaming enabled)

## Build (Optional)

You can package a standalone Windows executable using PyInstaller.

Prerequisites:
- Windows 10/11, Python 3.9+ (3.10–3.12 recommended)
- Visual C++ Build Tools (for some wheels, if needed)

Commands (from repo root):

```powershell
py -3 -m venv venv
venv\Scripts\python -m pip install --upgrade pip
venv\Scripts\python -m pip install -r requirements-localflow.txt
venv\Scripts\python -m pip install pyinstaller

# Example: build VoiceFlow tray app
venv\Scripts\pyinstaller -F -n VoiceFlow-Tray voiceflow_tray.py
```

Or use the provided scripts under `scripts/` (e.g., `scripts/BUILD-Windows-Executable.bat`).

## Privacy / Security

- Transcription runs locally after first model download.
- Clipboard injection is convenient but exposes clipboard briefly; set `type_if_len_le` > 0 to prefer typing for short texts.
- Injection sanitizes control characters and truncates excessively long payloads by default.

## Development Notes

- Structure:
  - `localflow/`: minimal Windows PTT dictation app
  - `voiceflow/`: modular application (core, ui, app)
  - Entry points: `voiceflow_main.py`, `voiceflow_lite.py`, `voiceflow_debug.py`, `voiceflow_tray.py`
  - `tests/`: unit (default) and integration suites
  - `docs/`: technical overview and notes (see `docs/README.md`)

- Tests
  - Default (unit): `pytest -q` (runs `tests/unit`)
  - Integration/Windows: `pytest tests/integration -q` (heavier; may require admin and Windows context)

- Forking tips
  - Start with LocalFlow for a simple PTT pipeline (`localflow/cli.py`, `localflow/asr.py`, `localflow/inject.py`).
  - For deeper changes, see `voiceflow/core/` and `voiceflow/app.py`.
  - Add markers and keep your unit tests fast; keep Windows/UI tests separate.

## Known Limitations

- First run downloads the selected model; `medium.en` can be ~1–2 GB.
- Some Windows integration tests require admin privileges and real devices.
- The tray/UI is optional; focus is on a reliable PTT path.
