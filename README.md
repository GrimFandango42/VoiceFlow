# VoiceFlow

Local, private, push-to-talk transcription for Windows.

[![Latest Release](https://img.shields.io/github/v/release/GrimFandango42/VoiceFlow?display_name=tag&style=for-the-badge)](https://github.com/GrimFandango42/VoiceFlow/releases/latest)
[![Windows EXE](https://img.shields.io/badge/Windows-Download%20EXE-0078D4?style=for-the-badge&logo=windows)](https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-win64.exe)
[![Windows Portable ZIP](https://img.shields.io/badge/Windows-Portable%20ZIP-005A9C?style=for-the-badge&logo=windows)](https://github.com/GrimFandango42/VoiceFlow/releases/latest/download/VoiceFlow-portable-win64.zip)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

Hold `Ctrl+Shift`, speak, release — your words appear in whatever app is focused. No cloud, no subscription, no data leaving your machine. VoiceFlow runs [faster-whisper](https://github.com/SYSTRAN/faster-whisper) locally and injects transcribed text directly into Windows applications.

---

## Features

- **Push-to-talk hotkey** — Hold `Ctrl+Shift` to record, release to transcribe and inject. Configurable from the tray menu.
- **Local Whisper inference** — faster-whisper runs entirely on your machine. CPU and GPU (CUDA) paths are both supported; the setup wizard picks the right profile for your hardware automatically.
- **Direct text injection** — Transcribed text is pasted or typed into the active window with no clipboard interference.
- **Streaming live preview** — See a live word-by-word preview in the overlay while you speak, before the final transcription is injected.
- **Continual learning system** — Adapts to your vocabulary and correction patterns over time. All learning is local; raw audio is never stored by default.
- **History and correction review** — Browse recent transcriptions, approve or correct them, and feed corrections back into the runtime learner from the tray.
- **Tray-first design** — All controls live in the system tray: toggle modes, open history, rerun hardware detection, or reopen the setup wizard without interrupting your workflow.
- **Audio confirmation beeps** — Distinct tones signal recording start and stop for eyes-free operation.
- **Three-pass text cleanup** — Light typo correction and a safe second pass run by default. Heavier cleanup and aggressive context rewriting are opt-in only.
- **Custom vocabulary** — Drop a `custom_vocabulary.txt` file in the config directory to bias transcription toward your domain terms.

---

## Installation

### Windows (primary)

**Option A — Download the pre-built EXE (recommended)**

1. Go to the [latest release](https://github.com/GrimFandango42/VoiceFlow/releases/latest).
2. Download `VoiceFlow-win64.exe` (single file) or `VoiceFlow-portable-win64.zip` (faster startup).
3. Run the EXE. Windows Defender may show a SmartScreen prompt on first run — click "More info" then "Run anyway".
4. The setup wizard opens on first launch. Click **Run Hardware Check**, then choose a profile and click **Save And Launch**.

**Option B — Run from source**

Requirements: Python 3.9+, Git, optionally CUDA 12.x for GPU acceleration.

```powershell
git clone https://github.com/GrimFandango42/VoiceFlow.git
cd VoiceFlow

# Bootstrap (installs venv, dependencies, and configures GPU if available)
powershell -ExecutionPolicy Bypass -File scripts\setup\bootstrap_windows.ps1 -GpuVenv

# Run in dev mode
python voiceflow.py
```

**Option C — Build the packaged EXE locally**

```powershell
# After bootstrap above
powershell -ExecutionPolicy Bypass -File scripts\setup\build_windows_exe.ps1
dist\VoiceFlow\VoiceFlow.exe
```

### Linux / macOS (experimental)

VoiceFlow's core architecture is platform-abstracted at the hotkey, injection, and tray boundaries, but active development and validation happen on Windows only. Community forks targeting other platforms are welcome — see [docs/guides/FORKING_AND_PLATFORM_GUIDE.md](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) for the porting seams.

| Platform | Status |
|---|---|
| Windows 10/11 | Supported |
| macOS | Community fork target |
| Linux | Community fork target |

---

## Usage

### Basic workflow

1. Focus the application you want to type into (any text field works — editors, browsers, chat apps, terminals).
2. Hold `Ctrl+Shift` and speak.
3. Release the hotkey. The transcribed text appears in the focused app within a second or two.

The overlay window shows the current state (idle, recording, processing) and a live streaming preview while you speak.

### Tray menu

Right-click the tray icon to access:

- **Setup and Defaults** — reopen the setup wizard to change your hardware profile or text cleanup settings
- **Recent History** — browse the last N transcriptions
- **Correction Review** — approve or correct transcriptions to improve the learning model
- **Code Mode** — toggle code-style formatting (suppresses sentence casing and punctuation normalization)
- **Toggle Injection Mode** — switch between clipboard paste and keyboard typing injection
- **Toggle Dock** — pin the overlay as a persistent dock instead of a transient popup

### Setup wizard

The setup wizard runs automatically on first launch and is always available from the tray menu. It:

- Detects your GPU and recommends a hardware profile (`Recommended`, `CPU Compatible`, or `GPU Balanced`)
- Exposes the main quality and behavior toggles so you can tune without editing config files
- Must complete the hardware check (Step 1) before the profile selection (Step 2) unlocks

### Configuration files

Config and learned data are stored under `%LOCALAPPDATA%\LocalFlow\`:

| Path | Contents |
|---|---|
| `settings.json` | All runtime settings |
| `adaptive_patterns.json` | Learned replacement patterns |
| `daily_learning_reports\` | Per-day learning summaries |
| `engineering_terms.json` | Optional personal domain vocabulary |
| `custom_vocabulary.txt` | Whisper bias vocabulary (one term per line) |

---

## Architecture

VoiceFlow is a single Python process with five layered subsystems. The primary entry point is `src/voiceflow/ui/cli_enhanced.py`.

### Data flow

```
Hold PTT
  -> hotkey listener enters recording state
  -> audio recorder buffers microphone at 16 kHz
  -> optional streaming preview updates overlay live

Release PTT
  -> recorder finalizes audio buffer
  -> ASR job runs (faster-whisper, CPU or CUDA)
  -> text normalization + formatting + optional cleanup passes
  -> injector writes text to active target window
  -> tray and overlay return to idle
```

### Subsystems

| Layer | Responsibility |
|---|---|
| `ui` | Setup wizard, tray icon, overlay, runtime orchestration |
| `integrations` | Global hotkey listener, text injection (clipboard + keyboard paths) |
| `core` | Audio capture, ASR engine, streaming preview, text processing pipeline |
| `utils` | Config persistence, async logging, idle monitoring, process safety |
| `ai` (optional) | Adaptive learning, confidence-weighted correction, command mode |

### Model server (two-process dev mode)

When `VOICEFLOW_MODEL_SERVER_ENABLED=1` is set, VoiceFlow delegates ASR to a separate model server process. This allows the main app to hot-reload during development without reloading the Whisper model. The `ModelServerASR` client in `core/model_server_client.py` speaks to it transparently.

### Hardware profiles

- `device=auto` selects CUDA when available, otherwise CPU.
- `model_tier=quick` maps to `small.en` on CPU and `distil-large-v3` on CUDA.
- The `latency_boost` option loads a lighter model for initial decode and upgrades in the background.

---

## Contributing

Contributions are welcome. The priorities for this project are release-to-text latency, transcription quality, and reliable hotkey and injection behavior on Windows.

### Dev setup

```powershell
git clone https://github.com/GrimFandango42/VoiceFlow.git
cd VoiceFlow
powershell -ExecutionPolicy Bypass -File scripts\setup\bootstrap_windows.ps1 -GpuVenv
```

### Running tests

```powershell
# Activate the venv
venv\Scripts\activate

# Quick smoke test
python scripts\dev\quick_smoke_test.py

# Full test suite
pytest -q tests\runtime
```

### PR guidelines

- Keep changes focused. Broad refactors should be discussed in an issue first.
- Update relevant docs in the same PR when behavior changes.
- Ensure the runtime tests pass locally before opening a PR.
- Screenshots and demo assets must be cropped or staged. Do not commit images that expose a real desktop, personal workspace, or unrelated applications.
- Call out risks or potential regressions explicitly in the PR description.

PR checklist:

- [ ] Change is scoped and explained
- [ ] Runtime tests pass locally (`pytest -q tests\runtime`)
- [ ] Docs updated if behavior changed
- [ ] Screenshots/assets are sanitized
- [ ] Risks and regressions noted

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for more detail.

---

## Documentation

| Document | Contents |
|---|---|
| [User Guide](docs/USER_GUIDE.md) | Tray settings, personalization, cleanup pass tuning |
| [FAQ](docs/guides/FAQ.md) | Common questions and quick troubleshooting |
| [Build Guide](docs/BUILD_GUIDE.md) | Building and packaging the EXE |
| [Technical Overview](docs/TECHNICAL_OVERVIEW.md) | Runtime pipeline and config reference |
| [Architecture](docs/ARCHITECTURE.md) | Component map and data flow |
| [Security and Privacy](docs/guides/SECURITY_AND_PRIVACY.md) | What is and is not stored locally |
| [Forking and Porting](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) | Platform adapter seams for macOS/Linux forks |

---

## License

MIT. See [LICENSE](LICENSE).
