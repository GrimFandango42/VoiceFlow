# VoiceFlow Build and Setup Guide

## Scope

VoiceFlow in this repository is a Python runtime (Windows-first), not a Tauri/Electron build pipeline.

This guide covers:
- environment setup
- dependency installation
- launch validation
- optional packaging direction for fork maintainers

## Prerequisites

- Python 3.9+
- Windows 10/11 (primary validated target)
- microphone device available

Optional for better performance:
- NVIDIA GPU + working CUDA runtime

## Environment Setup

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install --upgrade pip
pip install -r scripts\setup\requirements_windows.txt
```

One-step option:

```powershell
.\Bootstrap_Windows.bat
```

Optional installer script:

```powershell
python scripts\setup\setup_voiceflow.py
```

## Verify Build/Runtime Readiness

```powershell
python scripts\dev\quick_smoke_test.py
python scripts\list_audio_devices.py
```

If both pass, launch:

```powershell
.\VoiceFlow_Quick.bat
```

## Editable Install (Optional)

If you prefer package-style imports while developing:

```powershell
pip install -e .
```

## Runtime Artifacts

- Config: `%LOCALAPPDATA%\LocalFlow\config.json`
- Logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

## Test Commands

Fast slice:

```powershell
pytest -q tests\test_textproc.py tests\test_injector_logic.py tests\test_sanitization_and_rate.py
```

Broader run:

```powershell
pytest -q
```

## Packaging Notes For Forks

No single official installer pipeline is maintained in this branch.

If you need distributable artifacts, common fork strategies are:
- PyInstaller (`onefile` or directory mode)
- signed internal launcher + managed Python runtime
- OS-specific packaging in a downstream repo

Before packaging, validate:
- global hotkey reliability
- injection behavior on your target apps
- long-dictation latency and memory profile
