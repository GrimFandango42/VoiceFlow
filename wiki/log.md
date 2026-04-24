# VoiceFlow — Development Log

## Project Overview
Voice-to-text application. Two-process architecture: model server + app logic. Runs from source via dev.py with hot-reload (NOT frozen exe). .venv-gpu is the correct venv (CUDA enabled). Ctrl+Shift is push-to-talk hotkey.

## 2026-04-06 — Standup Seed
- **Rename complete**: LocalFlow → VoiceFlow across entire codebase and docs
- **Visual overhaul**: Spring physics bars, spark particles, mirrored bars, hue drift, glow effects
- **Audio overlay**: Fixed-height overlay, per-bar excitability, traveling wave animation
- **Stability**: Cap command queue, drop stale audio frames to prevent long-session crash
- **CUDA fix**: Removed broken _maybe_download_with_progress call that killed CUDA
- **Open-source prep**: CI badge, winget manifest template, installer hash script
- **Setup wizard**: CUDA guidance and model download progress added

## 2026-04-19 — Post-Restart Health Check
- **Process**: Running — PID 8372, 421 MB via `.venv-gpu`, launcher_silent.pyw
- **Model server**: Active (pythonw process confirmed)
- **Status**: Healthy, no action needed.
