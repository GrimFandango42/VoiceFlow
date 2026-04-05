# Animation + UI Spacing + Docs Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace broken bar animation with a modern ripple-ring orb effect, compress overlay-to-dock gap further, and rewrite README/CHANGELOG for open-source release.

**Architecture:** All visual changes live in `src/voiceflow/ui/visual_indicators.py`. The animation uses tkinter canvas ovals (ripple rings) expanding from a center orb, fading to the transparent key color. README/CHANGELOG are repo-root markdown files.

**Tech Stack:** Python 3.9+, tkinter Canvas, faster-whisper, pyproject.toml v3.1.8 → bump to 3.2.0

---

### Task 1: Compress UI spacing further

**Files:**
- Modify: `src/voiceflow/ui/visual_indicators.py`

**What to change:**

1. `_position_overlay` — dock gap: change `y = int(dock_y - self.height - 5)` → `y = int(dock_y - self.height - 2)`
2. `_position_overlay` — reserved_bottom: change `152` → `140`, change `110` → `100`
3. `_create_ui` — status_row pady: change `pady=(0, 2)` → `pady=(0, 1)`
4. `_create_ui` — preview_card pady: change `pady=(0, 1)` → `pady=(0, 0)`
5. `_update_visual_settings` — height bounds: change `min(156, max(116, req_h - 24))` → `min(148, max(110, req_h - 28))`

---

### Task 2: Replace animation with ripple-ring orb

**Files:**
- Modify: `src/voiceflow/ui/visual_indicators.py`

**Design:**
- Canvas: 58px tall, full width (~440px). Center at `(cx, cy) = (wave_w//2, 29)`.
- Elements: center glow oval, center orb oval, 4 ripple ring ovals (outlines)
- Ring phases staggered [0.0, 0.25, 0.5, 0.75] — cycle 0→1, reset each cycle
- Rings expand outward, fade to `transparent_key` color as they grow
- Phase rate: `0.004 + 0.032 * voiced_drive` (slow idle, fast speech)
- Ring size: `rx = (cx - 8) * ease`, `ry = (cy - 3) * ease` where `ease = phase ** 0.6`
- Ring color: `_mix_color(accent_bright, transparent_key, phase)` — fades to invisible
- Ring width: `int(2.5 * (1.0 - phase) * (1 + voiced_drive))` min 1
- Center orb radius: `3 + 7 * voiced_drive`, glow radius: `orb_r + 5 + 8 * voiced_drive`
- Color shifts: idle = muted accent, speaking = bright accent + white mix

**New instance attrs (add to `__init__`, initialize to [] / None):**
- `self.ripple_rings` — list of 4 canvas oval IDs
- `self.ripple_phases` — list of 4 floats
- `self.ripple_orb` — canvas oval ID
- `self.ripple_orb_glow` — canvas oval ID

**`_init_waveform_strip` replacement:** Clear all, create the 6 objects above.

**`_animate_waveform` replacement:** Drive rings + orb, keep signal processing section unchanged.

---

### Task 3: Rewrite README.md

**Files:**
- Modify: `README.md` (repo root)

**Structure:**
```
# VoiceFlow
[tagline + badges]

## What is VoiceFlow?
[2-paragraph description]

## Quick Start (Windows)
[numbered install steps]

## Features
[clean bullet list]

## Architecture Overview
[brief technical summary — layers, components]

## Platform Support
[table: Windows supported, macOS/Linux community]

## Configuration
[short: setup wizard, tray, key settings]

## Continual Learning
[brief: how it adapts]

## Contributing
[fork, branch, test, PR]

## License
[MIT]
```

Remove: internal dev workflow bullets, raw file paths like `%LOCALAPPDATA%`, "Stable Baseline" internal note, "Configuration UX" bullet dump.
Add: clean installation section, architecture overview, contributing section.

---

### Task 4: Create CHANGELOG.md

**Files:**
- Create: `CHANGELOG.md` (repo root)

**Content:** Keepachangelog format. Document v3.2.0 as the current release with all changes made in this development cycle: UI overhaul, animation system, streaming improvements, learning system, audio preprocessing.

---

### Task 5: Bump version to 3.2.0

**Files:**
- Modify: `pyproject.toml` — `version = "3.1.8"` → `version = "3.2.0"`
- Modify: `src/voiceflow/__init__.py` if version string exists there

---

### Task 6: Verify + Test

1. Kill all VoiceFlow processes
2. Launch from worktree source: `cd src && python -m voiceflow.ui.cli_enhanced`
3. Screenshot overlay during Ctrl+Shift
4. Run tests: `pytest tests/ -x -q`

---

### Task 7: Commit + push to main

```bash
git add -A
git commit -m "feat: ripple-ring animation, compressed UI, open-source docs v3.2.0"
git push origin HEAD:main
```
