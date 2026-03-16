# VoiceFlow User Guide

## Core Workflow

1. Focus the target app.
2. Hold push-to-talk (`Ctrl+Shift` by default).
3. Speak.
4. Release to transcribe and insert text.
5. By default, VoiceFlow pastes text without auto-sending Enter.

## UI Surfaces

VoiceFlow is intentionally tray-first:

- Setup wizard: first-run defaults and advanced overrides.
- Tray menu: primary settings and actions.
- Overlay + dock: status and recent transcript visibility.
- Recent History + Correction Review: fast correction loop.
- VoiceFlow keeps day-to-day control close to the transcription loop instead of scattering it across separate admin surfaces.

## Tray Settings Map

Use this as a visual click-path map:

| Goal | Click Path | Persists In Config |
|---|---|---|
| Open setup wizard | Tray -> `Setup & Defaults` | `setup_*` fields + selected defaults |
| Toggle code mode | Tray -> `Code Mode` | Session toggle (runtime state) |
| Choose paste vs type injection | Tray -> `Injection` | `paste_injection` |
| Auto-press Enter after paste (default OFF) | Tray -> `Auto-Enter` | `press_enter_after_paste` |
| Show/hide visual indicators | Tray -> `Visual Indicators` | `visual_indicators_enabled` |
| Show/hide dock | Tray -> `Dock` | `visual_dock_enabled` |
| Change push-to-talk preset | Tray -> `PTT Hotkey` -> pick preset | `hotkey_*` fields |
| Open transcript history | Tray -> `Recent History` | n/a |
| Open correction workflow | Tray -> `Correction Review` | n/a |

Also available via hotkeys:

- `Ctrl+Alt+C`: toggle code mode
- `Ctrl+Alt+P`: toggle paste/type injection
- `Ctrl+Alt+Enter`: toggle auto-enter

## Setup Wizard

At startup, VoiceFlow can show a setup wizard before the main runtime starts.

- First startup flow highlights Step 1 as the required action:
  - `Step 1: Run Hardware Check (Required)`
  - Step 2 controls are intentionally locked/dimmed until the check completes.
- Recommended mode: chooses defaults based on hardware detection.
- CPU-compatible mode: safest fallback for broad compatibility.
- GPU-balanced mode: optimized for CUDA-capable systems.
- `Run Hardware Check`: re-detect hardware and reset profile preview to recommended defaults.
- Choose one profile after check (`Recommended`, `CPU Compatible`, or `GPU Balanced`) before `Save And Launch`.
- Selected profile shows a green `✓ Selected` indicator in Step 2 for quick visual confirmation.
- Advanced section: device/compute/model/injection overrides.

You can reopen the same wizard from tray:

- Right-click tray icon -> `Setup & Defaults`

For a clean first-run regression pass, use a clean config or reset the setup markers before launch:

- `setup_completed=false`
- `show_setup_on_startup=true`

If setup is incomplete, startup stays gated until setup is saved (or setup is explicitly skipped via env flag).

## Transcription Quality and Formatting

Speed-first defaults now separate lightweight cleanup from aggressive rewrites:

- `enable_light_typo_correction=true`
  - Low-latency typo/spelling cleanup (safe regex pass).
  - Runs before destination formatting and injection.
- `enable_safe_second_pass_cleanup=true`
  - Deterministic second-pass cleanup after primary formatting.
  - Designed for low overhead and predictable output.
- `enable_heavy_second_pass_cleanup=false`
  - Stronger optional cleanup stage, disabled by default.
  - Runs only when explicitly enabled and transcript length meets `heavy_second_pass_min_chars` (default `180`).
- `enable_aggressive_context_corrections=false`
  - Disables risky phrase rewrites unless explicitly enabled.
  - Useful if you observed over-correction in normal dictation.
- `destination_aware_formatting=true`
  - Keeps line wrapping/paragraph shaping suited to target app.
  - Terminal and PowerShell targets stay mostly prose-first, with stronger breaks reserved for clear section changes and spoken lists.

If quality drops mid-session:

1. Keep speaking for 1-2 clips to allow ASR warm path to settle.
2. Confirm `model_tier` and `device` in logs.
3. Keep aggressive rewrites off unless you need domain-specific substitutions.
4. Use `Correction Review` for recurring misses.

Performance/quality telemetry in logs now includes:

- `safe2_ms`, `heavy2_ms`
- `second_pass` mode (`none`, `safe`, `heavy`, `safe+heavy`)
- `delta_chars` after second-pass cleanup

## Animation Quality Controls

Visual indicator animation is now configurable with performance-aware defaults:

- `visual_animation_quality=auto`
  - Adaptive quality mode. The overlay reduces effect complexity under load.
- `visual_target_fps=28`
  - Preferred frame target for adaptive mode (guarded to `12..60`).
- `visual_reduced_motion=false`
  - When enabled, disables high-cost motion effects and lowers animation intensity.

You can tune these fields in config if your system needs smoother visuals or lower motion.

## Documentation Screenshot Hygiene

Public docs should stay focused on VoiceFlow itself, not whatever happened to be open on the author's desktop.

Use this standard when adding screenshots:

1. Crop tightly to the VoiceFlow surface or use a neutral sample background.
2. Do not expose real project tabs, taskbar items, account names, usernames, or other workspace context.
3. If surrounding UI must stay visible for clarity, blur or fully redact non-VoiceFlow content.
4. Prefer sample apps such as a blank terminal or Notepad over a real working desktop.

The current open-source docs intentionally avoid embedding live setup screenshots until sanitized replacements are available.

## Accent and Personalization

VoiceFlow keeps personalization enabled:

- Recent transcript history
- Correction review workflow
- Daily learning from correction data
- Local engineering terms dictionary support
- Built-in normalization for recurring coding-tool names such as `Claude Code` and `Claude Desktop`
- Local adaptive replacement patterns for recurring accent and work-domain misses

Fastest way to improve accent-specific output:

1. Open `Correction Review` from tray.
2. Correct recurring misses.
3. Let daily learning process those corrections.
4. Check the latest report in `%LOCALAPPDATA%\LocalFlow\daily_learning_reports\` for the active rules/tokens VoiceFlow is promoting.
5. If you have stable house-style vocabulary, add it to `%LOCALAPPDATA%\LocalFlow\engineering_terms.json` (example seed files live in `docs/examples/`).

Learning trust model:

- Explicit correction feedback is higher-trust than auto-analysis and promotes faster.
- Saved correction-review feedback also feeds the live runtime learner, so the next dictation in the same session can benefit sooner.
- Routine runtime observations still learn, but they need more repetition before they auto-apply.
- Raw transcript snippet storage is off by default; enable it only if you want local debugging breadcrumbs.
- Daily reports now include both top replacement rules and common recent domain tokens so you can see whether the system is adapting to your work vocabulary.

Long-idle reliability defaults:

- After extended idle gaps, VoiceFlow now applies a safer first-pass pause-compaction profile.
- For longer first dictations after extended idle, VoiceFlow can bypass pause compaction entirely to preserve full context.
- If output looks sparse after heavy compaction, VoiceFlow can run a bounded raw-audio retry.
- For longer clips beyond the single-pass retry window, VoiceFlow uses chunked raw retry with overlap to recover clipped words.

Daily learning commands:

```powershell
.\VoiceFlow_DailyLearning.bat
.\VoiceFlow_DailyLearning.bat --dry-run
```

Schedule daily learning:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup\register_daily_learning_task.ps1 -StartTime "08:00" -Force
```

## Model and Hardware Defaults

Out-of-box defaults:

- `device=auto`
- `model_tier=quick`

Runtime behavior:

- CUDA available: GPU path with `float16`
- No CUDA: CPU path with `int8`

Optional tier overrides:

- `tiny`: lowest latency
- `quick`: default adaptive tier
- `balanced`: higher quality with good speed (best on GPU)
- `quality`: best recognition, slower

## Advanced Config and Logs

- Config: `%LOCALAPPDATA%\LocalFlow\config.json`
- Logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`

Local runtime stores are bounded for long-session stability:

- `ui_actions.jsonl`: bounded write + stale-event filtering.
- `recent_history_events.jsonl`: bounded append with rotation.
- `transcription_corrections.jsonl`: bounded append with rotation.

Injection reliability defaults:

- `inject_require_target_focus=true`
- `inject_refocus_on_miss=true`
- `inject_refocus_attempts=3`
- If final injection misses due focus drift, transcript is copied to clipboard for manual paste.

For troubleshooting and quick issue triage, use [`docs/guides/FAQ.md`](guides/FAQ.md).
