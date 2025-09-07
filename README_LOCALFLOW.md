LocalFlow MVP (Windows, NVIDIA GPU)

Overview
- Push-to-talk dictation that pastes transcription into the focused app.
- Fully local, uses faster-whisper with CUDA fp16 on an RTX 4080-class GPU.
- Code mode: converts spoken symbols (e.g., “open bracket”) into code characters.
- Toggle hotkeys: Ctrl+Alt+C (code mode), Ctrl+Alt+P (paste vs type injection).
- Optional: Ctrl+Alt+Enter toggles sending Enter after paste.
- Tray: lightweight system tray with mode toggles (if `pystray` + `Pillow` are installed).
 - Tray shows a brief notification on launch (3–5 seconds, OS-dependent) and includes a one-click action to set Ctrl+Alt as the default PTT.

Run
- Double-click `LAUNCH_LOCALFLOW.bat` (creates `venv`, installs deps, runs app).
- Hold `Ctrl+Shift+Space` to speak, release to transcribe and paste.
- Change the PTT hotkey from the tray (e.g., Ctrl+Alt+Space, Ctrl+Alt, Ctrl+Space, Alt+Space). Default is Ctrl+Shift+Space to avoid conflicts.
 - One-click: tray → “Set Ctrl+Alt as default PTT” to switch and persist when you’re ready.
 - Preferences (hotkey, injection mode, send Enter) are saved to `%LOCALAPPDATA%\LocalFlow\config.json` and loaded on startup.

Config
- Edit `localflow/config.py`:
  - `model_name`: defaults to `small.en` for faster first run; switch to `medium.en` for higher accuracy. `distil-large-v3` optional.
  - `device`: `cuda` (GPU) or `cpu`.
  - `hotkey_*`: change to Ctrl+Alt by setting `hotkey_shift=False`, `hotkey_ctrl=True`, `hotkey_alt=True`.
  - You can also choose presets from the tray under “PTT Hotkey” (easiest).
  - `paste_injection`: True pastes via clipboard; False types keystrokes directly.
  - `paste_shortcut`: change from `ctrl+v` to `shift+insert` if needed.
  - `code_mode_default`: enable/disable code keywords to symbols.
  - `code_mode_lowercase`: force lowercase before mapping for consistency.
  - `press_enter_after_paste`: if True, sends Enter after paste/type.
  - `max_inject_chars`: truncate very long outputs for safety.
  - `min_inject_interval_ms`: simple rate-limit for repeated injection events.
  - `type_if_len_le`: if > 0, use typing (not clipboard) for short texts.
  - `use_tray`: enable/disable tray icon.

Preload models
- `py -3 scripts\preload_models.py small.en medium.en distil-large-v3`

Environment check
- `py -3 scripts\bench_env.py`
 - List audio devices: `py -3 scripts\list_audio_devices.py`

Notes
- For best reliability, run as Administrator so global hotkeys and pasting work in elevated apps.
- Clipboard content is restored after paste (best effort). Disable via `restore_clipboard=False`.
- Toggle code mode with Ctrl+Alt+C. Toggle paste vs type injection with Ctrl+Alt+P.
- Privacy: to avoid clipboard exposure for short texts, set `type_if_len_le` > 0 to prefer typing.
 - First run downloads the selected model to your local cache. `small.en` is ~hundreds of MB; `medium.en` can be ~1–2 GB.
 - If you prefer not to involve Space (e.g., Notepad inserts a space), pick “Ctrl+Alt (no key)” from the tray PTT menu.

Technical overview
- See `docs/TECHNICAL_OVERVIEW.md` for component details, security considerations, and extension points.

Developer Notes (beginner-friendly)
- Architecture:
  - Audio: `sounddevice` streams 16 kHz mono into memory on PTT.
  - ASR: `faster-whisper` (CUDA fp16) transcribes buffer on release.
  - Text processing: optional “code mode” maps spoken symbols to characters.
  - Injection: paste (clipboard + Ctrl+V) or direct typing; clipboard restored.
  - Tray: optional system tray for toggles (pystray + Pillow).
- Where to change things:
  - Hotkeys and behavior: `localflow/config.py`
  - Dictation flow: `localflow/cli.py`
  - Symbol mapping: `localflow/textproc.py`
  - Injection internals: `localflow/inject.py`
  - Tray: `localflow/tray.py`
- Testing:
  - Unit tests: `pytest -q` (see `tests/`)
  - Run curated tests: `python run_tests.py --type unit`
  - Mapping demo (no audio): `py -3 scripts\check_mappings.py`
  - Audio devices: `py -3 scripts\list_audio_devices.py`

Security & Privacy
- Everything runs locally after the first model download.
- Clipboard injection is convenient but exposes a brief window where other apps could read clipboard; use typing for sensitive or short texts (`type_if_len_le`).
- Injection sanitizes control characters and truncates huge payloads by default.
