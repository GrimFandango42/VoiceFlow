# Launch VoiceFlow (Windows)

## Pick a launch path

| Path | Command | Use it for |
|---|---|---|
| **Packaged bundle** | `dist\VoiceFlow\VoiceFlow.exe` | Day-to-day use and end-to-end testing |
| Release download | `VoiceFlow-win64.exe` (one file) or the portable zip | Installing on another machine |
| **Source, GPU, hot reload** | `.venv-gpu\Scripts\python.exe dev.py` | Active development |
| Source, single process | `python _app_entry.py` | Debugging without the watcher or model server |
| `.bat` launchers | `VoiceFlow.bat`, `VoiceFlow_Quick.bat`, `VoiceFlow_Silent.bat`, `VoiceFlow_Tray.vbs` | Source debugging; they clean stale VoiceFlow processes first and prefer `.venv-gpu` |

Never start the app with `python -m voiceflow.ui.cli_enhanced`: the single-instance guard mistakes the py.exe launcher's child for a duplicate and ends it. `_app_entry.py` exists to avoid that.

Use the packaged executable for acceptance testing; the batch launchers are source/debug tools.

## First-time setup

1. Launch VoiceFlow.
2. In the setup wizard click **Step 1: Run Hardware Check (Required)**.
3. Pick **Recommended**, **CPU Compatible** or **GPU Balanced**.
4. Click **Save and Launch VoiceFlow**.

Reopen it any time from tray → **Setup & Defaults**. For a first-run test, start from a clean `%LOCALAPPDATA%\VoiceFlow\config.json` or set `setup_completed=false` and `show_setup_on_startup=true`.

## From source with a GPU (hot reload)

`dev.py` splits VoiceFlow into two processes so Whisper does not reload on every code change:

- a **model server** that loads the model once and serves it on `127.0.0.1:8765` (override with `--port` / `VOICEFLOW_MODEL_SERVER_PORT`); it restarts only when `asr_engine.py`, `model_server.py` or `preloader.py` change;
- the **app** (UI, audio, hotkeys), which restarts whenever any watched `.py` file is saved.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\bootstrap_windows.ps1 -GpuVenv   # creates .venv-gpu
# then install a CUDA 12 build of PyTorch into .venv-gpu (it supplies the CUDA DLLs, see the README GPU note)
.venv-gpu\Scripts\python.exe dev.py
```

Useful flags: `--no-model-server` (one process, model reloads on each restart), `--debounce SECS`, `--no-restart` (run once, no watching). Set `VOICEFLOW_USE_GPU_VENV=0` to make the `.bat` launchers and the build prefer `venv` over `.venv-gpu`.

**Check that the GPU is really in use.** The log line `asr_engine_initialized ... device=cuda compute=float16` shows the device VoiceFlow settled on; `device=cpu compute=int8` means the CUDA DLLs were not found (`cuda_runtime_unavailable missing_dlls=...` names them). The nightly learning job reports the same state.

## The packaged bundle

Build it with `scripts\setup\build_windows_exe.ps1` ([Build guide](BUILD_GUIDE.md)). The build ships the CUDA runtime DLLs inside the bundle and fails if it cannot, so the EXE runs on the GPU without any Python environment. After a build you can verify it without the microphone, tray or hotkeys:

```powershell
dist\VoiceFlow\VoiceFlow.exe --self-check=$env:TEMP\voiceflow_self_check.json
```

Exit code 0 means every check passed; the JSON lists each one, including the commit the build was made from. Run it with VoiceFlow not otherwise running.

## Basic verification

1. The tray icon appears and the dock shows **Ready** with an **Updated MM-DD HH:MM** date.
2. Hold `Ctrl+Shift` in Notepad and speak: the overlay shows the waveform, caption and timer.
3. Release: the text is pasted without Enter and the overlay shows **Done**.
4. Tray → **Recent** lists the dictation.

## If launch fails

```powershell
python scripts\list_audio_devices.py
python scripts\dev\quick_smoke_test.py
```

Runtime log: `%LOCALAPPDATA%\VoiceFlow\logs\voiceflow.log`. If it is locked, `logs\active_log_path.txt` names the live file, which falls back to `%TEMP%\VoiceFlow\voiceflow-<pid>.log`. A previous instance that did not exit cleanly can block a new start; end the old `VoiceFlow.exe` / `python` process (or run `scripts\setup\stop_voiceflow_processes.ps1`) and launch again.
