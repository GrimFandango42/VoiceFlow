# VoiceFlow Architecture (pointer)

The maintained description is [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md): layers, data flow, configuration, environment controls and repository layout.

## Two-process dev setup (the part specific to maintainers)

`python dev.py` runs two processes:

- **Model server** — loads the Whisper model once and serves it on `127.0.0.1:8765`; restarted only when `core/asr_engine.py`, `core/model_server.py` or `core/preloader.py` change.
- **App** — UI, audio capture, hotkeys, learning; restarted on every saved `.py`, so a UI or logic change reloads in about a second without reloading the model.

Run it with the GPU venv: `.venv-gpu\Scripts\python.exe dev.py` (the venv needs a CUDA 12 PyTorch for the CUDA DLLs). The packaged app and `python _app_entry.py` are single-process; the model is loaded in-process.

## Audio pipeline (summary)

```
Microphone -> shared capture stream (pre-roll + recording ring)
  -> (long recordings) pause segmenter + Silero VAD gate
  -> ASR (faster-whisper; hotwords + vocabulary prompt)
  -> cleanup / spoken commands / formatting
  -> history (saved before paste) -> paste into the target window
```
