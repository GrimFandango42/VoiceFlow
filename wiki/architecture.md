# VoiceFlow Architecture

## Two-Process Design

### Process 1 — Model Server
- Hosts Whisper distil-large-v3.5 model in GPU memory
- Accepts audio chunks via IPC
- Returns transcription results with timestamps
- Stays resident to avoid model reload latency

### Process 2 — App Logic
- Manages UI, hotkey listener, audio capture
- Sends audio to model server for transcription
- Handles learning system and vocabulary
- Hot-reloadable via `dev.py` (no need to restart model server)

## Runtime Environment
- **Python venv**: `.venv-gpu` (CUDA-enabled)
- **Entry point**: `python dev.py` (development with hot-reload)
- **GPU**: CUDA acceleration for Whisper inference
- **NOT a frozen exe** — runs from source for development flexibility

## Audio Pipeline
```
Microphone → Audio Capture → Silero VAD (filter silence)
    → Audio Preprocessing → Whisper distil-large-v3.5
    → Transcription → Learning Weights → Final Text Output
```

## Key Components
- **Silero VAD**: Filters silence/noise before sending to Whisper. Enabled by default.
- **Whisper distil-large-v3.5**: Distilled model balancing speed and accuracy
- **Learning system**: Adjusts recognition based on user corrections. 14-day data retention.
- **Vocabulary customization**: User-defined terms for domain-specific recognition

## Hotkey
- **Ctrl+Shift**: Push-to-talk (hold to record, release to transcribe)
