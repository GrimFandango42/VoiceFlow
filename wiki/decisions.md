# VoiceFlow Design Decisions

## Run from source, not frozen exe
- **Decision**: Use `dev.py` with hot-reload instead of building a frozen executable
- **Rationale**: Faster iteration during active development. Hot-reload lets you change app logic without restarting the model server (which takes time to load the model into GPU).
- **Trade-off**: Requires Python environment setup; not distributable as a standalone app yet.

## VAD enabled by default
- **Decision**: Silero VAD is on by default, filtering silence before Whisper
- **Rationale**: Without VAD, Whisper processes silence and background noise, wasting GPU cycles and sometimes hallucinating text. VAD dramatically reduces false transcriptions.
- **Trade-off**: Very quiet speech might get filtered. User can disable if needed.

## 14-day retention for learning data
- **Decision**: Learning corrections are retained for 14 days, then purged
- **Rationale**: Balances personalization with privacy/storage. Recent corrections are most relevant to current usage patterns. Prevents unbounded data growth.
- **Trade-off**: Long-term vocabulary improvements may be lost if user doesn't correct regularly.

## Two-process architecture
- **Decision**: Separate model server from app logic
- **Rationale**: Model loading is expensive (several seconds). Keeping the model resident means hot-reload only restarts the lightweight app process. Also isolates crashes — a UI bug doesn't kill the model server.
- **Trade-off**: More complex process management, singleton mutex issues.

## Whisper distil-large-v3.5
- **Decision**: Use distilled model over full large-v3
- **Rationale**: ~2x faster inference with minimal accuracy loss. Good enough for real-time transcription. Full model is overkill for push-to-talk use case.
