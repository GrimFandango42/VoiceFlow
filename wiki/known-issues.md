# VoiceFlow Known Issues

## Active Issues

### Singleton mutex blocks fresh launches
- **Severity**: Medium
- **Description**: If a previous VoiceFlow process didn't shut down cleanly, the mutex prevents new instances from starting
- **Workaround**: Kill the old process manually before launching (`taskkill` or Task Manager)
- **Fix needed**: Add stale mutex detection or auto-cleanup on startup

### Learning system needs manual corrections to accumulate data
- **Severity**: Low
- **Description**: The learning/personalization system only improves when the user manually corrects transcription errors. Without corrections, no training data accumulates.
- **Impact**: New users don't see accuracy improvements until they invest time in corrections
- **Potential fix**: Add an easy inline correction UI, or bootstrap from common correction patterns

## Resolved Issues
- Audio device enumeration on startup (fixed)
- Streaming buffer overflow on long utterances (fixed)
- Hotkey registration conflict with other apps (fixed)
- Model server crash on malformed audio packets (fixed)
