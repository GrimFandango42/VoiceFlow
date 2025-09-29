# Data Model: NoneType Context Manager Error Fix

## Core Entities

### ModelState
**Purpose**: Represents the current state and health of the speech recognition model
**Fields**:
- `model_instance`: The actual Whisper model object (can be None during transitions)
- `is_healthy`: Boolean indicating if model is functional
- `load_time`: Timestamp of last successful model load
- `transcription_count`: Number of transcriptions performed with current model
- `last_error`: Last error encountered (if any)
- `reload_in_progress`: Boolean flag for atomic reload operations

**State Transitions**:
```
UNLOADED → LOADING → LOADED → [RELOADING] → LOADED
                  ↓             ↓
                ERROR ←←←←←←←←←← ERROR
```

**Validation Rules**:
- `model_instance` can be None only during LOADING or ERROR states
- `is_healthy` must be False when `model_instance` is None
- `transcription_count` resets to 0 after successful reload
- `reload_in_progress` prevents concurrent reload operations

### TranscriptionSession
**Purpose**: Represents a single transcription request with safety guarantees
**Fields**:
- `session_id`: Unique identifier for tracking
- `audio_data`: Input audio data (numpy array)
- `start_time`: When transcription request started
- `model_state_snapshot`: ModelState at time of request
- `safety_context`: Safe context manager (never None)
- `result`: Transcription result (empty string on failure)
- `error_info`: Error details if transcription failed

**Validation Rules**:
- `safety_context` must always provide valid context manager
- `result` must be string (empty on failure, never None)
- `error_info` populated only when transcription fails
- Session must complete within 30 seconds (timeout)

### ErrorRecoveryContext
**Purpose**: Manages automatic recovery from model failures
**Fields**:
- `error_type`: Classification of error (ModelNoneType, LoadFailure, etc.)
- `recovery_strategy`: Strategy to apply (PreserveReplace, NullObject, etc.)
- `attempt_count`: Number of recovery attempts made
- `recovery_start_time`: When recovery process began
- `success`: Boolean indicating if recovery succeeded
- `fallback_active`: Whether null object fallback is in use

**State Management**:
- Recovery attempts limited to 3 per error
- Fallback mode activated after failed recovery
- Recovery statistics tracked for health monitoring

## Relationships

```
ModelState ←→ TranscriptionSession (many sessions per model state)
TranscriptionSession → ErrorRecoveryContext (created on failure)
ErrorRecoveryContext → ModelState (modifies state during recovery)
```

## Safety Contracts

### Model Access Contract
```python
@contract
def get_safe_model_context() -> ContextManager:
    """
    Guarantees:
    - Returns valid context manager (never None)
    - Context manager supports transcribe() method
    - Falls back to null context if model unavailable
    """
```

### Transcription Contract
```python
@contract
def transcribe_safely(audio: np.ndarray) -> str:
    """
    Preconditions:
    - audio is valid numpy array
    - audio contains no NaN/Inf values

    Guarantees:
    - Returns string result (empty on failure)
    - Never raises NoneType context manager error
    - Model state preserved on failure
    - Recovery attempted automatically
    """
```

### Reload Contract
```python
@contract
def reload_model_atomically() -> bool:
    """
    Guarantees:
    - Current model preserved until new model validated
    - Atomic swap operation (no intermediate None state)
    - Thread-safe operation with proper locking
    - Returns success status
    """
```

## Implementation Notes

**Thread Safety**: All operations protected by `threading.RLock`
**Memory Management**: Old models cleaned up after successful swap
**Performance**: Atomic operations maintain <200ms response time requirement
**Constitutional Compliance**: Preserves offline operation and Windows optimization