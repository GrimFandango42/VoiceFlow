# Data Model: VoiceFlow Stability & Long-Running Operation

## Core Entities

### AudioSession
Represents a complete usage period with multiple transcription requests, maintains state and performance metrics.

**Fields:**
- `session_id: UUID` - Unique identifier for the session
- `start_time: datetime` - When session began
- `last_activity: datetime` - Last user interaction timestamp
- `transcription_count: int` - Number of transcriptions in this session
- `total_audio_duration: float` - Cumulative audio processed (seconds)
- `memory_usage_peak: float` - Peak memory usage during session (MB)
- `state: SessionState` - Current session state (idle/active/degraded/recovery)
- `health_score: float` - 0.0-1.0 indicating session health
- `error_count: int` - Number of recoverable errors encountered

**State Transitions:**
```
idle → active (on hotkey press)
active → idle (after transcription completion + timeout)
active → degraded (on performance degradation detection)
degraded → recovery (automatic recovery attempt)
recovery → active (successful recovery)
recovery → idle (recovery timeout, clean restart)
```

### TranscriptionRequest
Individual audio processing operation with timing, quality, and error tracking.

**Fields:**
- `request_id: UUID` - Unique identifier for the request
- `session_id: UUID` - Parent session reference
- `audio_duration: float` - Length of audio input (seconds)
- `processing_time: float | None` - Time to complete transcription (seconds)
- `text_output: str` - Transcribed text result
- `quality_score: float` - 0.0-1.0 quality assessment
- `state: RequestState` - Current request state (queued/processing/completed/failed)

### SystemState
Current operational status with validation and transition logging.

**Fields:**
- `current_state: OperationalState` - Current system state
- `hotkey_active: bool` - Whether hotkey is currently pressed
- `model_loaded: bool` - Whether ASR model is in memory
- `pending_requests: int` - Number of queued transcription requests

### ErrorRecoveryContext
Information needed to restore system to functional state after failures.

**Fields:**
- `error_id: UUID` - Unique identifier for the error instance
- `error_type: ErrorType` - Classification of the error
- `recovery_attempts: int` - Number of recovery attempts made
- `recovery_successful: bool` - Whether recovery succeeded

### PerformanceMetrics
Real-time monitoring data for session health and degradation detection.

**Fields:**
- `memory_usage_mb: float` - Current memory usage in MB
- `cpu_usage_percent: float` - Current CPU usage percentage
- `transcription_latency_ms: float` - Time from audio end to text output
- `model_reload_count: int` - Number of model reloads in current session
- `error_rate: float` - Errors per hour in current session

## Storage Strategy

### In-Memory Storage
- Current `SystemState` - single instance, frequently updated
- Active `AudioSession` - current session only
- Recent `PerformanceMetrics` - rolling window of last 100 entries

### Cleanup Strategy
- Completed requests archived after 1 hour
- Performance metrics aggregated and pruned daily
- Session history rotated after 10 sessions

This data model provides the foundation for robust session management and long-term stability monitoring.