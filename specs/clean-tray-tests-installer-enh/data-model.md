# Data Model: Clean Tray Tests & Installer Enhancements

## Core Entities

### 1. TrayState
**Purpose**: Represents current system tray status and configuration

**Fields**:
- `status: Enum[IDLE, RECORDING, PROCESSING, ERROR]` - Current operational state
- `icon_path: str` - Path to current tray icon
- `menu_items: List[TrayMenuItem]` - Current menu structure
- `tooltip_text: str` - Current tooltip display text
- `last_updated: datetime` - Timestamp of last state change
- `notification_queue: List[Notification]` - Pending user notifications

**Validation Rules**:
- status must be valid enum value
- icon_path must exist and be readable
- tooltip_text must be <= 64 characters (Windows limitation)
- menu_items must have at least one item (Settings)

**State Transitions**:
- IDLE → RECORDING: User presses hotkey
- RECORDING → PROCESSING: User releases hotkey
- PROCESSING → IDLE: Transcription complete
- Any → ERROR: System error occurs
- ERROR → IDLE: Error resolved or user acknowledgment

### 2. TestConfiguration
**Purpose**: Defines test execution parameters and environment

**Fields**:
- `test_category: Enum[UNIT, INTEGRATION, STABILITY, CONTRACT]` - Test type
- `environment: str` - Test environment identifier
- `timeout_seconds: int` - Maximum test execution time
- `required_resources: List[str]` - Required system resources (audio, display, etc.)
- `parallel_safe: bool` - Can run concurrently with other tests
- `cleanup_required: bool` - Requires cleanup after execution
- `dependencies: List[str]` - Test dependencies that must pass first

**Validation Rules**:
- timeout_seconds must be > 0 and <= 3600
- required_resources must be valid system resource identifiers
- dependencies must reference existing test identifiers

### 3. InstallerConfiguration
**Purpose**: Manages installation process configuration and validation

**Fields**:
- `target_platform: str` - Windows version (10, 11)
- `python_version: str` - Required Python version
- `install_path: Path` - Target installation directory
- `required_dependencies: List[Dependency]` - System requirements
- `optional_features: List[Feature]` - Optional installation components
- `validation_checks: List[ValidationCheck]` - Pre-installation validation
- `rollback_enabled: bool` - Support for installation rollback

**Validation Rules**:
- install_path must be writable
- python_version must match supported versions (3.9-3.12)
- required_dependencies must all pass validation
- target_platform must be supported Windows version

### 4. SystemPerformance
**Purpose**: Tracks system performance metrics for constitutional compliance

**Fields**:
- `response_time_ms: float` - UI response time in milliseconds
- `memory_usage_mb: float` - Current memory usage
- `cpu_usage_percent: float` - Current CPU utilization
- `audio_latency_ms: float` - Audio processing latency
- `timestamp: datetime` - Measurement timestamp
- `component: str` - Component being measured (tray, control_center, etc.)

**Validation Rules**:
- response_time_ms must be >= 0
- memory_usage_mb must be >= 0
- cpu_usage_percent must be 0-100
- audio_latency_ms must be >= 0
- component must be valid system component

**Performance Thresholds** (Constitutional Requirements):
- response_time_ms: MUST be <= 200
- memory_usage_mb: MUST be <= 200 (idle), <= 500 (processing)
- audio_latency_ms: SHOULD be minimized for real-time processing

### 5. ControlCenterState
**Purpose**: Manages Control Center interface state and user interactions

**Fields**:
- `active_tab: str` - Currently displayed tab/section
- `log_filter: str` - Current log filtering criteria
- `monitoring_enabled: bool` - Real-time monitoring status
- `window_geometry: Dict[str, int]` - Window size and position
- `auto_refresh_interval: int` - Automatic refresh interval in seconds
- `visible: bool` - Window visibility state

**Validation Rules**:
- active_tab must be valid tab identifier
- window_geometry must contain valid x, y, width, height
- auto_refresh_interval must be 0 (disabled) or >= 1 second

## Entity Relationships

### TrayState ↔ SystemPerformance
- TrayState updates drive SystemPerformance measurements
- Performance violations trigger TrayState error conditions
- One-to-many: TrayState has multiple performance measurements over time

### TestConfiguration → SystemPerformance
- Test execution generates performance measurements
- Test results validate constitutional performance requirements
- Many-to-many: Tests measure multiple performance aspects

### InstallerConfiguration → SystemPerformance
- Installation validation includes performance verification
- System performance baselines established during installation
- One-to-one: Each installation has associated performance baseline

### ControlCenterState ↔ TrayState
- Control Center displays and can modify TrayState
- TrayState changes trigger Control Center updates
- Bidirectional: Both can initiate state changes

## Data Storage Strategy

### Configuration Files
- JSON format for human readability and editing
- Located in user's application data directory
- Atomic updates to prevent corruption during writes
- Versioned schema for upgrade compatibility

### Runtime State
- In-memory objects with periodic persistence
- Thread-safe access for concurrent UI updates
- Event-driven updates to minimize overhead
- Graceful degradation when persistence fails

### Test Data
- SQLite database for test results and metrics
- Indexed by timestamp, test category, and environment
- Retention policy: Keep 30 days of detailed results, 1 year of summaries
- Export capabilities for analysis and reporting

## Validation Framework

### Constitutional Compliance Validation
- Automatic validation of performance thresholds
- Alert generation when limits exceeded
- Integration with test suite for continuous monitoring
- User notification for constitutional violations

### Data Integrity Validation
- Schema validation for all configuration files
- Range checking for numeric values
- Referential integrity for entity relationships
- Graceful error handling with user-friendly messages

This data model supports all enhancement areas while maintaining constitutional compliance and providing robust error handling and validation throughout the system.