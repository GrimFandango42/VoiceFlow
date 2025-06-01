# VoiceFlow Architecture

## Overview

VoiceFlow is a desktop application built with Tauri, combining the performance of Rust with the flexibility of web technologies. It provides real-time voice transcription using OpenAI's Whisper model running locally on GPU.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Interface                        │
│                    (React + Vite + CSS)                     │
├─────────────────────────────────────────────────────────────┤
│                      Tauri Runtime                          │
│                    (Rust + WebView2)                        │
├─────────────────────────────────────────────────────────────┤
│                    Backend Services                         │
├─────────────┬────────────────┬─────────────────────────────┤
│   Hotkey    │    Window      │      System Tray           │
│  Manager    │   Manager      │      Integration           │
├─────────────┴────────────────┴─────────────────────────────┤
│                  WebSocket Client                           │
│              (Rust - Tungstenite)                          │
├─────────────────────────────────────────────────────────────┤
│                Python STT Server                            │
│            (localhost:5000)                                 │
├─────────────┬────────────────┬─────────────────────────────┤
│  Whisper    │      VAD       │    DeepSeek AI             │
│    GPU      │   Detection    │  Post-Processing           │
└─────────────┴────────────────┴─────────────────────────────┘
```

## Component Details

### 1. Frontend (React Application)

**Location**: `/src/`

**Responsibilities**:
- User interface rendering
- Real-time transcription display
- Settings management
- Statistics visualization
- WebSocket message handling

**Key Files**:
- `App.jsx` - Main application component
- `main.jsx` - Application entry point
- `index.css` - Global styles

**Technologies**:
- React 18.3.1
- Vite (build tool)
- Tauri API for native features

### 2. Tauri Backend (Rust)

**Location**: `/src-tauri/`

**Responsibilities**:
- Native window management
- System tray integration
- Global hotkey registration
- WebSocket communication
- File system access
- Process management

**Key Files**:
- `main.rs` - Application entry point
- `Cargo.toml` - Rust dependencies
- `tauri.conf.json` - Tauri configuration

**Key Features**:
```rust
// Global hotkey handling
tauri::GlobalShortcutManager::register("Ctrl+Alt")

// System tray with menu
SystemTray::new()
    .with_menu(menu)
    .on_event(|event| { /* handle events */ })

// WebSocket client
WebSocketClient::connect("ws://localhost:5000")
```

### 3. Python STT Server

**Location**: `/python/`

**Responsibilities**:
- Audio capture and processing
- Whisper model management
- Voice Activity Detection (VAD)
- DeepSeek AI integration
- WebSocket server

**Key Components**:

#### Audio Pipeline
```python
Audio Input → VAD → Whisper → DeepSeek → WebSocket Output
```

#### Model Management
- Dynamic model loading based on GPU memory
- Dual-model approach (preview + final)
- Automatic fallback on errors

#### WebSocket Protocol
```json
// Start recording
{"action": "start_recording"}

// Stop recording
{"action": "stop_recording"}

// Transcription result
{
  "type": "transcription",
  "text": "Hello world",
  "model": "large-v3",
  "language": "en",
  "processing_time": 0.125
}
```

## Data Flow

### 1. Recording Flow
```
User presses Ctrl+Alt
    ↓
Tauri captures hotkey
    ↓
Send "start_recording" via WebSocket
    ↓
Python server starts audio capture
    ↓
VAD detects speech segments
    ↓
Whisper processes audio chunks
    ↓
DeepSeek enhances text
    ↓
Send transcription back via WebSocket
    ↓
UI displays formatted text
```

### 2. Settings Flow
```
User changes settings in UI
    ↓
React updates local state
    ↓
Tauri saves to config file
    ↓
Send config update to Python server
    ↓
Server reloads models if needed
```

## Key Design Decisions

### 1. Tauri over Electron
- **Reason**: Smaller bundle size (10MB vs 100MB+)
- **Benefits**: Native performance, lower memory usage
- **Trade-off**: Requires Rust knowledge

### 2. WebSocket Communication
- **Reason**: Real-time bidirectional communication
- **Benefits**: Low latency, event-driven
- **Alternative considered**: HTTP polling (rejected due to latency)

### 3. Separate Python Server
- **Reason**: Best ML ecosystem support
- **Benefits**: Easy Whisper integration, flexible processing
- **Trade-off**: Additional process to manage

### 4. GPU Acceleration
- **Reason**: 40x performance improvement
- **Benefits**: Real-time transcription possible
- **Requirement**: NVIDIA GPU with CUDA

### 5. Dual-Model Approach
- **Preview Model**: Small/base for instant feedback
- **Final Model**: Large-v3 for accuracy
- **Benefit**: Best of both worlds - speed and accuracy

## Security Considerations

### 1. Local Processing
- All audio processing happens locally
- No internet connection required
- No data leaves the machine

### 2. Process Isolation
- Python server runs as separate process
- Communication only via localhost WebSocket
- No external network access

### 3. File System Access
- Limited to app data directory
- User consent required for other locations
- Sandboxed by Tauri permissions

## Performance Optimizations

### 1. GPU Utilization
- CUDA acceleration for Whisper
- Batch processing for efficiency
- Dynamic batch sizing based on GPU memory

### 2. Memory Management
- Model loaded once and reused
- Audio buffer recycling
- Automatic garbage collection

### 3. Background Processing
- UI remains responsive during transcription
- Async/await patterns throughout
- Worker threads for heavy operations

## Deployment

### Build Process
```
Frontend Build → Rust Compilation → Bundle Creation
     ↓                ↓                    ↓
  Vite Build    Cargo Build         Tauri Bundle
     ↓                ↓                    ↓
   /dist/       /target/release/    .exe/.msi
```

### Distribution
- Standalone executable (no installer needed)
- MSI installer for traditional installation
- Portable version (upcoming)

## Future Architecture Considerations

### 1. Plugin System
- Allow custom post-processors
- Support for additional STT engines
- Third-party integrations

### 2. Multi-Language Support
- i18n for UI
- Multiple Whisper models
- Language auto-detection

### 3. Cloud Sync (Optional)
- End-to-end encrypted
- User-controlled
- Privacy-first design

### 4. Mobile Companion
- Share transcriptions
- Remote control
- Sync settings