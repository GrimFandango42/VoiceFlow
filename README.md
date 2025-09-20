# VoiceFlow

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Tests](https://img.shields.io/badge/tests-pytest-green.svg)](https://pytest.org/)
[![Offline](https://img.shields.io/badge/offline-privacy%20focused-green.svg)](#privacy)

A local voice transcription system for Windows that converts speech to text using OpenAI Whisper. Works completely offline with no data sent to external servers.

## Why Use VoiceFlow?

- **Privacy First**: All processing happens locally - your voice never leaves your computer
- **Always Available**: Works without internet connection or cloud services
- **Practical Speed**: Fast enough for real-time dictation and note-taking
- **System Integration**: Automatically types or pastes transcribed text into any application
- **Developer Friendly**: Built for coding conversations with technical term recognition

## Control Center

![VoiceFlow Control Center](assets/control-center-gui-clean.png)

The Control Center provides a unified interface for system management:
- System launch and configuration
- Visual demo controls for testing
- Real-time status monitoring with progress indicators
- Test suite execution and health checks

Launch commands:

```bash
# Windows
tools\launchers\LAUNCH_CONTROL_CENTER.bat

# Or run directly
python tools/VoiceFlow_Control_Center.py
```

## What It Does

**Voice to Text Conversion**
- Press and hold Ctrl+Shift to record speech
- Automatic transcription using OpenAI Whisper
- Text is automatically typed into any application

**System Integration**
- Visual status indicator shows recording/processing state
- System tray for easy access and configuration
- Works with any Windows application (browsers, editors, documents)

**Technical Features**
- Offline processing - no internet required
- Configurable audio devices and settings
- Smart text formatting for programming and technical terms
- Clipboard or direct typing output modes

## Installation & Usage

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/voiceflow.git
cd voiceflow

# Install with pip (recommended)
pip install -e .

# Or install from PyPI (when available)
pip install voiceflow
```

### Basic Usage

```bash
# Launch with system tray (recommended)
voiceflow-tray

# Or launch in terminal mode
voiceflow

# Setup and configuration wizard
voiceflow-setup
```

### Windows Quick Launch

For Windows users, use the convenient batch launchers:

```batch
# Double-click to launch
tools/launchers/LAUNCH_TRAY.bat        # System tray mode
tools/launchers/LAUNCH_TERMINAL.bat    # Terminal mode
tools/launchers/LAUNCH_CONTROL_CENTER.bat  # Control center GUI
```

## Visual Status System

The system uses color-coded indicators to show current state:

| Color | Status | Description |
|-------|--------|-------------|
| 🔵 Blue | Ready | System ready for voice input |
| 🟠 Orange | Listening | Recording audio (hold `Ctrl+Shift`) |
| 🟢 Green | Processing | Transcribing and processing audio |
| 🔴 Red | Error | Error state or system issue |

## Default Controls

- Voice Activation: `Ctrl + Shift` (press and hold)
- System Tray: Right-click for settings and options
- Visual Overlay: Bottom-center screen display
- Auto Text Injection: Automatic paste after transcription

## Configuration

Configuration options are available through multiple interfaces:

### System Tray Menu
- Toggle code mode for programming
- Switch between typing and paste injection
- Configure hotkey combinations
- Adjust visual indicator settings

### Configuration Files
- **Main Config**: Automatic creation and management
- **Visual Settings**: Themes, positions, and display options
- **Audio Settings**: Sample rates, devices, and processing options

### Environment Variables
```bash
export VOICEFLOW_MODEL="base.en"     # Whisper model
export VOICEFLOW_DEVICE="cuda"       # Processing device
export VOICEFLOW_LOG_LEVEL="INFO"    # Logging level
```

## Architecture

The system uses a modular 4-layer architecture optimized for low-latency audio processing:

### System Architecture Overview

![VoiceFlow Architecture](assets/voiceflow-architecture-diagram.png)

VoiceFlow uses a **4-layer modular architecture** designed for low-latency, real-time speech processing:

#### 🎨 **User Interface Layer**
```
┌─────────────────────────────────────────────────────────┐
│  Control Center GUI  │  System Tray  │  Visual Overlays │
│  ├─ Launch Controls  │  ├─ Settings  │  ├─ Status LEDs  │
│  ├─ System Status    │  ├─ Quick     │  ├─ Progress     │
│  └─ Test Suite       │  └─ Toggle    │  └─ Indicators   │
└─────────────────────────────────────────────────────────┘
```

#### 🔗 **Integration Layer**
```
┌─────────────────────────────────────────────────────────┐
│  Global Hotkeys  │  Text Injection  │  System Events   │
│  ├─ Ctrl+Shift   │  ├─ Direct Type  │  ├─ Focus Track  │
│  ├─ Custom Keys  │  ├─ Clipboard    │  ├─ App Monitor  │
│  └─ Key Capture  │  └─ Smart Paste  │  └─ State Sync   │
└─────────────────────────────────────────────────────────┘
```

#### ⚡ **Core Processing Layer**
```
┌─────────────────────────────────────────────────────────┐
│  Audio Engine    │  ASR Pipeline    │  Performance     │
│  ├─ Real-time    │  ├─ Whisper      │  ├─ Memory Pool  │
│  ├─ Capture      │  ├─ faster-      │  ├─ Lock-free    │
│  ├─ Buffering    │  │   whisper     │  ├─ Threading    │
│  └─ VAD Filter   │  └─ Text Proc    │  └─ Optimization │
└─────────────────────────────────────────────────────────┘
```

#### 🖥️ **Hardware/OS Layer**
```
┌─────────────────────────────────────────────────────────┐
│  Audio Devices   │  OS Integration  │  System Resources│
│  ├─ Microphone   │  ├─ Windows API  │  ├─ CPU/GPU      │
│  ├─ Drivers      │  ├─ DirectSound  │  ├─ Memory       │
│  └─ Sample Rate  │  └─ Permissions  │  └─ Storage      │
└─────────────────────────────────────────────────────────┘
```

### Core Components

```
src/voiceflow/
├── core/                    # 🎵 Audio processing and transcription
│   ├── config.py           #    Configuration management
│   ├── textproc.py         #    Text processing and formatting
│   ├── memory_optimized_audio.py  #  Audio capture & buffering
│   └── adaptive_model_access.py   #  Whisper model management
├── ui/                      # 🎨 User interface components
│   ├── tray.py             #    System tray integration
│   ├── enhanced_tray.py    #    Advanced tray features
│   ├── visual_config.py    #    Visual overlay system
│   └── visual_indicators.py #    Status indicators
├── integrations/            # 🔗 System integrations and hotkeys
│   └── [platform-specific] #    OS-specific implementations
└── utils/                   # 🛠️ Utilities and helpers
    ├── logging_setup.py    #    Centralized logging
    ├── validation.py       #    Input validation
    └── utils.py            #    Common utilities
```

#### Component Details

🎵 **Audio Processing Pipeline**
- **Real-time Capture**: Low-latency audio streaming with configurable buffer sizes
- **VAD Integration**: Voice Activity Detection for automatic start/stop
- **Adaptive Buffering**: Dynamic buffer management for optimal performance
- **Multi-device Support**: Flexible audio device selection and fallback

⚡ **ASR Engine Integration**
- **Whisper Models**: Support for all OpenAI Whisper model sizes (tiny → large)
- **faster-whisper**: CTranslate2-optimized inference for 4x speed improvement
- **GPU Acceleration**: CUDA support with automatic CPU fallback
- **Model Caching**: Intelligent model loading and memory management

📝 **Text Processing Features**
- **Smart Formatting**: Context-aware punctuation and capitalization
- **Code Mode**: Programming-optimized transcription with technical terms
- **Custom Vocabularies**: User-defined word replacements and shortcuts
- **Multi-language**: Support for 50+ languages with automatic detection

🎨 **Visual Feedback System**
- **Status Overlays**: Non-intrusive color-coded indicators
- **Thread-safe UI**: Concurrent visual updates without blocking
- **Customizable Themes**: User-configurable colors and positions
- **Progress Tracking**: Real-time transcription progress visualization

🚀 **Performance Optimizations**
- **Lock-free Architecture**: Minimal contention for real-time performance
- **Memory Pooling**: Pre-allocated buffers to reduce garbage collection
- **Async Processing**: Non-blocking I/O and concurrent operations
- **Micro-optimizations**: Profile-guided performance improvements

## 🧪 Testing

VoiceFlow includes comprehensive testing:

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit          # Unit tests
pytest tests/integration   # Integration tests
pytest tests/e2e          # End-to-end tests

# Run with coverage
pytest --cov=src/voiceflow --cov-report=html

# Quick smoke test
python scripts/dev/quick_smoke_test.py
```

## 📚 Documentation

- **[Build Guide](docs/BUILD_GUIDE.md)**: Detailed setup and installation instructions
- **[User Guide](docs/USER_GUIDE.md)**: Complete usage and configuration documentation
- **[Technical Overview](docs/TECHNICAL_OVERVIEW.md)**: Architecture and development details
- **[Contributing Guide](docs/CONTRIBUTING.md)**: Development and contribution guidelines
- **[Testing Notes](docs/TESTING_NOTES.md)**: Testing framework and procedures

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](docs/CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/yourusername/voiceflow.git
cd voiceflow

# Install with development dependencies
pip install -e ".[dev,test,docs]"

# Install pre-commit hooks
pre-commit install

# Run development checks
ruff check src tests      # Linting
mypy src                  # Type checking
pytest tests/            # Testing
```

## 📋 Requirements

- **Python**: 3.9 or higher
- **Operating System**: Windows (primary), Linux/macOS (community support)
- **Hardware**:
  - Microphone for voice input
  - 4GB+ RAM recommended
  - GPU optional (CUDA support for faster processing)

### Dependencies

Core dependencies are automatically managed through `pyproject.toml`:

- **Audio**: `sounddevice`, `pyaudio`, `pydub`
- **AI/ML**: `faster-whisper`, `torch`, `ctranslate2`
- **UI**: `pystray`, `tkinter`, `Pillow`
- **System**: `keyboard`, `pyperclip`

## 🚨 Troubleshooting

### Common Issues

**Audio not detected**:
```bash
python scripts/dev/list_audio_devices.py  # List available devices
```

**Performance issues**:
```bash
python scripts/dev/health_check.py        # System health check
```

**Permission errors**:
- Run as administrator (Windows)
- Check microphone permissions

### Getting Help

- 📖 Check our [Documentation](docs/)
- 🐛 [Report Issues](https://github.com/yourusername/voiceflow/issues)
- 💬 [Discussions](https://github.com/yourusername/voiceflow/discussions)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OpenAI Whisper](https://github.com/openai/whisper) for the speech recognition engine
- [faster-whisper](https://github.com/guillaumekln/faster-whisper) for optimized inference
- [Wispr Flow](https://www.wisprapp.com) for visual design inspiration

---

**VoiceFlow** - *Transforming voice to text with modern AI*