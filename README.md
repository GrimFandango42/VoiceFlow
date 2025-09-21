# VoiceFlow

> **Author's Note**: This project has been primarily vibe coded with Claude. It's been fun to code with Claude. Feel free to tear the code apart - submit issues where Claude is good and bad at coding. Feel free to fork it off. I promise it should mostly work on a Windows machine, which is where I've tested it. Feel free to make your own, do what you need to, and hopefully you find it useful to avoid paying for equivalent transcription services (likely better transcription services for more money, but oh well). Do with it as you please, and again feel free to submit any issues. I may or may not ever get to them.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-pytest-green.svg)](https://pytest.org/)

A local voice transcription system for Windows that converts speech to text using OpenAI Whisper. Works offline with no data sent to external servers. Built for personal use - your mileage may vary.

## What It Does

- Press and hold a hotkey (default: Ctrl+Shift+Space) to record speech
- Automatically transcribes using OpenAI Whisper when you release the key
- Types the transcribed text into whatever application you're using
- Everything happens locally on your machine - no internet required

## Control Center

![VoiceFlow Control Center](assets/control-center-gui-clean.png)

The Control Center provides system management and monitoring. Launch it with:

```bash
# Windows
tools\launchers\LAUNCH_CONTROL_CENTER.bat

# Or run directly
python tools/VoiceFlow_Control_Center.py
```

## Installation

### Prerequisites
- Python 3.9 or higher
- Windows (tested here, other platforms untested)
- A microphone
- 4GB+ RAM recommended

### Install Steps

```bash
# Clone the repository
git clone https://github.com/yourusername/voiceflow.git
cd voiceflow

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Quick Start

```bash
# Launch with system tray
START_VOICEFLOW.bat

# Or launch terminal mode
LAUNCH_VOICEFLOW.bat
```

### Basic Operation

1. Launch VoiceFlow using one of the methods above
2. Press and hold `Ctrl+Shift+Space` to start recording
3. Speak while holding the key
4. Release the key to stop recording and transcribe
5. The transcribed text appears in your active window

### Visual Indicators

The system shows status with colored indicators:

- **Blue**: Ready for input
- **Orange**: Recording (while holding hotkey)
- **Green**: Processing/transcribing
- **Red**: Error occurred

## Configuration

Settings can be adjusted through:

- **System Tray**: Right-click the tray icon for basic toggles
- **Configuration Files**: JSON files in the config directory
- **Command Line**: Various startup options available

Common settings:
- Change hotkey combinations
- Switch between typing and clipboard paste
- Toggle "code mode" for programming terms
- Adjust audio devices and quality

## Architecture

The system has four main layers:

1. **UI Layer**: System tray, visual indicators, Control Center GUI
2. **Integration Layer**: Hotkey capture, text injection, system events
3. **Core Processing**: Audio capture, Whisper transcription, text formatting
4. **Hardware Layer**: Audio devices, OS integration, file system

```
src/voiceflow/
├── core/           # Audio processing and transcription
├── ui/             # User interface components
├── integrations/   # System integrations and hotkeys
└── utils/          # Utilities and configuration
```

Key components:
- `core/advanced_performance_asr.py`: Main transcription engine
- `ui/enhanced_tray.py`: System tray interface
- `integrations/inject.py`: Text injection system
- `ui/visual_indicators.py`: Status display system

## Testing

```bash
# Run unit tests
pytest tests/unit/

# Run all tests
pytest

# Quick health check
python scripts/dev/health_check_simple.py

# Stress testing
python tests/stress/test_edge_case_stress.py
```

## Performance

Typical performance on modern hardware:
- Transcription speed: 10-15x realtime
- Latency: 50-150ms after key release
- Memory usage: 1-3GB depending on model size
- Works with or without GPU acceleration

## Troubleshooting

**Audio not working**:
```bash
python scripts/list_audio_devices.py  # List available microphones
```

**Performance issues**:
- Try smaller Whisper model (`base.en` instead of `large`)
- Check if GPU drivers are installed for CUDA support
- Close other memory-intensive applications

**Permission errors**:
- Run as administrator on Windows
- Check microphone permissions in Windows settings

## Known Issues

- Primarily tested on Windows 11
- May not work well with some applications that block input simulation
- Large Whisper models require significant RAM
- GPU support depends on CUDA installation

## Dependencies

Main dependencies:
- `faster-whisper`: Optimized Whisper inference
- `sounddevice`: Audio capture
- `keyboard`: Hotkey detection and text injection
- `pyperclip`: Clipboard operations
- `tkinter`: GUI components
- `torch`: ML framework (CPU/CUDA)

## Documentation

- [Technical Overview](docs/TECHNICAL_OVERVIEW.md): Architecture details
- [User Guide](docs/USER_GUIDE.md): Detailed usage instructions
- [Testing Notes](docs/TESTING_NOTES.md): Testing framework info

## License

MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

- [OpenAI Whisper](https://github.com/openai/whisper) for the speech recognition
- [faster-whisper](https://github.com/guillaumekln/faster-whisper) for optimized inference
- Various Python libraries that make this possible

---

**VoiceFlow** - Local speech-to-text for personal use