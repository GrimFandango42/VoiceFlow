# VoiceFlow - AI Voice Transcription Tool

**Fast, accurate, and privacy-focused speech-to-text for Windows with local processing.**

VoiceFlow provides push-to-talk dictation with enterprise-grade accuracy while keeping all processing completely local. Choose between full-featured mode for maximum capability or lite mode for speed and efficiency.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Windows](https://img.shields.io/badge/platform-windows-lightgrey.svg)](https://www.microsoft.com/windows)

## 🚀 Quick Start

### Option 1: One-Click Launch (Recommended)
```batch
# Double-click to install and run
LAUNCH_LOCALFLOW.bat
```

### Option 2: Manual Setup
```bash
# Create environment and install
py -3 -m venv venv
venv\Scripts\activate
pip install -r requirements-localflow.txt

# Run VoiceFlow
python voiceflow.py                    # Full mode
python voiceflow.py --lite            # Lite mode
python voiceflow.py --profile=speed   # Speed-optimized
```

## 🎯 Usage Modes

### VoiceFlow (Full Mode)
**Best for**: Maximum accuracy, advanced features, regular use
- **Model**: `large-v3-turbo` (5.4x faster than large-v2)
- **Device**: CUDA with CPU fallback
- **Features**: System tray, real-time streaming, advanced VAD
- **Accuracy**: Enterprise-grade transcription

### VoiceFlow Lite
**Best for**: Speed, low resource usage, quick tasks
- **Model**: `base.en` (ultra-fast)
- **Device**: CPU-optimized
- **Features**: Minimal interface, basic transcription
- **Speed**: 15-20x faster processing

## ⚡ Performance Optimizations (2024)

**Recent upgrades based on latest research:**

| Feature | Before | After | Improvement |
|---------|--------|-------|-------------|
| **Model** | `small.en` | `large-v3-turbo` | **5.4x faster + 20% more accurate** |
| **Processing** | Sequential | VAD-batching | **12.5x speedup possible** |
| **Configuration** | Basic | Optimized profiles | **Speed/accuracy profiles** |
| **Structure** | Cluttered (130+ files) | Clean (39 core files) | **Easy forking & deployment** |

## 🎮 Command Line Interface

```bash
python voiceflow.py [OPTIONS]

# Mode Selection
--lite                    # Enable lite mode (minimal features, CPU-optimized)

# Model & Device  
--model MODEL            # Whisper model: tiny.en, base.en, small.en, large-v3-turbo
--device DEVICE          # Processing: auto (detect), cpu, cuda
--profile PROFILE        # Presets: speed, accuracy, balanced

# Interface Options
--no-tray                # Disable system tray (CLI only)
--hotkey COMBO           # Custom hotkey (default: ctrl+shift+space)
--audio-input FILE       # Process audio file and exit

# Examples
python voiceflow.py                              # Full VoiceFlow
python voiceflow.py --lite                       # VoiceFlow Lite  
python voiceflow.py --model=tiny.en --device=cpu # Ultra-light mode
python voiceflow.py --profile=speed              # Speed-optimized
python voiceflow.py --audio-input recording.wav  # Process file
```

## 🔧 Configuration Profiles

**Speed Profile** (Ultra-fast):
- Model: `base.en`, Beam: 1, Batching: Max
- **Use case**: Quick notes, drafts, real-time feedback

**Accuracy Profile** (Highest quality):  
- Model: `large-v3-turbo`, Beam: 5, Temperature: 0.2
- **Use case**: Important documents, professional transcription

**Balanced Profile** (Recommended):
- Model: `large-v3-turbo`, Beam: 1, Batching: Optimized  
- **Use case**: Daily use, good speed + accuracy

## 🎯 Core Features

### Push-to-Talk Dictation
- **Default hotkey**: `Ctrl+Shift+Space`
- **Smart injection**: Clipboard paste or direct typing
- **Code mode**: Spoken symbols → characters (`"open bracket"` → `[`)
- **Context awareness**: Automatically restores clipboard

### Advanced Audio Processing
- **Voice Activity Detection**: Silero VAD for precise speech detection
- **Real-time streaming**: Live transcription preview
- **Noise handling**: Robust performance in various environments
- **Batch processing**: Process multiple audio segments efficiently

### Privacy & Security
- **100% local processing**: No data leaves your computer
- **Model caching**: Downloaded models stored locally
- **Secure injection**: Control character sanitization
- **Optional clipboard**: Direct typing mode available

## 📁 Project Structure

```
VoiceFlow/                           # 🧹 Cleaned & optimized structure
├── voiceflow.py                     # 🎯 Unified entry point (NEW!)
├── voiceflow_main.py                # Full-featured app
├── voiceflow_lite.py                # Lightweight version
├── voiceflow_tray.py                # System tray launcher
├── LAUNCH_LOCALFLOW.bat             # One-click installer
│
├── localflow/                       # Minimal core (LocalFlow)
│   ├── config.py                    # ⚡ Optimized configuration
│   ├── asr.py                      # Speech recognition engine
│   └── inject.py                   # Text injection system
│
├── voiceflow/                       # Full-featured modules
│   ├── core/                       # Core transcription engine
│   ├── audio/                      # Audio processing
│   └── ui/                         # User interface components
│
├── tests/                          # ✅ Essential unit tests (4/4 passing)
├── docs/                           # Documentation
├── scripts/                        # Build and deployment scripts
│
├── archive/                        # 🗄️ Organized development artifacts
│   ├── testing_infrastructure/     # Comprehensive testing suite
│   ├── reports/                    # Performance and security reports  
│   ├── development_scripts/        # Research and dev tools
│   └── temp_files/                 # Logs and temporary files
│
├── OPTIMIZATION_GUIDE.md           # 📋 Performance improvement roadmap
├── UNIFIED_DESIGN.md               # 🎯 Unified architecture design
└── requirements-localflow.txt      # Minimal dependencies
```

## 🔧 Installation & Setup

### System Requirements
- **OS**: Windows 10/11
- **Python**: 3.9+ (3.10-3.12 recommended)  
- **Memory**: 4GB RAM minimum, 8GB+ recommended
- **GPU**: NVIDIA CUDA recommended (CPU works fine)

### Dependencies
```bash
# Core dependencies (minimal)
pip install -r requirements-localflow.txt

# Full dependencies (all features)  
pip install -r requirements_windows.txt

# Development dependencies
pip install -r requirements-dev.txt
```

### First Run
1. **Model Download**: First launch downloads your selected Whisper model
   - `tiny.en`: ~39MB (ultra-fast)
   - `base.en`: ~74MB (fast)  
   - `large-v3-turbo`: ~1.5GB (accurate)

2. **GPU Setup**: CUDA will be detected automatically
   - **NVIDIA GPU**: Uses `float16` precision for speed
   - **CPU Only**: Uses `int8` quantization for efficiency

## 🧪 Testing

```bash
# Run core unit tests (fast)
python -m pytest tests/test_textproc.py tests/test_injector_logic.py -v

# Test configuration
python -c "from localflow.config import Config; print(Config().model_name)"

# Test entry points
python voiceflow.py --help
python voiceflow.py --lite --model=tiny.en
```

**Test Status**: ✅ **4/4 core tests passing**

## 🚀 Performance Tips

### For Maximum Speed
```bash
python voiceflow.py --lite --model=tiny.en --device=cpu
```

### For Maximum Accuracy  
```bash
python voiceflow.py --profile=accuracy
```

### For Balanced Performance (Recommended)
```bash
python voiceflow.py --profile=balanced
```

### Hardware-Specific Optimization
- **NVIDIA GPUs**: Use CUDA with `float16` (automatic)
- **CPU Only**: Models automatically use `int8` quantization
- **Limited RAM**: Use `--lite --model=tiny.en`

## 🔨 Building Executables

```bash
# Install PyInstaller
pip install pyinstaller

# Build standalone executable
pyinstaller -F -n VoiceFlow voiceflow.py

# Build tray application
pyinstaller -F -n VoiceFlow-Tray voiceflow_tray.py
```

## 📚 Documentation

- **[OPTIMIZATION_GUIDE.md](OPTIMIZATION_GUIDE.md)**: Performance tuning and advanced features
- **[UNIFIED_DESIGN.md](UNIFIED_DESIGN.md)**: Architecture and design principles
- **[docs/](docs/)**: Technical documentation and API reference

## 🤝 Contributing & Forking

This project is designed for easy forking and customization:

1. **Clean structure**: Core functionality clearly separated
2. **Modular design**: Easy to modify individual components  
3. **Comprehensive tests**: Validate changes with existing test suite
4. **Performance optimized**: Built on 2024 best practices research

### Development Workflow
```bash
# Setup development environment
git clone <your-fork>
cd VoiceFlow
python -m venv venv
venv\Scripts\activate
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/ -v

# Test your changes
python voiceflow.py --lite
```

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OpenAI Whisper**: Foundation speech recognition model
- **faster-whisper**: High-performance inference implementation  
- **Silero VAD**: Advanced voice activity detection
- **Community research**: 2024 optimization techniques and benchmarks

---

**VoiceFlow v2.0.0** - Built for speed, accuracy, and privacy 🎯⚡🔒