# VoiceFlow - Production-Ready Local Voice Transcription

**🎉 PRODUCTION-READY WISPR FLOW REPLACEMENT - v1.1.0**

[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)](https://github.com/yourusername/voiceflow)
[![Version](https://img.shields.io/badge/Version-v1.1.0-blue)](https://github.com/yourusername/voiceflow/releases)
[![User Validated](https://img.shields.io/badge/User%20Confirmed-Working-success)](https://github.com/yourusername/voiceflow)

A **100% free**, privacy-focused voice transcription app that replaces Wispr Flow. Powered by OpenAI Whisper running locally with optional AI enhancement.

## 🚀 QUICK START

### Installation (One Time Only)
```batch
INSTALL_ENHANCED_DEPS.bat
```

### Daily Usage
```batch
# Recommended: Clean, reliable console version
VoiceFlow-Simple.bat

# OR System Tray with icon (minimized operation)
VoiceFlow-Simple-Tray.bat

# OR Performance-optimized version (fastest response)
VoiceFlow-Performance.bat

# OR Enhanced version with full features
VoiceFlow-Enhanced.bat
```

### How to Use
1. **Run** any launcher above
2. **Position cursor** in any text field (Notepad, browser, chat, etc.)
3. **Press and hold** `Ctrl+Alt`
4. **Speak clearly** while holding keys
5. **Release keys** when done
6. **Watch text appear** instantly!

## ✨ Features

- 🎙️ **Universal Voice Input** - Works in ANY Windows application
- 🚀 **Blazing Fast** - GPU/CPU optimized Whisper transcription
- 🧠 **AI Enhancement** - Optional formatting and grammar correction
- 📊 **Performance Tracking** - Built-in speed and accuracy metrics
- 🔒 **100% Private** - Everything runs locally on your machine
- 💰 **Completely Free** - No subscriptions, no API costs
- 🖥️ **Multiple Modes** - Console, System Tray, or Invisible operation

## 🏆 Current Status - v1.1.0

### ✅ WORKING VERSIONS
- **VoiceFlow-Simple**: Streamlined, reliable daily driver
- **VoiceFlow-Performance**: Speed-optimized with ~100ms latency
- **VoiceFlow-Enhanced**: Full-featured with AI enhancement
- **System Tray Versions**: Background operation with tray icons

### ✅ VALIDATED FEATURES
- **Universal Text Injection**: Works across all Windows applications
- **Smart Audio Buffering**: Captures complete speech utterances
- **Auto-Fallbacks**: CUDA→CPU, port conflicts, injection methods
- **Error Recovery**: Graceful handling of all failure scenarios
- **Performance Optimization**: Multiple model sizes (tiny→base→small)

### ✅ TECHNICAL ACHIEVEMENTS
- **Zero-Config Operation**: Works out-of-the-box
- **Robust CUDA Handling**: Automatic GPU detection and fallback
- **Multi-Method Text Injection**: Direct keyboard + clipboard fallback
- **Professional Logging**: Clear diagnostics and error reporting

## 📁 Clean Project Structure

After cleanup, the project now has a streamlined structure:

```
VoiceFlow/
├── python/                     # Core Python modules
│   ├── stt_server.py          # Main STT server
│   ├── simple_server.py       # Alternative server
│   ├── voiceflow_performance.py # Performance-optimized version
│   ├── performance_benchmark.py # Benchmarking tools
│   ├── simple_tray.py         # System tray functionality
│   └── enum_patch.py          # Python 3.13 compatibility
├── native/                     # Native Windows integration
│   ├── voiceflow_native.py    # Core native service
│   ├── speech_processor.py    # Speech processing module
│   └── functional_test.py     # Native functionality tests
├── electron/                   # Standalone executable
├── docs/                       # Documentation
├── VoiceFlow-Simple.bat        # Recommended launcher
├── VoiceFlow-Performance.bat   # Speed-optimized launcher
├── VoiceFlow-Enhanced.bat      # Full-featured launcher
├── INSTALL_ENHANCED_DEPS.bat   # Dependency installer
├── comprehensive_end_to_end_test.py # Main test suite
├── quick_system_check.py       # Health check
└── voiceflow_mcp_server.py     # MCP protocol integration
```

## 🎯 Version Comparison

| Version | Speed | Features | Use Case |
|---------|-------|----------|----------|
| **Simple** | Fast | Core transcription | Daily driver, reliable |
| **Performance** | Fastest | Speed-optimized | Power users, minimal latency |
| **Enhanced** | Medium | Full AI features | Advanced users, formatting |

## 🔧 Performance Options

### Model Selection (Speed vs Accuracy)
- **Tiny**: ~100ms latency, basic accuracy, 1GB VRAM
- **Base**: ~200ms latency, good accuracy, 1GB VRAM  
- **Small**: ~400ms latency, best accuracy, 2GB VRAM

### Hardware Requirements
- **Minimum**: CPU-only operation (slower but works)
- **Recommended**: NVIDIA GPU with 2GB+ VRAM
- **Optimal**: NVIDIA GPU with 4GB+ VRAM

## 🧪 Testing

### Quick Health Check
```batch
python quick_system_check.py
```

### Comprehensive Testing
```batch
python comprehensive_end_to_end_test.py
```

### Native Functionality Test
```batch
python native/functional_test.py
```

## 🚀 Phase 2 Roadmap

### Next Release (v1.2.0)
- **Linux/WSL Compatibility**: Fix text injection in terminal environments
- **Model Persistence**: Remember user's preferred Whisper model
- **Custom Hotkeys**: User-configurable key combinations
- **Audio Device Selection**: Choose specific microphone input

### Future Enhancements (v1.3.0+)
- **Multi-Language Support**: Auto-detection and switching
- **Voice Commands**: "new paragraph", "comma", etc.
- **Real-time Confidence**: Show transcription accuracy
- **Export History**: Save transcriptions to file

## 🛠️ Troubleshooting

### Common Issues
1. **No transcription appears**: Check microphone permissions
2. **Slow performance**: Try smaller model (tiny/base)
3. **CUDA errors**: App automatically falls back to CPU
4. **Port conflicts**: App tries multiple ports automatically

### Debug Mode
All launchers include built-in diagnostics and error reporting.

## 🤝 Contributing

VoiceFlow is open source and welcomes contributions:
1. Fork the repository
2. Create a feature branch
3. Test your changes
4. Submit a pull request

## 📄 License

MIT License - Complete freedom to use, modify, and distribute.

## 🙏 Acknowledgments

- [OpenAI Whisper](https://github.com/openai/whisper) - Core speech recognition
- [faster-whisper](https://github.com/guillaumekln/faster-whisper) - Optimized implementation
- Windows Speech API - Audio capture
- Python ecosystem - Core functionality

---

**Built to provide a free, private alternative to expensive transcription services!**

*Save $15+/month while getting better performance and complete privacy.*