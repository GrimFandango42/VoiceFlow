# VoiceFlow - Professional Local Voice Transcription

[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)](https://github.com/GrimFandango42/voiceflow)
[![Version](https://img.shields.io/badge/Version-v2.0.0-blue)](https://github.com/GrimFandango42/voiceflow/releases)
[![Security](https://img.shields.io/badge/Security-Audited-green)](https://github.com/GrimFandango42/voiceflow)
[![Testing](https://img.shields.io/badge/Testing-Comprehensive-brightgreen)](https://github.com/GrimFandango42/voiceflow)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Professional-grade local voice transcription system with AI enhancement.** A free, privacy-focused alternative to commercial transcription services like Wispr Flow, featuring lightning-fast local processing, intelligent text formatting, and enterprise-level security.

## 🎯 Overview

VoiceFlow transforms speech into text using state-of-the-art OpenAI Whisper models running entirely on your machine. Enhanced with local AI for intelligent formatting and context-aware text processing. Perfect for developers, writers, professionals, and anyone who values privacy and performance.

### Key Benefits
- **🔒 100% Private** - All processing happens locally, your voice never leaves your device
- **⚡ Lightning Fast** - Sub-500ms transcription with optimized GPU acceleration
- **🧠 AI-Enhanced** - Intelligent punctuation, formatting, and context awareness
- **🎯 Universal** - Works in any application (browsers, IDEs, documents, chat)
- **💰 Completely Free** - No subscriptions, API costs, or usage limits
- **🛡️ Enterprise Security** - Security-audited with comprehensive testing

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/GrimFandango42/voiceflow.git
cd voiceflow

# Install dependencies
pip install -r python/requirements.txt

# Start with simple mode
python voiceflow_simple.py
```

### Two Simple Options

#### Option 1: **Simple Mode** (Recommended for new users)
```bash
python voiceflow_simple.py
```
Perfect for trying VoiceFlow and daily usage.

#### Option 2: **Tray Mode** (For background usage)
```bash
python voiceflow_tray.py
```
Runs in background with system tray icon. Use once you're confident it works well.

### Basic Usage

1. **Start VoiceFlow**: Choose simple or tray mode above
2. **Position Cursor**: Click in any text field (browser, IDE, document)
3. **Record**: Press `Ctrl+Alt` and speak clearly
4. **Result**: Enhanced text appears instantly where you clicked

## ✨ Features

### Core Capabilities
- **Universal Text Input** - Works in any Windows/Linux application
- **GPU Acceleration** - CUDA-optimized Whisper with automatic CPU fallback
- **Smart Formatting** - Context-aware punctuation and capitalization
- **Multi-Model Support** - Choose speed vs accuracy (tiny/base/small/large)
- **Real-time Processing** - Live transcription with minimal latency
- **Error Recovery** - Graceful handling of network, hardware, and software issues

### AI Enhancement
- **Local AI Processing** - Ollama/DeepSeek integration for text enhancement
- **Context Awareness** - Adapts formatting based on application context
- **Custom Vocabulary** - Personal dictionary for technical terms and names
- **Voice Commands** - Support for "new line", "new paragraph", editing commands
- **Multi-Language** - Support for multiple languages and dialects

### Privacy & Security
- **Zero Data Collection** - No telemetry, analytics, or data transmission
- **Local Processing** - All AI and speech processing happens on your device
- **Encrypted Storage** - Optional database encryption for transcription history
- **Security Audited** - Comprehensive security testing and validation
- **Open Source** - Fully auditable codebase with MIT license

## 🏗️ Architecture

VoiceFlow features a clean, modular architecture designed for reliability and extensibility:

```
voiceflow/
├── core/                      # Core functionality modules
│   ├── voiceflow_core.py     # Main speech processing engine
│   ├── ai_enhancement.py     # AI text enhancement
│   └── __init__.py           # Module exports
├── implementations/           # Application implementations
│   ├── simple.py             # Simple CLI implementation
│   └── server.py             # WebSocket server (planned)
├── utils/                     # Shared utilities
│   └── config.py             # Configuration management
├── python/                    # Legacy implementations
│   ├── stt_server.py         # WebSocket server
│   ├── simple_server.py      # Simple CLI version
│   └── voiceflow_performance.py # Performance-optimized
├── native/                    # Platform-specific integration
│   └── voiceflow_native.py   # Windows native service
├── electron/                  # Desktop application
│   ├── main.js               # Electron main process
│   └── preload.js            # Secure preload script
├── tests/                     # Comprehensive testing suite
└── docs/                      # Documentation
```

## 🎛️ Advanced Options

For developers and advanced users, additional implementations are available:

### WebSocket Server
For integration with web applications:
```bash
python python/stt_server.py
```

### MCP Integration
For Claude MCP ecosystem integration:
```bash
python voiceflow_mcp_server.py
```

### Native Windows Service
For advanced system integration:
```bash
python native/voiceflow_native.py
```

## ⚙️ Configuration

VoiceFlow supports flexible configuration through environment variables, config files, and runtime options:

### Environment Variables
```bash
# Audio Configuration
export VOICEFLOW_MODEL=base          # Model size (tiny/base/small/large)
export VOICEFLOW_DEVICE=auto         # Device (auto/cuda/cpu)

# AI Enhancement
export ENABLE_AI_ENHANCEMENT=true    # Enable AI text enhancement
export OLLAMA_HOST=localhost         # Ollama server host
export AI_MODEL=llama3.3:latest      # AI model for enhancement

# Security
export ENABLE_DEBUG_LOGGING=false    # Debug logging
export MAX_AUDIO_DURATION=30         # Max recording duration
```

### Configuration File
Create `.voiceflow/config.json` in your home directory:
```json
{
  "audio": {
    "model": "base",
    "device": "auto",
    "language": "en"
  },
  "ai": {
    "enabled": true,
    "model": "llama3.3:latest",
    "temperature": 0.3
  },
  "hotkeys": {
    "record_and_inject": "ctrl+alt"
  }
}
```

## 🧪 Testing

VoiceFlow includes a comprehensive testing framework with 95%+ code coverage:

### Run All Tests
```bash
# Complete testing suite
python run_tests.py --all --report

# Specific test categories
python run_tests.py unit integration e2e ux
```

### Test Categories
- **Unit Tests** - Core module functionality
- **Integration Tests** - Component interactions
- **End-to-End Tests** - Complete user workflows
- **UX Tests** - User experience and accessibility
- **Performance Tests** - Load and stress testing
- **Security Tests** - Security implementation validation

## 🚀 Performance

### Benchmarks
- **Latency**: <500ms end-to-end transcription
- **Accuracy**: 95%+ for clear speech
- **Throughput**: 50+ transcriptions/minute
- **Memory**: <2GB RAM for base model
- **CPU Usage**: <20% during transcription

### Hardware Requirements
- **Minimum**: 4GB RAM, modern CPU
- **Recommended**: 8GB RAM, NVIDIA GPU with 2GB+ VRAM
- **Optimal**: 16GB RAM, NVIDIA GPU with 4GB+ VRAM

## 🛡️ Security

VoiceFlow has undergone comprehensive security auditing:

- ✅ **No exposed secrets or API keys**
- ✅ **Secure network communications (HTTPS/WSS)**
- ✅ **Input validation and sanitization**
- ✅ **Dependency vulnerability scanning**
- ✅ **File permission and access control validation**
- ✅ **Security configuration best practices**

See [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) for detailed security analysis.

## 📚 Documentation

- **[Architecture Guide](docs/ARCHITECTURE.md)** - Technical architecture overview
- **[User Guide](docs/USER_GUIDE.md)** - Detailed usage instructions
- **[Build Guide](docs/BUILD_GUIDE.md)** - Build and development setup
- **[Contributing Guide](docs/CONTRIBUTING.md)** - Development guidelines
- **[Security Report](SECURITY_AUDIT_REPORT.md)** - Security audit results
- **[Testing Guide](COMPREHENSIVE_TESTING_REPORT.md)** - Testing framework overview

## 🔧 Troubleshooting

### Common Issues

**No transcription appears**
- Check microphone permissions
- Verify audio input device selection
- Test with `python tests/test_audio.py`

**Slow performance**
- Try smaller model: `export VOICEFLOW_MODEL=tiny`
- Check GPU availability: `nvidia-smi`
- Verify system resources

**AI enhancement not working**
- Check Ollama installation and models
- Verify network connectivity
- Test with: `python tests/test_ai_enhancement.py`

### Debug Mode
Enable detailed logging for troubleshooting:
```bash
export ENABLE_DEBUG_LOGGING=true
python implementations/simple.py
```

## 🤝 Contributing

VoiceFlow welcomes contributions! See our [Contributing Guide](docs/CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/GrimFandango42/voiceflow.git
cd voiceflow

# Install development dependencies
pip install -r requirements_testing.txt

# Run tests
python run_tests.py

# Make your changes and submit a pull request
```

## 🎯 Use Cases

### For Developers
- **Code Documentation** - Dictate comments and documentation
- **Email & Chat** - Fast communication without typing
- **Bug Reports** - Quick issue descriptions and notes
- **Meeting Notes** - Capture discussions and decisions

### For Writers
- **Content Creation** - Draft articles, stories, and scripts
- **Note Taking** - Capture ideas and research notes
- **Editing** - Voice-driven editing and revisions
- **Transcription** - Convert interviews and recordings

### For Professionals
- **Business Communication** - Professional emails and messages
- **Presentations** - Draft slides and speaker notes
- **Reports** - Document creation and collaboration
- **Accessibility** - Voice input for users with mobility challenges

## 📊 Comparison

| Feature | VoiceFlow | Wispr Flow | Talon | Dragon |
|---------|-----------|------------|-------|--------|
| **Privacy** | ✅ 100% Local | ❌ Cloud | ✅ Local | ❌ Cloud |
| **Cost** | ✅ Free | ❌ $7/month | ❌ $15/month | ❌ $300+ |
| **Speed** | ✅ <500ms | ⚠️ Variable | ✅ Fast | ⚠️ Variable |
| **Accuracy** | ✅ 95%+ | ✅ High | ✅ High | ✅ High |
| **AI Enhancement** | ✅ Local AI | ❌ Basic | ❌ Limited | ❌ Basic |
| **Open Source** | ✅ MIT | ❌ Proprietary | ❌ Proprietary | ❌ Proprietary |
| **Customization** | ✅ Full | ❌ Limited | ✅ Extensive | ⚠️ Some |

## 📈 Roadmap

### v2.1.0 (Next Release)
- [ ] Linux/macOS native support
- [ ] Real-time transcription display
- [ ] Custom hotkey configuration UI
- [ ] Audio device selection interface
- [ ] Multi-language auto-detection

### v2.2.0 (Future)
- [ ] Plugin architecture for STT engines
- [ ] WebUI for configuration management
- [ ] Mobile companion app
- [ ] Cloud sync (optional, encrypted)
- [ ] Team collaboration features

## 📜 License

MIT License - Complete freedom to use, modify, and distribute.

See [LICENSE](LICENSE) for full details.

## 🙏 Acknowledgments

- **OpenAI Whisper** - State-of-the-art speech recognition
- **Ollama** - Local AI model hosting
- **RealtimeSTT** - Real-time speech processing
- **Contributors** - Community developers and testers

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/GrimFandango42/voiceflow/issues)
- **Discussions**: [GitHub Discussions](https://github.com/GrimFandango42/voiceflow/discussions)
- **Documentation**: [Project Wiki](https://github.com/GrimFandango42/voiceflow/wiki)

---

**Made with ❤️ for developers, writers, and professionals who value privacy and performance.**

## 🏷️ Keywords

`voice-to-text` `speech-recognition` `whisper` `ai-transcription` `local-processing` `privacy-focused` `developer-tools` `productivity` `accessibility` `open-source` `free-software` `voice-input` `dictation` `speech-to-text` `transcription` `ai-enhancement` `real-time` `cross-platform` `secure` `enterprise-ready`