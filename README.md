# VoiceFlow - Free Local Voice Transcription App

**🎉 MVP SUCCESS - WORKING WISPR FLOW REPLACEMENT!**

[![Status](https://img.shields.io/badge/Status-MVP%20Working-brightgreen)](https://github.com/yourusername/voiceflow)
[![Version](https://img.shields.io/badge/Version-v1.0.0--mvp-blue)](https://github.com/yourusername/voiceflow/releases)
[![User Confirmed](https://img.shields.io/badge/User%20Confirmed-Working-success)](https://github.com/yourusername/voiceflow)

A **100% free**, privacy-focused voice transcription app that rivals Wispr Flow. Powered by OpenAI Whisper running locally on your GPU and enhanced with DeepSeek AI for intelligent formatting.

## 🚀 QUICK START - CONFIRMED WORKING!

**✅ USER CONFIRMED**: "It worked!" - Successfully replaces Wispr Flow  
**✅ GLOBAL HOTKEY**: Press and hold `Ctrl+Alt` anywhere to record  
**✅ UNIVERSAL**: Works in any Windows application  
**✅ FREE**: Eliminates $144/year Wispr Flow subscription  
**✅ PRIVATE**: 100% local processing, no cloud dependency

### Recommended: Simple VoiceFlow (MVP)
```batch
# Install dependencies (one time)
INSTALL_ENHANCED_DEPS.bat

# Launch VoiceFlow (daily use)
LAUNCH_NOW.bat
```

### How to Use
1. **Run** `LAUNCH_NOW.bat` and choose System Tray mode
2. **Position cursor** in any text field (Notepad, browser, chat, etc.)
3. **Press and hold** `Ctrl+Alt`
4. **Speak clearly** while holding keys
5. **Release keys** when done
6. **Watch text appear** instantly!

### Legacy Options (Original Implementation)
```batch
# Original Electron version
electron\dist\win-unpacked\VoiceFlow.exe

# Original system tray
VoiceFlow-SystemTray.bat
```

## ✨ Features

- 🎙️ **Real-time Voice Transcription** - Press and hold `Ctrl+Alt` anywhere to record
- 🚀 **GPU Accelerated** - Leverages your NVIDIA GPU for blazing fast performance
- 🧠 **AI Enhancement** - DeepSeek formats your transcriptions with proper punctuation
- 📊 **Usage Statistics** - Track your words, sessions, and performance metrics
- 🔒 **100% Private** - Everything runs locally, no data leaves your machine
- 💰 **Completely Free** - No subscriptions, no API costs, just electricity
- 🖥️ **System Tray** - Runs quietly in the background, always ready

## 📦 What's Included

✅ **Electron App** - Fully built executable at `electron\dist\win-unpacked\VoiceFlow.exe`  
✅ **Python Backend** - Whisper + DeepSeek integration ready  
✅ **React Frontend** - Modern UI with real-time updates  
✅ **Launcher Scripts** - Multiple ways to run the app  
✅ **System Tray Support** - PowerShell script with tray icon  
✅ **Test Suite** - Comprehensive testing framework  

## 🏃 Running VoiceFlow

### Prerequisites
- Windows 10/11
- NVIDIA GPU with CUDA support
- 16GB RAM
- Node.js 16+
- Rust (installed automatically during setup)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/voiceflow.git
   cd voiceflow
   ```

2. **Run setup** (first time only)
   ```bash
   setup.bat
   ```

3. **Build the application**
   ```bash
   BUILD.bat
   ```

4. **Run VoiceFlow**
   ```bash
   RUN.bat
   ```

The executable will be available at:
- Release: `src-tauri\target\release\voiceflow.exe`
- Debug: `src-tauri\target\debug\voiceflow.exe`

## 📁 Project Structure

```
VoiceFlow/
├── src/                    # React frontend source
├── src-tauri/             # Rust/Tauri backend
├── python/                # Python STT server
├── scripts/               # Build and utility scripts
├── docs/                  # Documentation
├── BUILD.bat             # Build the application
├── RUN.bat               # Run the application
├── dev.bat               # Development mode
└── setup.bat             # Initial setup
```

## 💻 Development

### Running in Development Mode
```bash
dev.bat
```

This will:
- Start the Python STT server on port 5000
- Launch Tauri in development mode with hot reload
- Open the dev tools console

### Building for Production
```bash
BUILD.bat
```

This creates:
- Standalone executable in `src-tauri\target\release\`
- Installer package in `src-tauri\target\release\bundle\`
- Desktop shortcut (automatic)

### Checking Build Status
```bash
scripts\check-build.bat
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│              VoiceFlow (Tauri App)                  │
├─────────────────────────────────────────────────────┤
│  Frontend (React + Vite)                            │
│  - Real-time transcription display                  │
│  - Statistics dashboard                             │
│  - Settings management                              │
├─────────────────────────────────────────────────────┤
│  Rust Backend (Tauri)                               │
│  - Global hotkey handling (Ctrl+Alt)              │
│  - System tray integration                          │
│  - Native window management                         │
│  - WebSocket client                                 │
├─────────────────────────────────────────────────────┤
│  Python STT Server (localhost:5000)                 │
│  - Whisper.cpp GPU acceleration                     │
│  - WebRTC VAD for voice detection                   │
│  - DeepSeek R1 post-processing                      │
│  - WebSocket server                                 │
└─────────────────────────────────────────────────────┘
```

## 🎯 Key Features

### Global Hotkey System
- **Ctrl+Alt**: Toggle recording from anywhere
- Works even when app is minimized to tray
- Visual indicator when recording

### Dual-Model Approach
1. **Fast Preview**: Small model for real-time feedback
2. **Accurate Final**: Large-v3 model for best quality

### AI Post-Processing
DeepSeek R1 automatically:
- Adds punctuation and capitalization
- Fixes common speech recognition errors
- Formats text into proper paragraphs
- Preserves your speaking style

### Performance Optimization
- GPU acceleration via CUDA
- Efficient memory management
- Background processing
- Minimal CPU usage when idle

## 🛠️ Configuration

Access settings through the system tray icon:
- Whisper model selection (tiny → large-v3)
- Language preferences
- AI enhancement toggle
- Auto-start on Windows boot
- Hotkey customization

## 📊 Performance Benchmarks

| Model    | Speed  | Accuracy | VRAM  | Use Case                    |
|----------|--------|----------|-------|------------------------------|
| Tiny     | 100x   | 39 WER   | 1GB   | Quick notes                 |
| Base     | 80x    | 30 WER   | 1GB   | Casual transcription        |
| Small    | 50x    | 21 WER   | 2GB   | Real-time preview (default) |
| Medium   | 20x    | 15 WER   | 5GB   | High quality                |
| Large-v3 | 10x    | 10 WER   | 10GB  | Best quality (default final)|

*WER = Word Error Rate (lower is better)*

## 🔧 Troubleshooting

### Build Issues
- Run `scripts\check-deps.bat` to verify dependencies
- Ensure Windows Defender isn't blocking Rust
- Try debug build: `npx tauri build --debug`

### Runtime Issues
- Check if Python server is running (port 5000)
- Verify CUDA is properly installed
- Check Windows audio permissions

### Performance Issues
- Lower Whisper model size in settings
- Check GPU usage in Task Manager
- Ensure no other apps are using CUDA

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `npm test`
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OpenAI Whisper](https://github.com/openai/whisper) - Speech recognition models
- [Whisper.cpp](https://github.com/ggerganov/whisper.cpp) - Optimized C++ implementation
- [RealtimeSTT](https://github.com/KoljaB/RealtimeSTT) - Real-time framework
- [Tauri](https://tauri.app/) - Native app framework
- [DeepSeek](https://deepseek.ai/) - AI post-processing

---

**Built with ❤️ to provide a free, private alternative to expensive transcription services!**

*Save $15+/month while getting better performance and complete privacy.*