# Changelog

All notable changes to VoiceFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-05-31

### Added
- Initial release of VoiceFlow
- Real-time voice transcription with Whisper
- System tray integration
- Global hotkey support (Ctrl+Alt+Space)
- GPU acceleration via CUDA
- DeepSeek AI post-processing
- Dual-model approach (preview + final)
- Statistics tracking
- Auto-text injection
- Settings management
- Windows native app using Tauri

### Features
- 100% local processing
- No internet required
- Zero cost operation
- Complete privacy
- Multiple Whisper model support
- WebSocket-based architecture
- React frontend with Vite
- Rust backend for performance

### Technical
- Tauri 1.6.3 framework
- React 18.3.1
- Whisper.cpp integration
- Python 3.10+ STT server
- WebRTC VAD
- CUDA GPU acceleration

## [Unreleased]

### Planned
- [ ] Custom hotkey configuration UI
- [ ] Multiple language support
- [ ] Export transcription history
- [ ] Voice commands
- [ ] Theme customization
- [ ] Punctuation training
- [ ] Speaker diarization
- [ ] Audio file transcription
- [ ] Integration with other apps
- [ ] Cloud backup (optional, encrypted)

## [1.1.0] - 2025-06-01

### 🎯 Changed
- **BREAKING CHANGE**: Default hotkey changed from `Ctrl+Alt+Space` to `Ctrl+Alt` for better accessibility
- Updated all documentation to reflect new hotkey configuration

### 🧹 Removed
- Cleaned up project structure by removing 15+ unnecessary files
- Removed duplicate launcher scripts (VoiceFlow-Enhanced.bat, VoiceFlow-Working.bat, etc.)
- Removed debug files (comprehensive_test_and_fix.py, debug_enhanced.py, etc.)
- Removed old test outputs (frontend_test_results.json, test_results.json)
- Removed unused utilities (VoiceFlow.ahk, rustup-init.exe)

### ✅ Added
- END_USER_TEST.bat for final verification
- Comprehensive documentation updates
- Enhanced testing and verification scripts

### 🔧 Fixed
- Streamlined project organization for better maintainability
- Updated architecture documentation
- Enhanced user guides with correct hotkey information

### 📦 Production Ready
- ✅ Working Electron executable (193MB) 
- ✅ Python backend with full STT pipeline
- ✅ System hotkey integration (Ctrl+Alt)
- ✅ Auto text injection at cursor
- ✅ Comprehensive documentation
- ✅ End-user testing verified