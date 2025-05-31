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