# VoiceFlow - AI Voice Transcription

Real-time speech-to-text with visual indicators and system tray integration.

## 🚀 Quick Start

### Option 1: Tray Mode (Recommended)
```bash
# Double-click or run:
LAUNCH_TRAY.bat
```
- System tray icon with status colors
- Bottom-screen overlay (similar to Wispr Flow)
- Visual feedback for all transcription states
- Can minimize to background

### Option 2: Terminal Mode
```bash
# Double-click or run:
LAUNCH_TERMINAL.bat
```
- Terminal output only
- No visual indicators
- Good for debugging

## ✨ Features

- **Real-time transcription** using OpenAI Whisper
- **Visual indicators** with bottom-screen overlay
- **System tray integration** with status colors
- **Long conversation support** (up to 30 seconds per recording)
- **Enhanced thread management** for stability
- **Configurable hotkeys** for push-to-talk

## 🎯 Visual Status System

- 🔵 **Blue**: Ready/Idle
- 🟠 **Orange**: Listening (recording active)
- 🟢 **Green**: Processing/Transcribing
- 🔴 **Red**: Error states

## 🔧 Requirements

```bash
pip install -r requirements_windows.txt
```

## 📁 Project Structure

- **`localflow/`** - Main package with enhanced functionality
- **`LAUNCH_TRAY.bat`** - Tray mode launcher (visual indicators)
- **`LAUNCH_TERMINAL.bat`** - Terminal mode launcher (no visuals)
- **`archive/`** - Archived test files and documentation
- **`verify_visual_system.py`** - System verification script

## 🧪 Testing

```bash
python verify_visual_system.py
```

## 📊 Status

✅ **Visual indicators system** - Complete  
✅ **Repository cleanup** - Complete  
🔄 **Executable packaging** - Pending

---

*VoiceFlow with enhanced visual feedback system*