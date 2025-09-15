# VoiceFlow - How to Launch Guide

## 🚀 Quick Launch Options

VoiceFlow has been cleaned up and simplified to **2 main ways** to launch:

### Option 1: Visual Mode (Recommended)
**Double-click:** `LAUNCH_TRAY.bat`
- ✅ System tray icon with status colors
- ✅ Bottom-screen overlay (Wispr Flow-style)  
- ✅ Visual feedback for transcription states
- ✅ Can minimize to background
- ✅ Right-click tray for settings menu

### Option 2: Terminal Mode (Debugging)
**Double-click:** `LAUNCH_TERMINAL.bat`
- ✅ Terminal output only
- ✅ No visual indicators 
- ✅ Good for troubleshooting
- ✅ Shows detailed logs

## 🔧 Manual Launch (Advanced)

If batch files don't work, use command line:

```bash
# Visual mode
cd C:\AI_Projects\VoiceFlow
python -m localflow.cli_enhanced

# Terminal mode
cd C:\AI_Projects\VoiceFlow  
python -m localflow.cli_enhanced --no-tray
```

## 📋 Requirements Check

Before launching, ensure you have:

```bash
# Install dependencies
pip install -r requirements_windows.txt

# Verify installation
python verify_visual_system.py
```

## 🎮 How to Use

1. **Launch** using one of the methods above
2. **Press and hold** your hotkey to record (default: `Ctrl+Shift+Space`)
3. **Speak** while holding the key
4. **Release** key to stop recording and transcribe
5. **Text appears** automatically in your active window

## ⚙️ Configuration

### Hotkey Options (Right-click tray):
- `Ctrl+Shift+Space` (default)
- `Ctrl+Alt+Space`  
- `Ctrl+Space`
- `Alt+Space`
- `Ctrl+Alt` (no key)

### Settings Toggle (Keyboard shortcuts):
- `Ctrl+Alt+C` - Toggle code mode
- `Ctrl+Alt+P` - Toggle paste/type mode
- `Ctrl+Alt+Enter` - Toggle auto-enter

## 🏗️ Project Structure (Cleaned)

```
VoiceFlow/
├── LAUNCH_TRAY.bat          # Visual mode launcher ⭐
├── LAUNCH_TERMINAL.bat      # Terminal mode launcher ⭐  
├── README.md                # Project overview
├── requirements_windows.txt # Dependencies
├── verify_visual_system.py  # System test
├── localflow/              # Main package
│   ├── cli_enhanced.py     # Enhanced CLI with visuals
│   ├── visual_indicators.py # Bottom overlay system
│   ├── enhanced_tray.py    # Tray icon system
│   └── ...                 # Other core modules
├── tests/comprehensive/     # Full test suite
└── archive/                # Old files (cleaned up)
    ├── test_scripts/       # Archived tests  
    ├── documentation/      # Old docs
    └── old_launchers/      # Old batch files
```

## 🧪 Testing

### Quick Verification:
```bash
python verify_visual_system.py
```

### Comprehensive Testing:
```bash
python run_comprehensive_tests.py
```

**⚠️ WARNING**: Comprehensive tests reveal critical stability issues. See `CRITICAL_GUARDRAILS_NEEDED.md` for details.

## 🐛 Test Results Summary

### ✅ Working:
- Basic transcription workflow  
- Visual indicators (overlay + tray)
- System tray integration
- Configuration persistence
- Short audio processing

### 🚨 Known Issues:
- **Edge cases cause crashes** (10/40 tests failed)
- **Extreme inputs crash Whisper** (NaN, Inf values)
- **Thread safety issues** with visual updates
- **Memory leaks** in long sessions  
- **Integration tests cause segfaults**

## 🛡️ Stability Recommendations

**For Production Use:**
1. **Implement critical guardrails** from `CRITICAL_GUARDRAILS_NEEDED.md`
2. **Avoid extreme inputs** (very long recordings, unusual sample rates)
3. **Monitor memory usage** during long sessions
4. **Use Terminal mode** for debugging issues

**For Development:**
1. **Run comprehensive tests** before changes
2. **Test edge cases** with new features
3. **Monitor thread safety** in visual components

## 🎯 Status Summary

- ✅ **Visual System**: Working with Wispr Flow-style overlay
- ✅ **Core Functionality**: Transcription works for normal usage  
- ✅ **Repository Cleanup**: Organized and external-ready
- ⚠️  **Stability**: Needs guardrails for production use
- 🔄 **Comprehensive Testing**: Revealed critical issues requiring fixes

## 🚀 Ready to Launch!

**For immediate use:** `LAUNCH_TRAY.bat`  
**For development:** `LAUNCH_TERMINAL.bat`  
**For production:** Implement guardrails first