# VoiceFlow - How to Launch Guide

## 🚀 Quick Launch Options

VoiceFlow offers **3 main ways** to launch:

### Option 1: Control Center (Recommended)
**Double-click:** `tools/launchers/LAUNCH_CONTROL_CENTER.bat`
- ✅ Full GUI control interface
- ✅ Real-time status monitoring
- ✅ Easy configuration management
- ✅ Performance metrics display
- ✅ System diagnostics and validation

### Option 2: Enhanced Tray Mode
**Double-click:** `START_VOICEFLOW.bat`
- ✅ System tray icon with visual indicators
- ✅ Real-time transcription feedback
- ✅ Quick access to settings
- ✅ Background operation mode

### Option 3: Terminal Mode (Debugging)
**Double-click:** `LAUNCH_VOICEFLOW.bat`
- ✅ Terminal output with detailed logs
- ✅ No visual indicators
- ✅ Good for troubleshooting
- ✅ Performance monitoring output

## 🔧 Manual Launch (Advanced)

If batch files don't work, use command line:

```bash
# Control Center (Recommended)
cd C:\AI_Projects\VoiceFlow
python tools/VoiceFlow_Control_Center.py

# Enhanced Tray Mode
cd C:\AI_Projects\VoiceFlow
venv/Scripts/python.exe -c "
import sys
sys.path.insert(0, 'src')
from voiceflow.ui.enhanced_tray import main
main()
"

# Terminal Mode
cd C:\AI_Projects\VoiceFlow
venv/Scripts/python.exe -c "
import sys
sys.path.insert(0, 'src')
from voiceflow.ui.cli_ultra_performance import main
main()
"
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