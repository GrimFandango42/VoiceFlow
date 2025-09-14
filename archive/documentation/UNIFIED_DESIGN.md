# VoiceFlow Unified Design

## Overview

Single VoiceFlow application with mode-based operation via command-line flags:

- **VoiceFlow** (default): Full-featured with tray, advanced options
- **VoiceFlow Lite**: Minimal, fast, CPU-optimized

## Unified Entry Points

### Primary Entry Point: `voiceflow.py`
```bash
# Full VoiceFlow (default)
python voiceflow.py

# VoiceFlow Lite mode  
python voiceflow.py --lite

# Specific configurations
python voiceflow.py --model=base.en --device=cpu
python voiceflow.py --lite --model=tiny.en
python voiceflow.py --no-tray --model=large-v3-turbo
```

### Mode-Based Configuration

**Default Mode (Full VoiceFlow)**:
```python
DEFAULT_CONFIG = {
    "model_name": "large-v3-turbo",
    "device": "cuda",  # with CPU fallback
    "enable_tray": True,
    "enable_streaming": True,
    "enable_batching": True,
    "features": ["advanced_vad", "code_mode", "clipboard_restore"]
}
```

**Lite Mode**:
```python
LITE_CONFIG = {
    "model_name": "base.en",  # or tiny.en for ultra-lite
    "device": "cpu", 
    "enable_tray": False,
    "enable_streaming": False,
    "enable_batching": False,
    "features": ["basic_transcription"]
}
```

## Simplified File Structure

```
VoiceFlow/
├── voiceflow.py           # 🎯 Unified entry point
├── voiceflow_tray.py      # 🎯 Tray launcher (calls voiceflow.py --tray)
├── config/
│   ├── default.py         # Full VoiceFlow config
│   ├── lite.py            # Lite mode config  
│   └── profiles.py        # Speed/Accuracy/Balanced profiles
├── core/                  # Unified core functionality
│   ├── transcription/     # ASR engines
│   ├── audio/             # Audio processing
│   ├── ui/                # User interface components
│   └── utils/             # Shared utilities
├── tests/                 # Essential tests only
├── docs/                  # Documentation
├── scripts/               # Setup and build scripts
└── archive/               # ✅ Archived development artifacts
```

## Command-Line Interface

```bash
python voiceflow.py [OPTIONS]

OPTIONS:
  --lite                    Enable lite mode (minimal features)
  --model MODEL            Whisper model (tiny.en, base.en, large-v3-turbo)
  --device DEVICE          Processing device (auto, cpu, cuda)
  --profile PROFILE        Preset profile (speed, accuracy, balanced)
  --no-tray                Disable system tray
  --hotkey HOTKEY          Custom hotkey (ctrl+shift+space)
  --config FILE            Custom config file
  --version                Show version
  --help                   Show help message

EXAMPLES:
  voiceflow.py                              # Full VoiceFlow
  voiceflow.py --lite                       # VoiceFlow Lite
  voiceflow.py --model=tiny.en --device=cpu # Ultra-light mode
  voiceflow.py --profile=speed              # Speed-optimized
  voiceflow.py --profile=accuracy           # Accuracy-optimized
```

## Installation Scripts

### Windows: `LAUNCH_VOICEFLOW.bat`
```batch
@echo off
echo VoiceFlow - AI Voice Transcription
echo ===================================
echo [1] VoiceFlow (Full)
echo [2] VoiceFlow Lite  
echo [3] Ultra-Light Mode
set /p choice="Select mode (1-3): "

if "%choice%"=="1" python voiceflow.py
if "%choice%"=="2" python voiceflow.py --lite  
if "%choice%"=="3" python voiceflow.py --lite --model=tiny.en --device=cpu
```

### Quick Launchers
- `voiceflow.py` - Full mode (default)
- `voiceflow.py --lite` - Lite mode
- `voiceflow_tray.py` - System tray launcher

## Benefits of Unified Design

1. **Simplified Structure**: One codebase, multiple modes
2. **Easy Deployment**: Single entry point with clear options
3. **User Choice**: Runtime selection of features vs performance
4. **Maintainability**: No duplicate code between LocalFlow/VoiceFlow
5. **Clear Branding**: VoiceFlow with Lite option

## Migration Strategy

1. ✅ Keep existing `localflow/` and `voiceflow/` packages for compatibility
2. 🎯 Create unified `voiceflow.py` entry point
3. 📋 Add command-line argument parsing
4. 📋 Implement mode-based configuration loading
5. 📋 Update documentation and README
6. 📋 Test all entry points and modes

This unified design gives users the best of both worlds: full features when needed, lightweight performance when desired, all through simple command-line flags.