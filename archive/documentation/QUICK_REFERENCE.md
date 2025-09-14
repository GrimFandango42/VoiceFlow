# VoiceFlow Quick Reference

## 🚀 Quick Commands
| Action | Command |
|--------|---------|
| Build app | `BUILD.bat` |
| Run app | `RUN.bat` |
| Development mode | `dev.bat` |
| Initial setup | `setup.bat` |

## ⌨️ Keyboard Shortcuts
| Shortcut | Action |
|----------|---------|
| `Ctrl+Alt` | Toggle recording |
| `Ctrl+Alt+V` | Show/hide window |
| `Ctrl+Alt+S` | Quick settings |

## 📁 Project Structure
```
VoiceFlow/
├── BUILD.bat          # Build production app
├── RUN.bat            # Run the application  
├── dev.bat            # Development mode
├── setup.bat          # First-time setup
├── src/               # Frontend code
├── src-tauri/         # Backend code
├── python/            # STT server
├── scripts/           # Utility scripts
│   ├── build.bat      # Full build script
│   ├── run.bat        # App launcher
│   ├── check-build.bat # Build status
│   └── check-deps.bat  # Check dependencies
└── docs/              # Documentation
    ├── ARCHITECTURE.md # Technical details
    ├── BUILD_GUIDE.md  # Build instructions
    ├── USER_GUIDE.md   # User manual
    └── CONTRIBUTING.md # Contribution guide
```

## 🎯 Common Tasks

### Check Build Status
```bash
scripts\check-build.bat
```

### Check Dependencies  
```bash
scripts\check-deps.bat
```

### Clean Project
```bash
scripts\cleanup.bat
```

## 📍 Output Locations
- **Executable**: `src-tauri\target\release\voiceflow.exe`
- **Debug Build**: `src-tauri\target\debug\voiceflow.exe`
- **Installer**: `src-tauri\target\release\bundle\`

## 🔧 Configuration Files
- **Tauri Config**: `src-tauri\tauri.conf.json`
- **Package Info**: `package.json`
- **Python Server**: `python\config.py`

## 📚 Documentation
- [User Guide](docs/USER_GUIDE.md) - How to use VoiceFlow
- [Architecture](docs/ARCHITECTURE.md) - Technical overview  
- [Build Guide](docs/BUILD_GUIDE.md) - Build instructions
- [Contributing](docs/CONTRIBUTING.md) - How to contribute

## 💡 Tips
1. First build takes 5-15 minutes (compiling Rust)
2. Subsequent builds are much faster
3. Use `dev.bat` for testing changes
4. Check `scripts\` folder for utilities

## ❓ Need Help?
1. Check [User Guide](docs/USER_GUIDE.md)
2. Run `scripts\check-deps.bat` for issues
3. See [Troubleshooting](docs/USER_GUIDE.md#troubleshooting)