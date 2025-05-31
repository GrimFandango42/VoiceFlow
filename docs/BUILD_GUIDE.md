# VoiceFlow Build Guide

## Quick Start

1. **Check Prerequisites**
   ```
   CHECK_PREREQUISITES.bat
   ```

2. **Build the App**
   ```
   COMPLETE_BUILD.bat
   ```

## Manual Build Steps

If you prefer to build manually:

### 1. Install Dependencies

#### Rust
- Download from https://rustup.rs/
- Run the installer
- Restart your terminal

#### Node.js
- Download from https://nodejs.org/
- Install LTS version

#### Microsoft C++ Build Tools (if needed)
- Download from https://visualstudio.microsoft.com/visual-cpp-build-tools/
- Install "Desktop development with C++"

### 2. Build Commands

```bash
# Install Node dependencies
npm install

# Build frontend
npm run build

# Build Tauri app
npm run tauri build
```

## Output Locations

After successful build:
- **Executable**: `src-tauri\target\release\voiceflow.exe`
- **Installer**: `src-tauri\target\release\bundle\`
- **Desktop Shortcut**: Created automatically

## Troubleshooting

### Build Fails
1. Run `CHECK_PREREQUISITES.bat` to verify all dependencies
2. Try debug build: `npm run tauri build -- --debug`
3. Check `src-tauri\target\release\` for error logs

### Missing Dependencies
- Rust: Required for Tauri backend
- Node.js: Required for frontend build
- C++ Build Tools: Required for native modules
- WebView2: Usually pre-installed with Windows

### Development Mode
For development without building:
```
dev.bat
```

This runs the app in development mode with hot reload.