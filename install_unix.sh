#!/bin/bash
# VoiceFlow Unix Installer
# Automated installation and setup for Linux/macOS

set -e

echo "====================================="
echo "VoiceFlow Unix Installer"
echo "====================================="
echo

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM=Linux;;
    Darwin*)    PLATFORM=macOS;;
    *)          PLATFORM="Unknown";;
esac

echo "[INFO] Detected platform: $PLATFORM"

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 not found. Please install Python 3.8+ first"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "  CentOS/RHEL: sudo yum install python3 python3-pip"
    echo "  macOS: brew install python3"
    exit 1
fi

echo "[INFO] Python found: $(python3 --version)"

# Check pip
if ! command -v pip3 &> /dev/null; then
    echo "[ERROR] pip3 not found. Installing pip..."
    python3 -m ensurepip --upgrade
fi

# Install system dependencies for Linux
if [[ "$PLATFORM" == "Linux" ]]; then
    echo "[INFO] Installing system dependencies for Linux..."
    
    # Detect package manager
    if command -v apt &> /dev/null; then
        echo "[INFO] Using apt package manager"
        sudo apt update
        sudo apt install -y python3-dev python3-pip python3-tk portaudio19-dev
        # For system tray support
        sudo apt install -y python3-xlib scrot
    elif command -v yum &> /dev/null; then
        echo "[INFO] Using yum package manager"
        sudo yum install -y python3-devel python3-pip python3-tkinter portaudio-devel
    elif command -v dnf &> /dev/null; then
        echo "[INFO] Using dnf package manager"
        sudo dnf install -y python3-devel python3-pip python3-tkinter portaudio-devel
    else
        echo "[WARNING] Unknown package manager. Some dependencies may need manual installation"
    fi
fi

# Install Python dependencies
echo "[INFO] Installing VoiceFlow dependencies..."
python3 -m pip install --user -r requirements_unix.txt

if [[ $? -ne 0 ]]; then
    echo "[ERROR] Failed to install Python dependencies"
    exit 1
fi

# Make scripts executable
chmod +x voiceflow_unix.py

# Create desktop entry for Linux
if [[ "$PLATFORM" == "Linux" ]] && [[ -d "$HOME/.local/share/applications" ]]; then
    echo "[INFO] Creating desktop entry..."
    
    cat > "$HOME/.local/share/applications/voiceflow.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=VoiceFlow
Comment=Local Voice Transcription System
Exec=python3 $(pwd)/voiceflow_unix.py --tray
Icon=audio-input-microphone
Terminal=false
StartupNotify=true
Categories=Utility;Audio;Office;
EOF
    
    echo "[INFO] Desktop entry created"
fi

# Create launcher script
cat > voiceflow << 'EOF'
#!/bin/bash
# VoiceFlow launcher script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
python3 voiceflow_unix.py "$@"
EOF

chmod +x voiceflow

echo
echo "[SUCCESS] VoiceFlow installed successfully!"
echo
echo "Quick Start:"
echo "  Console Mode: ./voiceflow --console"
echo "  Tray Mode:    ./voiceflow --tray"
echo "  Daemon Mode:  ./voiceflow --daemon"
echo
echo "Or use directly:"
echo "  python3 voiceflow_unix.py --console"
echo
if [[ "$PLATFORM" == "Linux" ]]; then
    echo "Desktop application available in your applications menu"
fi
echo
echo "Installation complete!"