#!/usr/bin/env python3
"""
VoiceFlow Personal Launcher
Quick setup and launch script for personal use
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def check_dependencies():
    """Check if required packages are installed"""
    required = ['RealtimeSTT', 'pyautogui', 'keyboard', 'requests']
    missing = []
    
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    return missing

def install_dependencies():
    """Install missing dependencies"""
    print("🔧 Installing VoiceFlow Personal dependencies...")
    
    # Install from requirements file
    result = subprocess.run([
        sys.executable, '-m', 'pip', 'install', '-r', 'requirements_personal.txt'
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ Installation failed: {result.stderr}")
        return False
    
    print("✅ Dependencies installed successfully")
    return True

def check_ollama():
    """Check if Ollama is available for AI enhancement"""
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code == 200:
            models = response.json().get('models', [])
            model_names = [m.get('name', '') for m in models]
            print(f"🤖 Ollama detected with models: {model_names}")
            return True
    except:
        pass
    
    print("⚠️  Ollama not detected - will use basic formatting")
    print("   💡 Install Ollama for AI enhancement: https://ollama.ai")
    return False

def check_gpu():
    """Check GPU availability"""
    try:
        import torch
        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            print(f"🎮 GPU detected: {gpu_name}")
            return True
    except ImportError:
        pass
    
    print("💻 Using CPU mode")
    print("   💡 Install torch with CUDA for GPU acceleration")
    return False

def main():
    """Main launcher"""
    print("🚀 VoiceFlow Personal Launcher")
    print("=" * 40)
    
    # Check current directory
    if not Path("voiceflow_personal.py").exists():
        print("❌ voiceflow_personal.py not found")
        print("   Please run from the VoiceFlow directory")
        return 1
    
    # Check dependencies
    missing = check_dependencies()
    if missing:
        print(f"⚠️  Missing dependencies: {missing}")
        response = input("Install automatically? (y/n): ").lower().strip()
        
        if response == 'y':
            if not install_dependencies():
                return 1
        else:
            print("❌ Cannot continue without dependencies")
            return 1
    
    print("✅ All dependencies available")
    
    # System checks
    print("\n🔍 System Analysis:")
    check_gpu()
    check_ollama()
    
    # Launch options
    print("\n🎯 Launch Options:")
    print("1. Standard mode (recommended)")
    print("2. Debug mode (verbose output)")
    print("3. CPU-only mode (force CPU)")
    print("4. Setup only (install dependencies)")
    
    choice = input("\nSelect option (1-4) [1]: ").strip() or "1"
    
    if choice == "4":
        print("✅ Setup complete - run again to start VoiceFlow")
        return 0
    
    # Set environment variables based on choice
    env = os.environ.copy()
    
    if choice == "2":
        env['VOICEFLOW_DEBUG'] = '1'
        print("🐛 Debug mode enabled")
    elif choice == "3":
        env['CUDA_VISIBLE_DEVICES'] = ''
        print("💻 CPU-only mode forced")
    
    # Launch VoiceFlow Personal
    print("\n🎉 Starting VoiceFlow Personal...")
    print("💡 Press Ctrl+C to stop")
    time.sleep(1)
    
    try:
        result = subprocess.run([
            sys.executable, 'voiceflow_personal.py'
        ], env=env)
        return result.returncode
    except KeyboardInterrupt:
        print("\n👋 VoiceFlow Personal stopped by user")
        return 0
    except Exception as e:
        print(f"❌ Launch failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main())