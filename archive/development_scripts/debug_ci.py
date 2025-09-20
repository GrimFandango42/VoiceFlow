#!/usr/bin/env python3
"""
Debug script to understand what's happening in CI
"""

import sys
import os
from pathlib import Path

def main():
    print("=== CI DEBUG INFORMATION ===")
    print(f"Python version: {sys.version}")
    print(f"Python executable: {sys.executable}")
    print(f"Current working directory: {os.getcwd()}")
    print(f"Current user: {os.getenv('USER', 'unknown')}")
    
    print("\n=== ENVIRONMENT VARIABLES ===")
    for key, value in sorted(os.environ.items()):
        if any(keyword in key.upper() for keyword in ['PYTHON', 'PATH', 'HOME', 'GITHUB', 'RUNNER']):
            print(f"{key}: {value}")
    
    print("\n=== FILE STRUCTURE ===")
    cwd = Path.cwd()
    print(f"Files in {cwd}:")
    for item in sorted(cwd.iterdir())[:20]:  # Limit to first 20 items
        print(f"  {item.name} ({'dir' if item.is_dir() else 'file'})")
    
    print("\n=== PYTHON PATH ===")
    for i, path in enumerate(sys.path[:10]):  # Limit to first 10 paths
        print(f"  {i}: {path}")
    
    print("\n=== TRYING IMPORTS ===")
    try:
        import yaml
        print("✅ yaml import successful")
    except Exception as e:
        print(f"❌ yaml import failed: {e}")
    
    try:
        import psutil
        print("✅ psutil import successful")
    except Exception as e:
        print(f"❌ psutil import failed: {e}")
    
    print("\n=== CHECKING UTILS MODULE ===")
    utils_path = Path("utils")
    print(f"utils directory exists: {utils_path.exists()}")
    if utils_path.exists():
        print("Contents of utils/:")
        for item in utils_path.iterdir():
            print(f"  {item.name}")
    
    print("\n=== TRYING UTILS.CONFIG IMPORT ===")
    try:
        sys.path.insert(0, str(Path.cwd()))
        from utils.config import VoiceFlowConfig
        print("✅ utils.config import successful")
        
        # Try to create config
        config = VoiceFlowConfig()
        print("✅ VoiceFlowConfig creation successful")
        
        # Try to access config
        model = config.get('audio', 'model')
        print(f"✅ Config access successful, model: {model}")
        
    except Exception as e:
        print(f"❌ utils.config failed: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
    
    print("\n=== END DEBUG ===")

if __name__ == "__main__":
    main()