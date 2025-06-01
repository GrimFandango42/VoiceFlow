#!/usr/bin/env python3
"""
VoiceFlow Quick System Check
ASCII-safe version for Windows testing
"""

import os
import sys
import subprocess
import importlib
import json
import time
import requests
from pathlib import Path

def log(message, level="INFO"):
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def test_dependencies():
    """Test critical dependencies"""
    log("Testing dependencies...")
    
    required = ["pyautogui", "keyboard", "RealtimeSTT", "requests", "websockets"]
    results = {}
    
    for package in required:
        try:
            if package == "RealtimeSTT":
                from RealtimeSTT import AudioToTextRecorder
                results[package] = "INSTALLED"
                log(f"[PASS] {package}")
            else:
                importlib.import_module(package)
                results[package] = "INSTALLED"
                log(f"[PASS] {package}")
        except ImportError:
            results[package] = "MISSING"
            log(f"[FAIL] {package} - MISSING")
    
    return results

def test_ollama():
    """Test Ollama connectivity"""
    log("Testing Ollama service...")
    
    urls = ["http://localhost:11434/api/tags", "http://172.30.248.191:11434/api/tags"]
    
    for url in urls:
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m.get('name', '') for m in models]
                log(f"[PASS] Ollama connected: {url}")
                log(f"[INFO] Models: {', '.join(model_names)}")
                return True, model_names
        except:
            continue
    
    log("[FAIL] Ollama not accessible")
    return False, []

def test_gpu():
    """Test GPU availability"""
    log("Testing GPU...")
    
    try:
        import torch
        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            log(f"[PASS] GPU available: {gpu_name}")
            return True, gpu_name
        else:
            log("[WARN] No GPU - will use CPU")
            return False, "CPU only"
    except:
        log("[WARN] PyTorch not available")
        return False, "Unknown"

def test_files():
    """Test required files exist"""
    log("Testing file structure...")
    
    required_files = [
        "python/stt_server.py",
        "VoiceFlow-Invisible.bat", 
        "VoiceFlow-Native.bat",
        "Install-Native-Mode.bat"
    ]
    
    missing = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing.append(file_path)
            log(f"[FAIL] Missing: {file_path}")
        else:
            log(f"[PASS] Found: {file_path}")
    
    return missing

def main():
    log("VoiceFlow System Check Starting...")
    log("=" * 50)
    
    # Test Python version
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        log(f"[PASS] Python {version.major}.{version.minor}.{version.micro}")
    else:
        log(f"[FAIL] Python version too old")
        return
    
    # Test file structure
    missing_files = test_files()
    
    # Test dependencies
    deps = test_dependencies()
    
    # Test services
    ollama_ok, models = test_ollama()
    gpu_ok, gpu_info = test_gpu()
    
    # Summary
    log("=" * 50)
    log("SUMMARY:")
    
    critical_missing = [k for k, v in deps.items() if v == "MISSING"]
    
    if not missing_files and not critical_missing and ollama_ok:
        log("[READY] System ready for testing!")
        readiness = "READY"
    elif len(critical_missing) <= 1:
        log("[MOSTLY_READY] Minor issues to fix")
        readiness = "MOSTLY_READY"
    else:
        log("[NOT_READY] Major issues need fixing")
        readiness = "NOT_READY"
    
    # Save results
    results = {
        "timestamp": time.time(),
        "readiness": readiness,
        "python_version": f"{version.major}.{version.minor}.{version.micro}",
        "missing_files": missing_files,
        "dependencies": deps,
        "ollama_connected": ollama_ok,
        "available_models": models,
        "gpu_available": gpu_ok,
        "gpu_info": gpu_info
    }
    
    with open("quick_system_check.json", "w") as f:
        json.dump(results, f, indent=2)
    
    log(f"Results saved to quick_system_check.json")
    
    if critical_missing:
        log("NEXT STEP: Run Install-Native-Mode.bat to install missing dependencies")
    
    return results

if __name__ == "__main__":
    os.chdir(Path(__file__).parent)
    main()
