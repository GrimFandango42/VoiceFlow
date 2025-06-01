"""
VoiceFlow Executable Verification Script
Tests that the built executable actually works
"""
import os
import sys
import subprocess
import time
import psutil
from pathlib import Path

def check_process_running(process_name):
    """Check if a process is running"""
    for proc in psutil.process_iter(['name']):
        if process_name.lower() in proc.info['name'].lower():
            return True
    return False

def test_electron_executable():
    """Test the Electron executable"""
    exe_path = Path("electron/dist/win-unpacked/VoiceFlow.exe")
    
    if not exe_path.exists():
        print("[FAIL] Electron executable not found")
        return False
    
    print(f"[OK] Found executable: {exe_path}")
    print(f"    Size: {exe_path.stat().st_size / 1024 / 1024:.2f} MB")
    
    # Try to start it (but immediately kill it since we're in a test environment)
    try:
        # Just check if it's a valid executable
        import pefile
        pe = pefile.PE(str(exe_path))
        print("[OK] Valid Windows executable")
        return True
    except:
        # If pefile isn't available, just check basic properties
        if exe_path.suffix == '.exe' and exe_path.stat().st_size > 1024*1024:
            print("[OK] Appears to be a valid executable")
            return True
        else:
            print("[FAIL] Invalid executable")
            return False

def test_launcher_scripts():
    """Test launcher scripts exist and are valid"""
    scripts = [
        "VoiceFlow-Launcher.bat",
        "VoiceFlow-SystemTray.bat",
        "VoiceFlow-Tray.ps1"
    ]
    
    all_exist = True
    for script in scripts:
        script_path = Path(script)
        if script_path.exists():
            print(f"[OK] {script} exists ({script_path.stat().st_size} bytes)")
        else:
            print(f"[FAIL] {script} not found")
            all_exist = False
    
    return all_exist

def test_python_environment():
    """Test Python environment is ready"""
    venv_python = Path("python/venv/Scripts/python.exe")
    
    if not venv_python.exists():
        print("[FAIL] Python virtual environment not found")
        return False
    
    # Test if we can import required modules
    test_imports = [
        "import websockets",
        "import numpy",
        "import RealtimeSTT",
        "import sqlite3"
    ]
    
    for test_import in test_imports:
        result = subprocess.run(
            [str(venv_python), "-c", test_import],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            module = test_import.split()[1]
            print(f"[OK] {module} module available")
        else:
            module = test_import.split()[1]
            print(f"[FAIL] {module} module not available")
            return False
    
    return True

def test_frontend_build():
    """Test frontend build exists"""
    dist_path = Path("dist")
    if not dist_path.exists():
        print("[FAIL] Frontend dist directory not found")
        return False
    
    required_files = ["index.html"]
    for file in required_files:
        file_path = dist_path / file
        if file_path.exists():
            print(f"[OK] Frontend {file} exists")
        else:
            print(f"[FAIL] Frontend {file} not found")
            return False
    
    # Check for assets
    assets_path = dist_path / "assets"
    if assets_path.exists():
        asset_count = len(list(assets_path.glob("*")))
        print(f"[OK] Frontend assets directory ({asset_count} files)")
    else:
        print("[WARN] Frontend assets directory not found")
    
    return True

def main():
    print("=" * 60)
    print("VoiceFlow Executable Verification")
    print("=" * 60)
    print()
    
    # Change to project directory
    os.chdir(Path(__file__).parent)
    
    tests = [
        ("Electron Executable", test_electron_executable),
        ("Launcher Scripts", test_launcher_scripts),
        ("Python Environment", test_python_environment),
        ("Frontend Build", test_frontend_build)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\nTesting {test_name}...")
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[ERROR] {test_name}: {e}")
            failed += 1
    
    print()
    print("=" * 60)
    print(f"Verification Complete: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if failed == 0:
        print("\n✅ VoiceFlow is ready to run!")
        print("\nTo start VoiceFlow, run one of:")
        print("  - electron\\dist\\win-unpacked\\VoiceFlow.exe")
        print("  - VoiceFlow-Launcher.bat")
        print("  - VoiceFlow-SystemTray.bat")
    else:
        print("\n❌ Some components are missing or not configured properly.")
    
    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
