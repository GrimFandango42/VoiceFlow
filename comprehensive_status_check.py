#!/usr/bin/env python3
"""
VoiceFlow Comprehensive Status Check
Quick test of all critical components
"""

import os
import sys
from pathlib import Path

def check_file_exists(file_path, description):
    """Check if a file exists and return status"""
    path = Path(file_path)
    exists = path.exists()
    size = ""
    if exists and path.is_file():
        size_bytes = path.stat().st_size
        if size_bytes > 1024*1024:
            size = f" ({size_bytes/(1024*1024):.1f}MB)"
        else:
            size = f" ({size_bytes/(1024):.1f}KB)"
    
    status = "[OK]" if exists else "[MISSING]"
    print(f"{status} {description}: {file_path}{size}")
    return exists

def check_directory_exists(dir_path, description):
    """Check if a directory exists and return status"""
    path = Path(dir_path)
    exists = path.exists() and path.is_dir()
    status = "[OK]" if exists else "[MISSING]"
    print(f"{status} {description}: {dir_path}")
    return exists

def main():
    print("=" * 60)
    print("VoiceFlow Comprehensive Status Check")
    print("=" * 60)
    
    # Base directory - handle both Windows and WSL paths
    base_dirs = [
        Path("C:/AI_Projects/VoiceFlow"),
        Path("/mnt/c/AI_Projects/VoiceFlow"),
        Path(".")  # Current directory
    ]
    
    base_dir = None
    for bd in base_dirs:
        if bd.exists():
            base_dir = bd
            break
    
    if not base_dir:
        print(f"[ERROR] Base directory not found in any of: {[str(bd) for bd in base_dirs]}")
        return
    
    print(f"\nBase Directory: {base_dir.absolute()}")
    print("-" * 40)
    
    # Critical files
    critical_files = [
        ("VoiceFlow-Launcher.bat", "Main launcher script"),
        ("voiceflow_frontend.html", "Web frontend"),
        ("README.md", "Documentation"),
        ("package.json", "Node.js configuration"),
    ]
    
    print("\nCritical Files:")
    all_critical_files_exist = True
    for filename, description in critical_files:
        if not check_file_exists(base_dir / filename, description):
            all_critical_files_exist = False
    
    # Python backend
    print("\nPython Backend:")
    python_files = [
        ("python/stt_server.py", "STT Server"),
        ("python/requirements.txt", "Python requirements"),
    ]
    
    all_python_files_exist = True
    for filename, description in python_files:
        if not check_file_exists(base_dir / filename, description):
            all_python_files_exist = False
    
    # Check Python virtual environment
    venv_python = base_dir / "python/venv/Scripts/python.exe"
    venv_exists = check_file_exists(venv_python, "Python virtual environment")
    
    # Native component
    print("\nNative Components:")
    native_files = [
        ("native/voiceflow_native.py", "Native Windows service"),
        ("native/speech_processor.py", "Speech processor"),
    ]
    
    all_native_files_exist = True
    for filename, description in native_files:
        if not check_file_exists(base_dir / filename, description):
            all_native_files_exist = False
    
    # Directories
    print("\nDirectories:")
    essential_dirs = [
        ("src", "Source code"),
        ("python", "Python backend"),
        ("native", "Native components"),
        ("docs", "Documentation"),
    ]
    
    all_dirs_exist = True
    for dirname, description in essential_dirs:
        if not check_directory_exists(base_dir / dirname, description):
            all_dirs_exist = False
    
    # Test for Unicode issues
    print("\nUnicode Check:")
    unicode_test_files = [
        "voiceflow_frontend.html",
        "test_final.py",
        "python/stt_server.py",
        "native/voiceflow_native.py"
    ]
    
    unicode_issues = []
    for filename in unicode_test_files:
        file_path = base_dir / filename
        if file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Check for problematic Unicode characters
                    if any(char in content for char in ['🎙️', '✅', '❌', '⚠️']):
                        unicode_issues.append(filename)
            except Exception as e:
                print(f"[WARNING] Could not check {filename}: {e}")
    
    if unicode_issues:
        print("[WARNING] Unicode symbols found in:")
        for file in unicode_issues:
            print(f"  - {file}")
    else:
        print("[OK] No problematic Unicode symbols found")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    issues = []
    if not all_critical_files_exist:
        issues.append("Missing critical files")
    if not all_python_files_exist:
        issues.append("Missing Python backend files")
    if not venv_exists:
        issues.append("Python virtual environment not found")
    if not all_native_files_exist:
        issues.append("Missing native component files")
    if not all_dirs_exist:
        issues.append("Missing essential directories")
    if unicode_issues:
        issues.append("Unicode encoding issues")
    
    if issues:
        print("[ISSUES FOUND]")
        for issue in issues:
            print(f"  - {issue}")
        print(f"\nTotal Issues: {len(issues)}")
    else:
        print("[SUCCESS] All components appear to be in place!")
        print("\nReady for end-to-end testing")
    
    print("\nNext Steps:")
    if issues:
        print("1. Address the issues listed above")
        print("2. Run end-to-end test")
        print("3. Create GitHub PR")
    else:
        print("1. Run end-to-end test: python comprehensive_end_to_end_test.py")
        print("2. Create GitHub PR if tests pass")

if __name__ == "__main__":
    main()
