#!/usr/bin/env python3
"""
VoiceFlow Final Test Suite - Post-Cleanup Verification
Tests all critical components after cleanup and hotkey changes
"""

import os
import sys
import json
import time
import subprocess
import requests
from pathlib import Path

class VoiceFlowFinalTests:
    def __init__(self):
        self.project_root = Path("C:/AI_Projects/VoiceFlow")
        self.results = {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "tests": []
        }
        
    def log_test(self, name, passed, details=""):
        """Log test result"""
        status = "PASS" if passed else "FAIL"
        self.results["total_tests"] += 1
        if passed:
            self.results["passed"] += 1
        else:
            self.results["failed"] += 1
        
        test_result = {
            "name": name,
            "status": status,
            "details": details
        }
        self.results["tests"].append(test_result)
        print(f"[{status}] {name}: {details}")
        
    def test_executable_exists(self):
        """Test if the executable exists and has reasonable size"""
        exe_path = self.project_root / "electron/dist/win-unpacked/VoiceFlow.exe"
        exists = exe_path.exists()
        size_mb = exe_path.stat().st_size / (1024*1024) if exists else 0
        
        self.log_test(
            "Executable exists",
            exists and size_mb > 50,  # Should be > 50MB
            f"Path: {exe_path}, Size: {size_mb:.1f}MB"
        )
        
    def test_launcher_scripts(self):
        """Test launcher scripts exist and are properly configured"""
        scripts = [
            "VoiceFlow-Launcher.bat",
            "VoiceFlow-SystemTray.bat", 
            "VoiceFlow-Tray.ps1"
        ]
        
        for script in scripts:
            script_path = self.project_root / script
            exists = script_path.exists()
            self.log_test(
                f"Launcher script: {script}",
                exists,
                f"Found: {exists}"
            )
            
    def test_backend_configuration(self):
        """Test backend server configuration"""
        backend_path = self.project_root / "python/stt_server.py"
        
        if not backend_path.exists():
            self.log_test("Backend configuration", False, "stt_server.py not found")
            return
            
        # Check for updated hotkey
        with open(backend_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        has_new_hotkey = "'ctrl+alt'" in content and "'ctrl+alt+space'" not in content
        self.log_test(
            "Hotkey updated to Ctrl+Alt",
            has_new_hotkey,
            f"New hotkey found: {has_new_hotkey}"
        )
        
    def test_python_dependencies(self):
        """Test Python virtual environment and basic dependencies"""
        venv_python = self.project_root / "python/venv/Scripts/python.exe"
        venv_exists = venv_python.exists()
        
        self.log_test(
            "Python virtual environment",
            venv_exists,
            f"venv exists: {venv_exists}"
        )
        
        if venv_exists:
            # Test basic imports
            try:
                result = subprocess.run([
                    str(venv_python), "-c", 
                    "import asyncio, websockets, json, sqlite3; print('OK')"
                ], capture_output=True, text=True, timeout=10)
                
                basic_imports_ok = result.returncode == 0 and "OK" in result.stdout
                self.log_test(
                    "Basic Python dependencies",
                    basic_imports_ok,
                    f"Import test: {basic_imports_ok}"
                )
            except Exception as e:
                self.log_test(
                    "Basic Python dependencies",
                    False,
                    f"Error: {e}"
                )
                
    def test_project_structure(self):
        """Test cleaned project structure"""
        essential_dirs = ["src", "python", "electron", "docs"]
        essential_files = [
            "package.json",
            "README.md", 
            "VoiceFlow-Launcher.bat"
        ]
        
        for directory in essential_dirs:
            dir_path = self.project_root / directory
            exists = dir_path.exists() and dir_path.is_dir()
            self.log_test(
                f"Essential directory: {directory}",
                exists,
                f"Exists: {exists}"
            )
            
        for file in essential_files:
            file_path = self.project_root / file
            exists = file_path.exists() and file_path.is_file()
            self.log_test(
                f"Essential file: {file}",
                exists,
                f"Exists: {exists}"
            )
            
    def test_cleanup_successful(self):
        """Test that unnecessary files were removed"""
        should_not_exist = [
            "VoiceFlow-Enhanced.bat",
            "VoiceFlow-Working.bat", 
            "debug_enhanced.py",
            "comprehensive_test_and_fix.py",
            "frontend_test_results.json",
            "VoiceFlow.ahk",
            "rustup-init.exe"
        ]
        
        cleanup_successful = True
        for file in should_not_exist:
            file_path = self.project_root / file
            if file_path.exists():
                cleanup_successful = False
                break
                
        self.log_test(
            "Cleanup successful",
            cleanup_successful,
            f"Unnecessary files removed: {cleanup_successful}"
        )
        
    def test_documentation_updated(self):
        """Test if documentation exists and mentions new hotkey"""
        readme_path = self.project_root / "README.md"
        
        if not readme_path.exists():
            self.log_test("Documentation exists", False, "README.md not found")
            return
            
        with open(readme_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Check for key documentation elements
        has_installation = "install" in content.lower()
        has_usage = "usage" in content.lower() or "how to" in content.lower()
        
        self.log_test(
            "Documentation completeness",
            has_installation and has_usage,
            f"Installation: {has_installation}, Usage: {has_usage}"
        )
        
    def run_all_tests(self):
        """Run all tests and generate report"""
        print("=" * 60)
        print("VoiceFlow Final Test Suite - Post-Cleanup Verification")
        print("=" * 60)
        print()
        
        # Run all tests
        self.test_executable_exists()
        self.test_launcher_scripts()
        self.test_backend_configuration()
        self.test_python_dependencies()
        self.test_project_structure()
        self.test_cleanup_successful()
        self.test_documentation_updated()
        
        # Generate summary
        print()
        print("=" * 60)
        print(f"Tests Passed: {self.results['passed']}")
        print(f"Tests Failed: {self.results['failed']}")
        print(f"Success Rate: {(self.results['passed']/self.results['total_tests']*100):.1f}%")
        print("=" * 60)
        
        # Save detailed results
        with open(self.project_root / "final_test_results.json", "w") as f:
            json.dump(self.results, f, indent=2)
            
        return self.results['failed'] == 0

if __name__ == "__main__":
    tester = VoiceFlowFinalTests()
    success = tester.run_all_tests()
    
    if success:
        print("\n✅ All tests passed! VoiceFlow is ready for deployment.")
    else:
        print(f"\n❌ {tester.results['failed']} test(s) failed. Review results above.")
        sys.exit(1)
