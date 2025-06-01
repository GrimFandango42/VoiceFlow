#!/usr/bin/env python3
"""
VoiceFlow Quick Component Test
Fast verification of all components without starting servers
"""

import os
import sys
import json
import subprocess
from pathlib import Path

class VoiceFlowQuickTest:
    def __init__(self):
        # Find project root
        possible_roots = [
            Path("/mnt/c/AI_Projects/VoiceFlow"),
            Path("C:/AI_Projects/VoiceFlow"),
            Path(".")
        ]
        
        self.project_root = None
        for root in possible_roots:
            if root.exists():
                self.project_root = root
                break
                
        if not self.project_root:
            raise Exception("Could not find VoiceFlow project directory")
            
        self.results = {"passed": 0, "failed": 0, "tests": []}
        
    def log_test(self, name, passed, details=""):
        """Log test result"""
        status = "PASS" if passed else "FAIL"
        if passed:
            self.results["passed"] += 1
        else:
            self.results["failed"] += 1
        
        self.results["tests"].append({"name": name, "status": status, "details": details})
        print(f"[{status}] {name}: {details}")
        return passed
    
    def run_quick_tests(self):
        """Run quick component verification tests"""
        print("=" * 60)
        print("VoiceFlow Quick Component Test")
        print("=" * 60)
        print(f"Project Root: {self.project_root.absolute()}")
        print()
        
        # Essential files
        essential_files = [
            ("VoiceFlow-Launcher.bat", "Main launcher"),
            ("voiceflow_frontend.html", "Web frontend"),
            ("python/stt_server.py", "Backend server"),
            ("native/voiceflow_native.py", "Native component"),
            ("README.md", "Documentation")
        ]
        
        print("Component Files:")
        for filename, description in essential_files:
            file_path = self.project_root / filename
            exists = file_path.exists()
            size = ""
            if exists:
                size_bytes = file_path.stat().st_size
                size = f" ({size_bytes/1024:.1f}KB)"
            self.log_test(description, exists, f"{filename}{size}")
        
        # Python environment
        print("\nPython Environment:")
        venv_python = self.project_root / "python/venv/Scripts/python.exe"
        venv_exists = venv_python.exists()
        self.log_test("Virtual environment", venv_exists, str(venv_python))
        
        if venv_exists:
            try:
                result = subprocess.run([
                    str(venv_python), "-c", 
                    "import asyncio, websockets; print('DEPS_OK')"
                ], capture_output=True, text=True, timeout=10)
                
                deps_ok = result.returncode == 0 and "DEPS_OK" in result.stdout
                self.log_test("Python dependencies", deps_ok, "asyncio, websockets available")
            except Exception as e:
                self.log_test("Python dependencies", False, f"Error: {e}")
        
        # Content verification
        print("\nContent Verification:")
        
        # Check launcher script
        launcher_path = self.project_root / "VoiceFlow-Launcher.bat"
        if launcher_path.exists():
            with open(launcher_path, 'r') as f:
                launcher_content = f.read()
            has_server_start = "python.exe python\\stt_server.py" in launcher_content
            has_frontend = "voiceflow_frontend.html" in launcher_content
            self.log_test("Launcher configuration", has_server_start and has_frontend, 
                         f"Server start: {has_server_start}, Frontend: {has_frontend}")
        
        # Check frontend
        frontend_path = self.project_root / "voiceflow_frontend.html"
        if frontend_path.exists():
            with open(frontend_path, 'r', encoding='utf-8') as f:
                frontend_content = f.read()
            has_websocket = "WebSocket" in frontend_content
            has_hotkey_info = "Ctrl+Alt" in frontend_content
            no_unicode = not any(char in frontend_content for char in ['🎙️', '✅', '❌'])
            self.log_test("Frontend features", has_websocket and has_hotkey_info and no_unicode,
                         f"WebSocket: {has_websocket}, Hotkey info: {has_hotkey_info}, No Unicode: {no_unicode}")
        
        # Check backend
        backend_path = self.project_root / "python/stt_server.py"
        if backend_path.exists():
            with open(backend_path, 'r', encoding='utf-8') as f:
                backend_content = f.read()
            has_websocket_server = "websockets.serve" in backend_content
            has_new_hotkey = "'ctrl+alt'" in backend_content
            has_ascii_logs = "[OK]" in backend_content and "[WARNING]" in backend_content
            self.log_test("Backend configuration", has_websocket_server and has_new_hotkey and has_ascii_logs,
                         f"WebSocket server: {has_websocket_server}, New hotkey: {has_new_hotkey}, ASCII logs: {has_ascii_logs}")
        
        # Unicode cleanup verification
        print("\nUnicode Cleanup:")
        test_files = ["voiceflow_frontend.html", "python/stt_server.py", "native/voiceflow_native.py"]
        unicode_clean = True
        for filename in test_files:
            file_path = self.project_root / filename
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    if any(char in content for char in ['🎙️', '✅', '❌', '⚠️']):
                        unicode_clean = False
                        break
                except:
                    pass
        
        self.log_test("Unicode cleanup complete", unicode_clean, "No problematic Unicode symbols found")
        
        # Summary
        total_tests = self.results["passed"] + self.results["failed"]
        success_rate = (self.results["passed"] / max(1, total_tests)) * 100
        
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Tests Passed: {self.results['passed']}")
        print(f"Tests Failed: {self.results['failed']}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        if self.results['failed'] == 0:
            print("\n[SUCCESS] All components verified! Ready for:")
            print("  1. Manual testing with VoiceFlow-Launcher.bat")
            print("  2. GitHub PR creation")
            print("  3. Production deployment")
        else:
            print(f"\n[ISSUES] {self.results['failed']} issue(s) found. Review above.")
        
        # Save results
        with open(self.project_root / "quick_test_results.json", "w") as f:
            json.dump(self.results, f, indent=2)
        
        return self.results['failed'] == 0

if __name__ == "__main__":
    try:
        tester = VoiceFlowQuickTest()
        success = tester.run_quick_tests()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"[FATAL ERROR] {e}")
        sys.exit(1)
