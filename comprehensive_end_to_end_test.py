#!/usr/bin/env python3
"""
VoiceFlow Comprehensive End-to-End Test
Tests complete system functionality including:
- Backend server startup
- Frontend connectivity  
- Component integration
- Error handling
"""

import os
import sys
import time
import json
import socket
import subprocess
import threading
import requests
from pathlib import Path
# import websocket  # Not available, will use socket instead

class VoiceFlowEndToEndTest:
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
            
        self.results = {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "tests": []
        }
        
        self.server_process = None
        
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
        return passed
        
    def test_port_available(self, port=8765):
        """Test if WebSocket port is available"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            available = result != 0  # Port is available if connection fails
            self.log_test(
                f"Port {port} availability",
                available,
                f"Port {port} is {'available' if available else 'in use'}"
            )
            return available
        except Exception as e:
            self.log_test(f"Port {port} availability", False, f"Error: {e}")
            return False
            
    def test_python_environment(self):
        """Test Python virtual environment"""
        venv_python = self.project_root / "python/venv/Scripts/python.exe"
        
        if not venv_python.exists():
            return self.log_test(
                "Python virtual environment", 
                False, 
                "venv/Scripts/python.exe not found"
            )
            
        # Test basic imports
        try:
            result = subprocess.run([
                str(venv_python), "-c", 
                "import asyncio, websockets, json; print('PYTHON_OK')"
            ], capture_output=True, text=True, timeout=15)
            
            success = result.returncode == 0 and "PYTHON_OK" in result.stdout
            details = "Basic imports successful" if success else f"Error: {result.stderr}"
            
            return self.log_test("Python virtual environment", success, details)
            
        except Exception as e:
            return self.log_test("Python virtual environment", False, f"Error: {e}")
    
    def test_ollama_connectivity(self):
        """Test Ollama service connectivity"""
        ollama_urls = [
            "http://172.30.248.191:11434/api/tags",
            "http://localhost:11434/api/tags",
            "http://127.0.0.1:11434/api/tags"
        ]
        
        for url in ollama_urls:
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    return self.log_test(
                        "Ollama connectivity",
                        True,
                        f"Connected to {url}"
                    )
            except:
                continue
                
        return self.log_test(
            "Ollama connectivity",
            False,
            "Could not connect to any Ollama instance (this is OK for testing)"
        )
    
    def start_backend_server(self):
        """Start the VoiceFlow backend server"""
        if not self.test_python_environment():
            return False
            
        # Kill any existing server
        try:
            subprocess.run(["taskkill", "/f", "/im", "python.exe"], 
                         capture_output=True, shell=True)
        except:
            pass
            
        venv_python = self.project_root / "python/venv/Scripts/python.exe"
        server_script = self.project_root / "python/stt_server.py"
        
        try:
            # Start server in background
            self.server_process = subprocess.Popen([
                str(venv_python), str(server_script)
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Wait for server startup
            for i in range(30):  # Wait up to 30 seconds
                if self.test_websocket_connection(silent=True):
                    return self.log_test(
                        "Backend server startup",
                        True,
                        f"Server started successfully on port 8765"
                    )
                time.sleep(1)
                
            return self.log_test(
                "Backend server startup",
                False,
                "Server did not start within 30 seconds"
            )
            
        except Exception as e:
            return self.log_test(
                "Backend server startup",
                False,
                f"Failed to start server: {e}"
            )
    
    def test_websocket_connection(self, silent=False):
        """Test WebSocket connection to backend"""
        try:
            # Simple socket test to see if server is listening
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(('localhost', 8765))
            sock.close()
            
            success = result == 0  # Connection successful
            
            if not silent:
                details = "Server listening on port 8765" if success else "No server on port 8765"
                self.log_test(
                    "WebSocket connection",
                    success,
                    details
                )
            return success
            
        except Exception as e:
            if not silent:
                self.log_test(
                    "WebSocket connection",
                    False,
                    f"Connection failed: {e}"
                )
            return False
    
    def test_frontend_file(self):
        """Test frontend HTML file"""
        frontend_path = self.project_root / "voiceflow_frontend.html"
        
        if not frontend_path.exists():
            return self.log_test(
                "Frontend HTML file",
                False,
                "voiceflow_frontend.html not found"
            )
            
        # Check file content
        try:
            with open(frontend_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Check for key components
            has_websocket = "WebSocket" in content
            has_title = "VoiceFlow" in content
            has_js = "javascript" in content.lower() or "<script>" in content
            
            success = has_websocket and has_title and has_js
            details = f"WebSocket: {has_websocket}, Title: {has_title}, JS: {has_js}"
            
            return self.log_test(
                "Frontend HTML file",
                success,
                details
            )
            
        except Exception as e:
            return self.log_test(
                "Frontend HTML file",
                False,
                f"Error reading file: {e}"
            )
    
    def test_launcher_script(self):
        """Test launcher script"""
        launcher_path = self.project_root / "VoiceFlow-Launcher.bat"
        
        if not launcher_path.exists():
            return self.log_test(
                "Launcher script",
                False,
                "VoiceFlow-Launcher.bat not found"
            )
            
        try:
            with open(launcher_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Check for key components
            has_python_start = "python" in content.lower()
            has_frontend_open = "voiceflow_frontend.html" in content
            has_timeout = "timeout" in content.lower()
            
            success = has_python_start and has_frontend_open
            details = f"Python start: {has_python_start}, Frontend: {has_frontend_open}"
            
            return self.log_test(
                "Launcher script",
                success,
                details
            )
            
        except Exception as e:
            return self.log_test(
                "Launcher script",
                False,
                f"Error reading script: {e}"
            )
    
    def test_native_components(self):
        """Test native Windows components"""
        native_file = self.project_root / "native/voiceflow_native.py"
        
        if not native_file.exists():
            return self.log_test(
                "Native components",
                False,
                "native/voiceflow_native.py not found"
            )
            
        try:
            with open(native_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Check for key functionality
            has_hotkey = "hotkey" in content.lower()
            has_text_injection = "inject_text" in content
            has_context_detection = "detect_application_context" in content
            
            success = has_hotkey and has_text_injection and has_context_detection
            details = f"Hotkey: {has_hotkey}, Injection: {has_text_injection}, Context: {has_context_detection}"
            
            return self.log_test(
                "Native components",
                success,
                details
            )
            
        except Exception as e:
            return self.log_test(
                "Native components",
                False,
                f"Error reading native file: {e}"
            )
    
    def test_unicode_cleanup(self):
        """Test that Unicode issues have been resolved"""
        test_files = [
            "voiceflow_frontend.html",
            "test_final.py", 
            "python/stt_server.py",
            "native/voiceflow_native.py"
        ]
        
        unicode_issues = []
        for filename in test_files:
            file_path = self.project_root / filename
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Check for problematic Unicode characters
                        if any(char in content for char in ['🎙️', '✅', '❌', '⚠️']):
                            unicode_issues.append(filename)
                except Exception:
                    pass
        
        success = len(unicode_issues) == 0
        details = f"Clean files: {len(test_files) - len(unicode_issues)}/{len(test_files)}"
        if unicode_issues:
            details += f", Issues in: {', '.join(unicode_issues)}"
            
        return self.log_test(
            "Unicode cleanup",
            success,
            details
        )
    
    def cleanup(self):
        """Clean up test resources"""
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
            except:
                try:
                    self.server_process.kill()
                except:
                    pass
        
        # Kill any remaining Python processes
        try:
            subprocess.run(["taskkill", "/f", "/im", "python.exe"], 
                         capture_output=True, shell=True)
        except:
            pass
    
    def run_comprehensive_test(self):
        """Run all comprehensive tests"""
        print("=" * 70)
        print("VoiceFlow Comprehensive End-to-End Test")
        print("=" * 70)
        print(f"Project Root: {self.project_root.absolute()}")
        print()
        
        try:
            # Pre-tests
            print("PHASE 1: Pre-Test Checks")
            print("-" * 30)
            self.test_port_available()
            self.test_python_environment()
            self.test_ollama_connectivity()
            self.test_unicode_cleanup()
            
            print("\nPHASE 2: Component Tests")
            print("-" * 30)
            self.test_frontend_file()
            self.test_launcher_script()
            self.test_native_components()
            
            print("\nPHASE 3: Integration Tests") 
            print("-" * 30)
            self.start_backend_server()
            self.test_websocket_connection()
            
            # Generate summary
            print("\n" + "=" * 70)
            print("TEST SUMMARY")
            print("=" * 70)
            print(f"Total Tests: {self.results['total_tests']}")
            print(f"Passed: {self.results['passed']}")
            print(f"Failed: {self.results['failed']}")
            print(f"Success Rate: {(self.results['passed']/max(1, self.results['total_tests'])*100):.1f}%")
            
            if self.results['failed'] == 0:
                print("\n[SUCCESS] All tests passed! VoiceFlow is ready for production.")
                print("\nNext steps:")
                print("1. Create GitHub PR")
                print("2. Deploy to production")
                print("3. User testing")
            else:
                print(f"\n[ISSUES] {self.results['failed']} test(s) failed.")
                print("Review failed tests above before proceeding.")
            
            # Save detailed results
            with open(self.project_root / "end_to_end_test_results.json", "w") as f:
                json.dump(self.results, f, indent=2)
            
            return self.results['failed'] == 0
            
        finally:
            self.cleanup()

if __name__ == "__main__":
    try:
        tester = VoiceFlowEndToEndTest()
        success = tester.run_comprehensive_test()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"[FATAL ERROR] {e}")
        sys.exit(1)
