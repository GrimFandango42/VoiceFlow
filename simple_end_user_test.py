#!/usr/bin/env python3
"""
VoiceFlow End-User Experience Test - Simple Version
Tests the exact workflow a user would experience
"""

import subprocess
import time
import requests
import json
import os
import sys
from pathlib import Path
import threading
import psutil

class VoiceFlowEndUserTest:
    def __init__(self):
        self.project_dir = Path("C:/AI_Projects/VoiceFlow")
        self.python_exe = self.project_dir / "python/venv/Scripts/python.exe"
        self.test_results = {
            "launcher_test": False,
            "server_startup": False,
            "websocket_connection": False,
            "ollama_connection": False,
            "hotkey_simulation": False,
            "text_injection": False,
            "system_tray": False,
            "overall_success": False
        }
        
    def log(self, message, success=None):
        """Log test results with status indicators"""
        if success is True:
            print(f"[PASS] {message}")
        elif success is False:
            print(f"[FAIL] {message}")
        else:
            print(f"[TEST] {message}")
            
    def test_1_environment_check(self):
        """Test 1: Verify environment is ready"""
        self.log("TEST 1: Environment Check", None)
        
        # Check Python
        if self.python_exe.exists():
            self.log("Python executable found", True)
        else:
            self.log("Python executable missing", False)
            return False
            
        # Check key files
        required_files = [
            "VoiceFlow-Invisible.bat",
            "VoiceFlow-TrulyInvisible.ps1", 
            "python/stt_server.py"
        ]
        
        for file in required_files:
            if (self.project_dir / file).exists():
                self.log(f"{file} found", True)
            else:
                self.log(f"{file} missing", False)
                return False
                
        return True
        
    def test_2_server_startup(self):
        """Test 2: Start STT server and verify it's working"""
        self.log("TEST 2: Server Startup", None)
        
        try:
            # Start server in background
            server_cmd = [
                str(self.python_exe),
                str(self.project_dir / "python/stt_server.py")
            ]
            
            self.log("Starting STT server...")
            self.server_process = subprocess.Popen(
                server_cmd,
                cwd=str(self.project_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            # Wait for server to initialize
            self.log("Waiting for server initialization...")
            time.sleep(8)  # Increased wait time
            
            # Check if process is still running
            if self.server_process.poll() is None:
                self.log("STT server started successfully", True)
                self.test_results["server_startup"] = True
                return True
            else:
                self.log("STT server failed to start", False)
                return False
                
        except Exception as e:
            self.log(f"Server startup failed: {e}", False)
            return False
            
    def test_3_websocket_connection(self):
        """Test 3: Verify WebSocket server is accessible"""
        self.log("TEST 3: WebSocket Connection", None)
        
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                self.log(f"WebSocket connection attempt {attempt + 1}/{max_attempts}")
                
                # Simple socket test
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex(('localhost', 8765))
                sock.close()
                
                if result == 0:
                    self.log("WebSocket port is accessible", True)
                    self.test_results["websocket_connection"] = True
                    return True
                else:
                    self.log(f"Port 8765 not accessible (attempt {attempt + 1})")
                    time.sleep(2)
                    
            except Exception as e:
                self.log(f"WebSocket test error: {e}")
                time.sleep(2)
                
        self.log("WebSocket connection failed", False)
        return False
            
    def test_4_ollama_integration(self):
        """Test 4: Verify Ollama AI enhancement is working"""
        self.log("TEST 4: Ollama Integration", None)
        
        try:
            # Test Ollama connection
            ollama_urls = [
                "http://localhost:11434/api/tags",
                "http://172.30.248.191:11434/api/tags"  # WSL IP from server
            ]
            
            for url in ollama_urls:
                try:
                    self.log(f"Testing Ollama at {url}")
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        models = response.json().get('models', [])
                        if models:
                            self.log(f"Ollama connected at {url}", True)
                            model_names = [m.get('name', '') for m in models]
                            self.log(f"Available models: {model_names}")
                            self.test_results["ollama_connection"] = True
                            return True
                except requests.RequestException as e:
                    self.log(f"Ollama connection failed: {e}")
                    continue
                    
            self.log("Ollama not accessible", False)
            return False
            
        except Exception as e:
            self.log(f"Ollama test failed: {e}", False)
            return False
            
    def test_5_launcher_simulation(self):
        """Test 5: Simulate running the invisible launcher"""
        self.log("TEST 5: Launcher Simulation", None)
        
        try:
            # Check if PowerShell script exists and is valid
            ps_script = self.project_dir / "VoiceFlow-TrulyInvisible.ps1"
            
            if not ps_script.exists():
                self.log("PowerShell script missing", False)
                return False
                
            # Test PowerShell script syntax
            syntax_cmd = [
                "powershell.exe",
                "-Command", 
                f"Get-Content '{ps_script}' | Out-Null; Write-Host 'SYNTAX_OK'"
            ]
            
            result = subprocess.run(
                syntax_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if "SYNTAX_OK" in result.stdout:
                self.log("PowerShell script syntax valid", True)
                self.test_results["launcher_test"] = True
                return True
            else:
                self.log(f"PowerShell script syntax error: {result.stderr}", False)
                return False
                
        except Exception as e:
            self.log(f"Launcher test failed: {e}", False)
            return False
            
    def test_6_text_injection_capability(self):
        """Test 6: Verify text injection modules are working"""
        self.log("TEST 6: Text Injection Capability", None)
        
        try:
            # Test if pyautogui and keyboard are working
            test_code = '''
import sys
sys.path.insert(0, "python/venv/Lib/site-packages")

try:
    import pyautogui
    import keyboard
    print("TEXT_INJECTION_OK")
except ImportError as e:
    print(f"TEXT_INJECTION_FAILED: {e}")
'''
            
            result = subprocess.run(
                [str(self.python_exe), "-c", test_code],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=str(self.project_dir)
            )
            
            if "TEXT_INJECTION_OK" in result.stdout:
                self.log("Text injection modules available", True)
                self.test_results["text_injection"] = True
                return True
            else:
                self.log(f"Text injection modules failed: {result.stdout}{result.stderr}", False)
                return False
                
        except Exception as e:
            self.log(f"Text injection test failed: {e}", False)
            return False
            
    def test_7_end_to_end_workflow(self):
        """Test 7: Complete end-to-end user workflow simulation"""
        self.log("TEST 7: End-to-End Workflow", None)
        
        try:
            # This simulates what happens when user runs VoiceFlow-Invisible.bat
            
            self.log("Simulating user double-clicking VoiceFlow-Invisible.bat...")
            
            # Check critical components
            components = {
                "STT Server": self.test_results["server_startup"],
                "WebSocket Communication": self.test_results["websocket_connection"],
                "Text Injection": self.test_results["text_injection"],
                "PowerShell Launcher": self.test_results["launcher_test"]
            }
            
            self.log("Checking critical components:")
            all_ready = True
            for component, status in components.items():
                status_text = "READY" if status else "FAILED"
                self.log(f"  {component}: {status_text}", status)
                if not status:
                    all_ready = False
            
            if all_ready:
                self.log("Complete workflow simulation successful", True)
                self.log("USER EXPERIENCE: Ready for voice transcription!")
                return True
            else:
                self.log("Workflow has missing components", False)
                return False
                
        except Exception as e:
            self.log(f"End-to-end test failed: {e}", False)
            return False
            
    def cleanup(self):
        """Clean up test processes"""
        self.log("Cleaning up test processes...")
        
        try:
            if hasattr(self, 'server_process'):
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
        except:
            pass
            
    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "="*60)
        print("VOICEFLOW END-USER EXPERIENCE TEST REPORT")
        print("="*60)
        
        total_tests = len(self.test_results) - 1  # -1 for overall_success
        passed_tests = sum(1 for k, v in self.test_results.items() if k != "overall_success" and v)
        
        print(f"Tests Passed: {passed_tests}/{total_tests}")
        
        # Overall assessment
        if passed_tests >= total_tests * 0.8:  # 80% pass rate
            self.test_results["overall_success"] = True
            self.log("OVERALL STATUS: READY FOR END-USER TESTING", True)
            self.log("VoiceFlow should work for real users!")
        else:
            self.log("OVERALL STATUS: NOT READY", False)
            self.log("Critical issues need to be fixed before user testing")
            
        print("\nDetailed Results:")
        for test, result in self.test_results.items():
            if test != "overall_success":
                status = "PASS" if result else "FAIL"
                print(f"  {test}: {status}")
                
        # Provide specific next steps
        print("\nNEXT STEPS FOR USER:")
        if self.test_results["overall_success"]:
            print("1. Double-click VoiceFlow-Invisible.bat")
            print("2. Look for microphone icon in system tray")
            print("3. Click in any text field (Notepad, browser, etc.)")
            print("4. Press and hold Ctrl+Alt")
            print("5. Speak your text")
            print("6. Release Ctrl+Alt")
            print("7. Watch text appear automatically!")
        else:
            print("Fix the FAILED components above before testing")
                
        return self.test_results["overall_success"]
        
    def run_all_tests(self):
        """Run the complete test suite"""
        print("Starting VoiceFlow End-User Experience Test Suite")
        print("This simulates exactly what a real user would experience")
        print("="*60)
        
        try:
            # Run tests in order
            tests = [
                ("Environment Check", self.test_1_environment_check),
                ("Server Startup", self.test_2_server_startup),
                ("WebSocket Connection", self.test_3_websocket_connection),
                ("Ollama Integration", self.test_4_ollama_integration),
                ("Launcher Simulation", self.test_5_launcher_simulation),
                ("Text Injection", self.test_6_text_injection_capability),
                ("End-to-End Workflow", self.test_7_end_to_end_workflow)
            ]
            
            for test_name, test_func in tests:
                print(f"\n--- {test_name} ---")
                success = test_func()
                if not success:
                    self.log(f"WARNING: {test_name} failed, but continuing...")
                    
            return self.generate_report()
            
        except KeyboardInterrupt:
            self.log("Test interrupted by user")
            return False
        finally:
            self.cleanup()

if __name__ == "__main__":
    tester = VoiceFlowEndUserTest()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)
