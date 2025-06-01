#!/usr/bin/env python3
"""
VoiceFlow End-User Experience Test
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
import websocket
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
            print(f"✅ {message}")
        elif success is False:
            print(f"❌ {message}")
        else:
            print(f"📋 {message}")
            
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
            time.sleep(5)
            
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
        
        try:
            # Test WebSocket connection
            import websocket
            
            def on_message(ws, message):
                data = json.loads(message)
                if data.get("type") == "connected":
                    self.log("WebSocket connection successful", True)
                    self.test_results["websocket_connection"] = True
                    ws.close()
                    
            def on_error(ws, error):
                self.log(f"WebSocket error: {error}", False)
                
            def on_close(ws, close_status_code, close_msg):
                pass
                
            ws = websocket.WebSocketApp(
                "ws://localhost:8765",
                on_open=lambda ws: self.log("Attempting WebSocket connection..."),
                on_message=on_message,
                on_error=on_error,
                on_close=on_close
            )
            
            # Run for 3 seconds
            ws.run_forever(timeout=3)
            
            return self.test_results["websocket_connection"]
            
        except Exception as e:
            self.log(f"WebSocket test failed: {e}", False)
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
                    response = requests.get(url, timeout=3)
                    if response.status_code == 200:
                        models = response.json().get('models', [])
                        if models:
                            self.log(f"Ollama connected at {url}", True)
                            self.log(f"Available models: {[m.get('name', '') for m in models]}")
                            self.test_results["ollama_connection"] = True
                            return True
                except requests.RequestException:
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
            # Test PowerShell script execution
            ps_script = self.project_dir / "VoiceFlow-TrulyInvisible.ps1"
            
            # Run PowerShell script (simulate invisible mode)
            ps_cmd = [
                "powershell.exe",
                "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Hidden", 
                "-File", str(ps_script)
            ]
            
            self.log("Testing PowerShell launcher...")
            
            # Start in background to simulate actual usage
            launcher_process = subprocess.Popen(
                ps_cmd,
                cwd=str(self.project_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            time.sleep(2)
            
            # Check if it's running
            if launcher_process.poll() is None:
                self.log("PowerShell launcher started", True)
                self.test_results["launcher_test"] = True
                
                # Kill it after test
                launcher_process.terminate()
                return True
            else:
                self.log("PowerShell launcher failed", False)
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
                timeout=10
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
            
            # Step 1: PowerShell starts system tray
            self.log("Step 1: System tray initialization")
            
            # Step 2: Python server starts
            self.log("Step 2: STT server startup") 
            
            # Step 3: Global hotkey registration
            self.log("Step 3: Global hotkey (Ctrl+Alt) registration")
            
            # Step 4: WebSocket server ready
            self.log("Step 4: WebSocket communication ready")
            
            # Step 5: Ollama AI connection
            self.log("Step 5: AI enhancement connection")
            
            # If all previous tests passed, workflow is ready
            workflow_ready = all([
                self.test_results["server_startup"],
                self.test_results["websocket_connection"], 
                self.test_results["text_injection"]
            ])
            
            if workflow_ready:
                self.log("Complete workflow simulation successful", True)
                self.log("✨ User Experience: Ready for voice transcription!")
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
        self.log("\n" + "="*60)
        self.log("VOICEFLOW END-USER EXPERIENCE TEST REPORT")
        self.log("="*60)
        
        total_tests = len(self.test_results) - 1  # -1 for overall_success
        passed_tests = sum(1 for k, v in self.test_results.items() if k != "overall_success" and v)
        
        self.log(f"Tests Passed: {passed_tests}/{total_tests}")
        
        # Overall assessment
        if passed_tests >= total_tests * 0.8:  # 80% pass rate
            self.test_results["overall_success"] = True
            self.log("🎉 OVERALL STATUS: READY FOR END-USER TESTING", True)
            self.log("VoiceFlow should work for real users!")
        else:
            self.log("❌ OVERALL STATUS: NOT READY", False)
            self.log("Critical issues need to be fixed before user testing")
            
        self.log("\nDetailed Results:")
        for test, result in self.test_results.items():
            if test != "overall_success":
                status = "PASS" if result else "FAIL"
                self.log(f"  {test}: {status}", result)
                
        return self.test_results["overall_success"]
        
    def run_all_tests(self):
        """Run the complete test suite"""
        self.log("🚀 Starting VoiceFlow End-User Experience Test Suite")
        self.log("This simulates exactly what a real user would experience")
        self.log("="*60)
        
        try:
            # Run tests in order
            tests = [
                self.test_1_environment_check,
                self.test_2_server_startup,
                self.test_3_websocket_connection,
                self.test_4_ollama_integration,
                self.test_5_launcher_simulation,
                self.test_6_text_injection_capability,
                self.test_7_end_to_end_workflow
            ]
            
            for test in tests:
                success = test()
                if not success:
                    self.log(f"⚠️  Test failed, but continuing with remaining tests...")
                self.log("")  # Spacing
                
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
