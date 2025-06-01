"""
Integration test suite for VoiceFlow
Tests the full application flow
"""
import subprocess
import time
import json
import asyncio
import websockets
import sys
import os
from pathlib import Path

class IntegrationTester:
    def __init__(self):
        self.results = {
            "tests_passed": 0,
            "tests_failed": 0,
            "integration_details": []
        }
        self.processes = []
        
    def log_result(self, test_name, passed, details=""):
        if passed:
            self.results["tests_passed"] += 1
            print(f"[PASS] {test_name}")
        else:
            self.results["tests_failed"] += 1
            print(f"[FAIL] {test_name}: {details}")
        
        self.results["integration_details"].append({
            "test": test_name,
            "passed": passed,
            "details": details,
            "timestamp": time.time()
        })
    
    def start_backend_server(self):
        """Start the Python STT server"""
        try:
            # Find Python executable
            venv_python = Path("python/venv/Scripts/python.exe")
            if not venv_python.exists():
                self.log_result("Backend server start", False, "Virtual environment not found")
                return None
            
            # Start the server
            process = subprocess.Popen(
                [str(venv_python), "python/stt_server.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            )
            
            self.processes.append(process)
            
            # Give it time to start
            time.sleep(5)
            
            # Check if it's running
            if process.poll() is None:
                self.log_result("Backend server start", True, "Server process started")
                return process
            else:
                self.log_result("Backend server start", False, "Server failed to start")
                return None
                
        except Exception as e:
            self.log_result("Backend server start", False, str(e))
            return None
    
    async def test_websocket_connection(self):
        """Test if we can connect to the WebSocket server"""
        try:
            uri = "ws://localhost:8765"
            websocket = await asyncio.wait_for(
                websockets.connect(uri),
                timeout=5.0
            )
            
            # Send test message
            await websocket.send(json.dumps({"type": "get_statistics"}))
            
            # Wait for response
            response = await asyncio.wait_for(websocket.recv(), timeout=5)
            data = json.loads(response)
            
            await websocket.close()
            
            if data.get("type") == "statistics":
                self.log_result("WebSocket integration", True, "Server responding correctly")
                return True
            else:
                self.log_result("WebSocket integration", False, "Unexpected response")
                return False
                
        except Exception as e:
            self.log_result("WebSocket integration", False, str(e))
            return False
    
    async def test_full_transcription_flow(self):
        """Test a simulated transcription flow"""
        try:
            uri = "ws://localhost:8765"
            websocket = await asyncio.wait_for(
                websockets.connect(uri),
                timeout=5.0
            )
            
            # Request history
            await websocket.send(json.dumps({"type": "get_history", "limit": 5}))
            response = await asyncio.wait_for(websocket.recv(), timeout=5)
            data = json.loads(response)
            
            if data.get("type") == "history":
                self.log_result("History retrieval", True, f"Got {len(data.get('data', []))} history items")
            else:
                self.log_result("History retrieval", False, "Failed to get history")
            
            await websocket.close()
            return True
            
        except Exception as e:
            self.log_result("Full transcription flow", False, str(e))
            return False
    
    def test_electron_app(self):
        """Test if Electron app can be started"""
        try:
            electron_path = Path("electron")
            if not electron_path.exists():
                self.log_result("Electron app test", False, "Electron directory not found")
                return False
            
            # Check if electron is installed
            node_modules = electron_path / "node_modules"
            if not node_modules.exists():
                self.log_result("Electron app test", False, "Electron not installed")
                return False
            
            # We can't actually start the GUI in this environment, but we can verify it's ready
            main_js = electron_path / "main.js"
            package_json = electron_path / "package.json"
            
            if main_js.exists() and package_json.exists():
                self.log_result("Electron app test", True, "Electron app is ready to run")
                return True
            else:
                self.log_result("Electron app test", False, "Missing required files")
                return False
                
        except Exception as e:
            self.log_result("Electron app test", False, str(e))
            return False
    
    def cleanup(self):
        """Clean up any running processes"""
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                time.sleep(1)
                if process.poll() is None:
                    process.kill()
    
    async def run_all_tests(self):
        """Run all integration tests"""
        print("=" * 50)
        print("VoiceFlow Integration Test Suite")
        print("=" * 50)
        print()
        
        # Start backend server
        server_process = self.start_backend_server()
        
        if server_process:
            # Test WebSocket
            await self.test_websocket_connection()
            
            # Test full flow
            await self.test_full_transcription_flow()
        
        # Test Electron
        self.test_electron_app()
        
        # Cleanup
        self.cleanup()
        
        # Summary
        print()
        print("=" * 50)
        print(f"Integration Tests Passed: {self.results['tests_passed']}")
        print(f"Integration Tests Failed: {self.results['tests_failed']}")
        print("=" * 50)
        
        # Save results
        results_file = Path("integration_test_results.json")
        with open(results_file, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\nDetailed results saved to: {results_file}")
        
        return self.results["tests_failed"] == 0

if __name__ == "__main__":
    # Change to project directory
    os.chdir(Path(__file__).parent)
    
    tester = IntegrationTester()
    success = asyncio.run(tester.run_all_tests())
    sys.exit(0 if success else 1)
