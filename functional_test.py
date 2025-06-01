#!/usr/bin/env python3
"""
VoiceFlow Functional Test Suite
Tests actual functionality of the VoiceFlow system
"""

import subprocess
import time
import requests
import json
import websocket
import threading
from pathlib import Path

class VoiceFlowFunctionalTest:
    def __init__(self):
        self.server_process = None
        self.test_results = {
            "server_startup": False,
            "websocket_connection": False,
            "ollama_integration": False,
            "text_injection_capability": False,
            "overall_status": "UNKNOWN"
        }
    
    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    def start_server(self):
        """Start the VoiceFlow server in background"""
        self.log("Starting VoiceFlow server...")
        
        try:
            # Start the server process
            self.server_process = subprocess.Popen(
                ["python/venv/Scripts/python.exe", "python/stt_server.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=Path.cwd()
            )
            
            # Give server time to start
            time.sleep(8)
            
            if self.server_process.poll() is None:
                self.test_results["server_startup"] = True
                self.log("[PASS] Server started successfully")
                return True
            else:
                self.log("[FAIL] Server failed to start")
                return False
                
        except Exception as e:
            self.log(f"[FAIL] Server startup error: {e}")
            return False
    
    def test_websocket_connection(self):
        """Test WebSocket connectivity"""
        self.log("Testing WebSocket connection...")
        
        try:
            # Simple WebSocket connection test
            ws_url = "ws://localhost:8765"
            
            def on_message(ws, message):
                data = json.loads(message)
                if data.get("type") == "connected":
                    self.test_results["websocket_connection"] = True
                    self.log("[PASS] WebSocket connection established")
            
            def on_error(ws, error):
                self.log(f"[FAIL] WebSocket error: {error}")
            
            def on_open(ws):
                self.log("[INFO] WebSocket opened")
                # Close after successful connection
                time.sleep(1)
                ws.close()
            
            ws = websocket.WebSocketApp(ws_url,
                                      on_message=on_message,
                                      on_error=on_error,
                                      on_open=on_open)
            
            # Run WebSocket in separate thread with timeout
            ws_thread = threading.Thread(target=ws.run_forever)
            ws_thread.daemon = True
            ws_thread.start()
            ws_thread.join(timeout=5)
            
            return self.test_results["websocket_connection"]
            
        except Exception as e:
            self.log(f"[FAIL] WebSocket test error: {e}")
            return False
    
    def test_ollama_integration(self):
        """Test Ollama integration"""
        self.log("Testing Ollama integration...")
        
        try:
            # Test Ollama API directly
            response = requests.post("http://localhost:11434/api/generate", 
                                   json={
                                       "model": "llama3.3:latest",
                                       "prompt": "Format this text: hello world",
                                       "stream": False
                                   }, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if "response" in result:
                    self.test_results["ollama_integration"] = True
                    self.log("[PASS] Ollama integration working")
                    return True
            
            self.log("[FAIL] Ollama integration failed")
            return False
            
        except Exception as e:
            self.log(f"[FAIL] Ollama test error: {e}")
            return False
    
    def test_text_injection(self):
        """Test text injection capability"""
        self.log("Testing text injection capability...")
        
        try:
            import pyautogui
            import keyboard
            
            # Test that modules are importable and functional
            pyautogui.FAILSAFE = False  # Disable failsafe for testing
            
            # Simple test - just verify the modules work
            pos = pyautogui.position()
            self.log(f"[INFO] Mouse position: {pos}")
            
            self.test_results["text_injection_capability"] = True
            self.log("[PASS] Text injection modules functional")
            return True
            
        except Exception as e:
            self.log(f"[FAIL] Text injection test error: {e}")
            return False
    
    def stop_server(self):
        """Stop the VoiceFlow server"""
        if self.server_process:
            self.log("Stopping VoiceFlow server...")
            self.server_process.terminate()
            self.server_process.wait(timeout=5)
            self.log("[INFO] Server stopped")
    
    def run_tests(self):
        """Run all functional tests"""
        self.log("VoiceFlow Functional Test Suite Starting...")
        self.log("=" * 50)
        
        # Test 1: Server startup
        if not self.start_server():
            self.test_results["overall_status"] = "FAILED_STARTUP"
            return self.test_results
        
        # Test 2: WebSocket connection
        self.test_websocket_connection()
        
        # Test 3: Ollama integration
        self.test_ollama_integration()
        
        # Test 4: Text injection capability
        self.test_text_injection()
        
        # Cleanup
        self.stop_server()
        
        # Overall assessment
        passed_tests = sum([
            self.test_results["server_startup"],
            self.test_results["websocket_connection"], 
            self.test_results["ollama_integration"],
            self.test_results["text_injection_capability"]
        ])
        
        if passed_tests == 4:
            self.test_results["overall_status"] = "FULLY_FUNCTIONAL"
            self.log("[SUCCESS] All tests passed - VoiceFlow is fully functional!")
        elif passed_tests >= 3:
            self.test_results["overall_status"] = "MOSTLY_FUNCTIONAL"
            self.log("[WARNING] Most tests passed - minor issues detected")
        else:
            self.test_results["overall_status"] = "NOT_FUNCTIONAL"
            self.log("[FAIL] Major issues detected")
        
        # Save results
        with open("functional_test_results.json", "w") as f:
            json.dump(self.test_results, f, indent=2)
        
        self.log("=" * 50)
        self.log(f"Overall Status: {self.test_results['overall_status']}")
        self.log("Results saved to functional_test_results.json")
        
        return self.test_results

if __name__ == "__main__":
    import os
    os.chdir(Path(__file__).parent)
    
    tester = VoiceFlowFunctionalTest()
    results = tester.run_tests()
