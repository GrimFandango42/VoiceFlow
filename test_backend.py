"""
Test suite for VoiceFlow backend
"""
import sys
import os
import asyncio
import json
import websockets
import requests
import time
from pathlib import Path

# Add python directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

class BackendTester:
    def __init__(self):
        self.results = {
            "tests_passed": 0,
            "tests_failed": 0,
            "details": []
        }
        
    def log_result(self, test_name, passed, details=""):
        if passed:
            self.results["tests_passed"] += 1
            print(f"[PASS] {test_name}")
        else:
            self.results["tests_failed"] += 1
            print(f"[FAIL] {test_name}: {details}")
        
        self.results["details"].append({
            "test": test_name,
            "passed": passed,
            "details": details,
            "timestamp": time.time()
        })
    
    def test_imports(self):
        """Test if all required modules can be imported"""
        try:
            import numpy as np
            from RealtimeSTT import AudioToTextRecorder
            import sqlite3
            self.log_result("Module imports", True)
            return True
        except ImportError as e:
            self.log_result("Module imports", False, str(e))
            return False
    
    def test_ollama_connection(self):
        """Test Ollama connectivity"""
        ollama_urls = [
            "http://172.30.248.191:11434/api/tags",
            "http://localhost:11434/api/tags",
            "http://127.0.0.1:11434/api/tags"
        ]
        
        for url in ollama_urls:
            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 200:
                    models = response.json().get('models', [])
                    self.log_result("Ollama connection", True, f"Connected to {url}, {len(models)} models available")
                    return True
            except:
                continue
        
        self.log_result("Ollama connection", False, "Could not connect to Ollama")
        return False
    
    def test_database_creation(self):
        """Test database creation and operations"""
        try:
            import sqlite3
            test_db = Path.home() / ".voiceflow" / "test_transcriptions.db"
            test_db.parent.mkdir(exist_ok=True)
            
            conn = sqlite3.connect(test_db)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transcriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    raw_text TEXT,
                    enhanced_text TEXT,
                    duration_ms INTEGER,
                    word_count INTEGER,
                    processing_time_ms INTEGER,
                    confidence REAL
                )
            ''')
            
            # Test insert
            cursor.execute('''
                INSERT INTO transcriptions (raw_text, enhanced_text, duration_ms, word_count, processing_time_ms)
                VALUES (?, ?, ?, ?, ?)
            ''', ("test text", "Test text.", 1000, 2, 50))
            
            conn.commit()
            
            # Test select
            cursor.execute('SELECT COUNT(*) FROM transcriptions')
            count = cursor.fetchone()[0]
            
            conn.close()
            
            # Clean up
            test_db.unlink()
            
            self.log_result("Database operations", True)
            return True
        except Exception as e:
            self.log_result("Database operations", False, str(e))
            return False
    
    async def test_websocket_server(self):
        """Test WebSocket connectivity"""
        try:
            # Try to connect to the WebSocket server
            uri = "ws://localhost:8765"
            try:
                websocket = await asyncio.wait_for(
                    websockets.connect(uri),
                    timeout=2.0
                )
                # Send a test message
                await websocket.send(json.dumps({"type": "get_statistics"}))
                
                # Wait for response
                response = await asyncio.wait_for(websocket.recv(), timeout=2)
                data = json.loads(response)
                
                await websocket.close()
                
                if data.get("type") == "statistics":
                    self.log_result("WebSocket server", True, "Server is running and responding")
                    return True
                else:
                    self.log_result("WebSocket server", False, "Unexpected response")
                    return False
            except asyncio.TimeoutError:
                self.log_result("WebSocket server", False, "Connection timeout")
                return False
                    
        except (ConnectionRefusedError, OSError):
            self.log_result("WebSocket server", False, "Server not running (this is expected in test mode)")
            return False
        except Exception as e:
            self.log_result("WebSocket server", False, str(e))
            return False
    
    def test_audio_device(self):
        """Test if audio devices are available"""
        try:
            import pyaudio
            p = pyaudio.PyAudio()
            
            # Get default input device
            default_input = p.get_default_input_device_info()
            
            # List all devices
            device_count = p.get_device_count()
            
            p.terminate()
            
            self.log_result("Audio devices", True, f"Found {device_count} devices, default: {default_input['name']}")
            return True
        except Exception as e:
            self.log_result("Audio devices", False, str(e))
            return False
    
    def test_whisper_model(self):
        """Test if Whisper model can be loaded"""
        try:
            from faster_whisper import WhisperModel
            
            # Check if model files exist
            model_path = Path.home() / ".cache" / "huggingface" / "hub"
            if model_path.exists():
                self.log_result("Whisper model cache", True, "Model cache directory exists")
            else:
                self.log_result("Whisper model cache", False, "Model will be downloaded on first use")
            
            return True
        except Exception as e:
            self.log_result("Whisper model", False, str(e))
            return False
    
    async def run_all_tests(self):
        """Run all tests"""
        print("=" * 50)
        print("VoiceFlow Backend Test Suite")
        print("=" * 50)
        print()
        
        # Basic tests
        self.test_imports()
        self.test_database_creation()
        self.test_ollama_connection()
        self.test_audio_device()
        self.test_whisper_model()
        
        # Async tests
        await self.test_websocket_server()
        
        # Summary
        print()
        print("=" * 50)
        print(f"Tests Passed: {self.results['tests_passed']}")
        print(f"Tests Failed: {self.results['tests_failed']}")
        print("=" * 50)
        
        # Save results
        results_file = Path("test_results.json")
        with open(results_file, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\nDetailed results saved to: {results_file}")
        
        return self.results["tests_failed"] == 0

if __name__ == "__main__":
    tester = BackendTester()
    success = asyncio.run(tester.run_all_tests())
    sys.exit(0 if success else 1)
