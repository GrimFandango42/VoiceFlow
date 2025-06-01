#!/usr/bin/env python3
"""
VoiceFlow Comprehensive Test Suite
Tests all components and validates readiness for end-user testing
"""

import os
import sys
import subprocess
import importlib
import json
import time
import requests
from pathlib import Path

class VoiceFlowTester:
    def __init__(self):
        self.test_results = {
            "setup": {},
            "dependencies": {},
            "services": {},
            "integration": {},
            "performance": {},
            "summary": {
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "warnings": 0
            }
        }
        
    def log(self, message, level="INFO"):
        timestamp = time.strftime("%H:%M:%S")
        # Handle Unicode issues on Windows
        try:
            print(f"[{timestamp}] {level}: {message}")
        except UnicodeEncodeError:
            # Fallback to ASCII-safe version
            safe_message = message.encode('ascii', 'replace').decode('ascii')
            print(f"[{timestamp}] {level}: {safe_message}")
        
    def test_python_environment(self):
        """Test Python environment and virtual environment"""
        self.log("Testing Python environment...")
        
        try:
            # Check Python version
            version = sys.version_info
            if version.major >= 3 and version.minor >= 8:
                self.test_results["setup"]["python_version"] = "PASS"
                self.log(f"[PASS] Python {version.major}.{version.minor}.{version.micro}")
            else:
                self.test_results["setup"]["python_version"] = "FAIL"
                self.log(f"[FAIL] Python version too old: {version.major}.{version.minor}")
                
            # Check if we're in virtual environment
            venv_path = os.environ.get('VIRTUAL_ENV')
            if venv_path or hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
                self.test_results["setup"]["virtual_env"] = "PASS"
                self.log("[PASS] Virtual environment active")
            else:
                self.test_results["setup"]["virtual_env"] = "WARNING"
                self.log("[WARN] Not in virtual environment")
                
        except Exception as e:
            self.test_results["setup"]["python_environment"] = f"FAIL: {e}"
            self.log(f"❌ Python environment error: {e}")
            
    def test_dependencies(self):
        """Test critical dependencies for VoiceFlow native mode"""
        self.log("Testing dependencies...")
        
        required_packages = {
            "pyautogui": "Text injection",
            "keyboard": "Global hotkeys", 
            "pywin32": "Windows API access",
            "RealtimeSTT": "Speech-to-text",
            "faster_whisper": "Whisper engine",
            "requests": "HTTP requests",
            "websockets": "WebSocket server",
            "numpy": "Numerical processing"
        }
        
        for package, description in required_packages.items():
            try:
                if package == "pywin32":
                    import win32api
                    self.test_results["dependencies"][package] = "PASS"
                    self.log(f"✅ {package} ({description})")
                elif package == "faster_whisper":
                    import faster_whisper
                    self.test_results["dependencies"][package] = "PASS"
                    self.log(f"✅ {package} ({description})")
                else:
                    importlib.import_module(package)
                    self.test_results["dependencies"][package] = "PASS"
                    self.log(f"✅ {package} ({description})")
            except ImportError as e:
                self.test_results["dependencies"][package] = f"FAIL: {e}"
                self.log(f"❌ {package} missing ({description})")
                
    def test_ollama_service(self):
        """Test Ollama service connectivity and models"""
        self.log("Testing Ollama service...")
        
        ollama_urls = [
            "http://localhost:11434/api/tags",
            "http://172.30.248.191:11434/api/tags",
            "http://127.0.0.1:11434/api/tags"
        ]
        
        for url in ollama_urls:
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    models = response.json().get('models', [])
                    model_names = [m.get('name', '') for m in models]
                    
                    self.test_results["services"]["ollama_connectivity"] = "PASS"
                    self.test_results["services"]["ollama_url"] = url
                    self.test_results["services"]["available_models"] = model_names
                    
                    self.log(f"✅ Ollama connected: {url}")
                    self.log(f"📦 Available models: {', '.join(model_names)}")
                    
                    # Check for compatible models
                    compatible_models = [name for name in model_names if any(x in name.lower() for x in ['deepseek', 'llama', 'qwen'])]
                    if compatible_models:
                        self.test_results["services"]["compatible_models"] = compatible_models
                        self.log(f"✅ Compatible AI models found: {', '.join(compatible_models)}")
                    else:
                        self.test_results["services"]["compatible_models"] = "WARNING"
                        self.log("⚠️  No compatible AI models found")
                    return
                    
            except Exception as e:
                continue
                
        self.test_results["services"]["ollama_connectivity"] = "FAIL"
        self.log("❌ Ollama service not accessible")
        
    def test_gpu_availability(self):
        """Test GPU availability for Whisper acceleration"""
        self.log("Testing GPU availability...")
        
        try:
            import torch
            if torch.cuda.is_available():
                gpu_count = torch.cuda.device_count()
                gpu_name = torch.cuda.get_device_name(0) if gpu_count > 0 else "Unknown"
                
                self.test_results["services"]["gpu_available"] = "PASS"
                self.test_results["services"]["gpu_count"] = gpu_count
                self.test_results["services"]["gpu_name"] = gpu_name
                
                self.log(f"✅ GPU available: {gpu_name}")
                self.log(f"🚀 CUDA devices: {gpu_count}")
            else:
                self.test_results["services"]["gpu_available"] = "WARNING"
                self.log("⚠️  GPU not available - will use CPU")
                
        except ImportError:
            self.test_results["services"]["gpu_available"] = "FAIL"
            self.log("❌ PyTorch not available for GPU detection")
            
    def test_file_structure(self):
        """Test that all required files are present"""
        self.log("Testing file structure...")
        
        required_files = {
            "python/stt_server.py": "Main server script",
            "VoiceFlow-Invisible.bat": "Invisible launcher",
            "VoiceFlow-Native.bat": "Native launcher", 
            "Install-Native-Mode.bat": "Dependencies installer",
            "VoiceFlow-TrulyInvisible.ps1": "PowerShell tray script"
        }
        
        base_path = Path(".")
        
        for file_path, description in required_files.items():
            full_path = base_path / file_path
            if full_path.exists():
                self.test_results["setup"][file_path] = "PASS"
                self.log(f"✅ {file_path} ({description})")
            else:
                self.test_results["setup"][file_path] = "FAIL"
                self.log(f"❌ Missing: {file_path}")
                
    def test_whisper_basic(self):
        """Basic test of Whisper functionality"""
        self.log("Testing Whisper basic functionality...")
        
        try:
            from faster_whisper import WhisperModel
            
            # Try to load a small model for testing
            model = WhisperModel("tiny", device="cpu", compute_type="int8")
            self.test_results["integration"]["whisper_load"] = "PASS"
            self.log("✅ Whisper model loads successfully")
            
            # Test with a simple audio file (if available)
            # For now, just confirm the model can be instantiated
            
        except Exception as e:
            self.test_results["integration"]["whisper_load"] = f"FAIL: {e}"
            self.log(f"❌ Whisper test failed: {e}")
            
    def run_all_tests(self):
        """Run comprehensive test suite"""
        self.log(">> Starting VoiceFlow Comprehensive Test Suite")
        self.log("=" * 60)
        
        test_methods = [
            self.test_python_environment,
            self.test_file_structure,
            self.test_dependencies,
            self.test_ollama_service,
            self.test_gpu_availability,
            self.test_whisper_basic
        ]
        
        for test_method in test_methods:
            try:
                test_method()
                self.log("-" * 40)
            except Exception as e:
                self.log(f"❌ Test method {test_method.__name__} failed: {e}")
                
        self.generate_summary()
        self.save_results()
        
    def generate_summary(self):
        """Generate test summary"""
        self.log("📊 TEST SUMMARY")
        self.log("=" * 60)
        
        # Count results
        total_tests = 0
        passed = 0
        failed = 0
        warnings = 0
        
        for category in self.test_results.values():
            if isinstance(category, dict) and category != self.test_results["summary"]:
                for test, result in category.items():
                    total_tests += 1
                    if isinstance(result, str):
                        if result == "PASS":
                            passed += 1
                        elif result == "WARNING":
                            warnings += 1
                        elif result.startswith("FAIL"):
                            failed += 1
                        elif result == "FAIL":
                            failed += 1
                            
        self.test_results["summary"]["total_tests"] = total_tests
        self.test_results["summary"]["passed"] = passed
        self.test_results["summary"]["failed"] = failed
        self.test_results["summary"]["warnings"] = warnings
        
        self.log(f"Total Tests: {total_tests}")
        self.log(f"✅ Passed: {passed}")
        self.log(f"⚠️  Warnings: {warnings}")
        self.log(f"❌ Failed: {failed}")
        
        # Overall readiness assessment
        if failed == 0 and warnings <= 2:
            readiness = "READY"
            self.log("🎯 STATUS: READY FOR END-USER TESTING")
        elif failed <= 2:
            readiness = "MOSTLY_READY"
            self.log("⚠️  STATUS: MOSTLY READY - Minor issues to resolve")
        else:
            readiness = "NOT_READY"
            self.log("❌ STATUS: NOT READY - Major issues need fixing")
            
        self.test_results["summary"]["readiness"] = readiness
        
    def save_results(self):
        """Save test results to file"""
        try:
            with open("comprehensive_test_results.json", "w") as f:
                json.dump(self.test_results, f, indent=2)
            self.log("💾 Test results saved to comprehensive_test_results.json")
        except Exception as e:
            self.log(f"❌ Failed to save results: {e}")

if __name__ == "__main__":
    # Change to VoiceFlow directory
    os.chdir(Path(__file__).parent)
    
    tester = VoiceFlowTester()
    tester.run_all_tests()
