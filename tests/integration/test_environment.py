import pytest
pytestmark = pytest.mark.integration

"""
Environment Setup Verification Tests
"""

import os
import sys
import importlib
import subprocess
import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

REPORT_DIR = Path("test_results")
REPORT_DIR.mkdir(exist_ok=True)

TEST_CONFIG = {
    "platform": "Windows" if sys.platform == "win32" else "Linux",
    "is_wsl": "microsoft-standard" in os.uname().release if sys.platform == "linux" else False,
}


class EnvironmentTester:
    def __init__(self):
        self.results = {
            "platform": {},
            "python": {},
            "dependencies": {},
            "permissions": {},
            "audio": {},
            "overall": "PENDING"
        }
        
    def test_platform(self):
        """Test platform compatibility"""
        logger.info("Testing platform compatibility...")
        
        self.results["platform"]["system"] = TEST_CONFIG["platform"]
        self.results["platform"]["is_wsl"] = TEST_CONFIG["is_wsl"]
        
        # Check if running on Windows
        if TEST_CONFIG["platform"] != "Windows" and not TEST_CONFIG["is_wsl"]:
            logger.warning("Not running on Windows - audio/keyboard may not work properly")
            self.results["platform"]["compatible"] = False
        else:
            self.results["platform"]["compatible"] = True
            
        # Check for admin privileges on Windows
        if TEST_CONFIG["platform"] == "Windows":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                self.results["platform"]["is_admin"] = bool(is_admin)
                if not is_admin:
                    logger.warning("Not running as administrator - some features may be limited")
            except:
                self.results["platform"]["is_admin"] = False
                
        return self.results["platform"]["compatible"]
        
    def test_python_version(self):
        """Test Python version compatibility"""
        logger.info("Testing Python version...")
        
        version_info = sys.version_info
        self.results["python"]["version"] = f"{version_info.major}.{version_info.minor}.{version_info.micro}"
        self.results["python"]["executable"] = sys.executable
        
        # Require Python 3.8+
        if version_info.major == 3 and version_info.minor >= 8:
            self.results["python"]["compatible"] = True
        else:
            self.results["python"]["compatible"] = False
            logger.error(f"Python 3.8+ required, found {self.results['python']['version']}")
            
        return self.results["python"]["compatible"]
        
    def test_dependencies(self):
        """Test all required dependencies"""
        logger.info("Testing dependencies...")
        
        dependencies = {
            "core": [
                ("numpy", None),
                ("keyboard", None),
                ("pyperclip", None),
            ],
            "audio": [
                ("sounddevice", "sd"),
                ("wave", None),
                ("struct", None),
            ],
            "whisper": [
                ("faster_whisper", None),
                ("whisper", None),
                ("torch", None),
            ],
            "optional": [
                ("RealtimeSTT", None),
                ("webrtcvad", None),
                ("halo", None),
            ]
        }
        
        for category, deps in dependencies.items():
            self.results["dependencies"][category] = {}
            for dep_name, import_name in deps:
                try:
                    if import_name:
                        importlib.import_module(import_name)
                    else:
                        importlib.import_module(dep_name)
                    self.results["dependencies"][category][dep_name] = {
                        "installed": True,
                        "version": self._get_module_version(dep_name)
                    }
                    logger.info(f"✓ {dep_name} installed")
                except ImportError:
                    self.results["dependencies"][category][dep_name] = {
                        "installed": False,
                        "version": None
                    }
                    if category in ["core", "audio"]:
                        logger.error(f"✗ {dep_name} NOT installed (REQUIRED)")
                    else:
                        logger.warning(f"✗ {dep_name} not installed (optional)")
                        
        # Check if at least one Whisper implementation is available
        whisper_available = any(
            self.results["dependencies"]["whisper"][dep]["installed"] 
            for dep in self.results["dependencies"]["whisper"]
        )
        
        core_available = all(
            self.results["dependencies"]["core"][dep]["installed"] 
            for dep in self.results["dependencies"]["core"]
        )
        
        audio_available = all(
            self.results["dependencies"]["audio"][dep]["installed"] 
            for dep in self.results["dependencies"]["audio"]
        )
        
        self.results["dependencies"]["summary"] = {
            "core_ok": core_available,
            "audio_ok": audio_available,
            "whisper_ok": whisper_available,
            "overall": core_available and audio_available and whisper_available
        }
        
        return self.results["dependencies"]["summary"]["overall"]
        
    def test_audio_devices(self):
        """Test audio device availability"""
        logger.info("Testing audio devices...")
        
        try:
            import sounddevice as sd
            devices = sd.query_devices()
            
            input_devices = [d for d in devices if d['max_input_channels'] > 0]
            output_devices = [d for d in devices if d['max_output_channels'] > 0]
            
            self.results["audio"]["devices"] = {
                "total": len(devices),
                "input": len(input_devices),
                "output": len(output_devices),
                "default_input": sd.default.device[0],
                "default_output": sd.default.device[1]
            }
            
            if len(input_devices) > 0:
                self.results["audio"]["has_microphone"] = True
                logger.info(f"✓ Found {len(input_devices)} input devices")
                
                # List input devices
                for i, dev in enumerate(input_devices):
                    logger.info(f"  - {dev['name']} ({dev['max_input_channels']} channels)")
            else:
                self.results["audio"]["has_microphone"] = False
                logger.error("✗ No input devices found!")
                
        except Exception as e:
            self.results["audio"]["error"] = str(e)
            self.results["audio"]["has_microphone"] = False
            logger.error(f"✗ Audio device test failed: {e}")
            
        return self.results["audio"].get("has_microphone", False)
        
    def test_permissions(self):
        """Test file system and clipboard permissions"""
        logger.info("Testing permissions...")
        
        # Test file write permissions
        try:
            test_file = Path("test_permissions.tmp")
            test_file.write_text("test")
            test_file.unlink()
            self.results["permissions"]["file_write"] = True
            logger.info("✓ File write permissions OK")
        except Exception as e:
            self.results["permissions"]["file_write"] = False
            logger.error(f"✗ File write failed: {e}")
            
        # Test clipboard access
        try:
            import pyperclip
            original = pyperclip.paste()
            pyperclip.copy("test")
            result = pyperclip.paste()
            pyperclip.copy(original)  # Restore
            self.results["permissions"]["clipboard"] = result == "test"
            if self.results["permissions"]["clipboard"]:
                logger.info("✓ Clipboard access OK")
            else:
                logger.error("✗ Clipboard access failed")
        except Exception as e:
            self.results["permissions"]["clipboard"] = False
            logger.error(f"✗ Clipboard test failed: {e}")
            
        return all(self.results["permissions"].values())
        
    def _get_module_version(self, module_name):
        """Get version of installed module"""
        try:
            module = importlib.import_module(module_name)
            if hasattr(module, "__version__"):
                return module.__version__
            elif hasattr(module, "VERSION"):
                return module.VERSION
            else:
                # Try pip show
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "show", module_name],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('Version:'):
                            return line.split(':')[1].strip()
        except:
            pass
        return "unknown"
        
    def run_all_tests(self):
        """Run all environment tests"""
        logger.info("="*60)
        logger.info("ENVIRONMENT VERIFICATION TEST SUITE")
        logger.info("="*60)
        
        tests = [
            ("Platform", self.test_platform),
            ("Python Version", self.test_python_version),
            ("Dependencies", self.test_dependencies),
            ("Audio Devices", self.test_audio_devices),
            ("Permissions", self.test_permissions),
        ]
        
        all_passed = True
        for test_name, test_func in tests:
            logger.info(f"\n--- {test_name} Test ---")
            try:
                passed = test_func()
                if not passed:
                    all_passed = False
            except Exception as e:
                logger.error(f"Test failed with exception: {e}")
                all_passed = False
                
        self.results["overall"] = "PASSED" if all_passed else "FAILED"
        
        # Save results
        self.save_results()
        
        return all_passed
        
    def save_results(self):
        """Save test results to file"""
        report_file = REPORT_DIR / "environment_test_results.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        logger.info(f"\nResults saved to: {report_file}")
        
        # Create summary report
        summary_file = REPORT_DIR / "environment_summary.txt"
        with open(summary_file, 'w') as f:
            f.write("ENVIRONMENT TEST SUMMARY\n")
            f.write("="*60 + "\n\n")
            f.write(f"Overall Result: {self.results['overall']}\n\n")
            
            f.write("Platform:\n")
            f.write(f"  - System: {self.results['platform']['system']}\n")
            f.write(f"  - WSL: {self.results['platform']['is_wsl']}\n")
            f.write(f"  - Compatible: {self.results['platform']['compatible']}\n\n")
            
            f.write("Python:\n")
            f.write(f"  - Version: {self.results['python']['version']}\n")
            f.write(f"  - Compatible: {self.results['python']['compatible']}\n\n")
            
            f.write("Dependencies:\n")
            if 'summary' in self.results['dependencies']:
                f.write(f"  - Core: {self.results['dependencies']['summary']['core_ok']}\n")
                f.write(f"  - Audio: {self.results['dependencies']['summary']['audio_ok']}\n")
                f.write(f"  - Whisper: {self.results['dependencies']['summary']['whisper_ok']}\n\n")
                
            f.write("Audio:\n")
            if 'devices' in self.results['audio']:
                f.write(f"  - Input Devices: {self.results['audio']['devices']['input']}\n")
                f.write(f"  - Has Microphone: {self.results['audio'].get('has_microphone', False)}\n\n")
                
            f.write("Permissions:\n")
            for perm, status in self.results['permissions'].items():
                f.write(f"  - {perm}: {status}\n")
                
        logger.info(f"Summary saved to: {summary_file}")


if __name__ == "__main__":
    tester = EnvironmentTester()
    success = tester.run_all_tests()
    
    if success:
        logger.info("\n✅ Environment is ready for VoiceFlow!")
    else:
        logger.error("\n❌ Environment setup incomplete. Please fix the issues above.")
        
    sys.exit(0 if success else 1)
