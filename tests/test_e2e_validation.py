"""
VoiceFlow E2E Test Environment Validation
==========================================

Validates that the test environment is properly set up and all dependencies
are available before running end-to-end tests.

This module provides:
1. Environment validation
2. Dependency checking
3. Test data preparation
4. Mock service setup
5. Configuration validation
"""

import json
import os
import sys
import tempfile
import threading
import time
import wave
from pathlib import Path
from typing import Dict, List, Optional, Any
import sqlite3
import subprocess

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class E2EValidationError(Exception):
    """Exception raised when E2E validation fails."""
    pass


class E2EValidator:
    """Validates E2E test environment and dependencies."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.validation_results = {}
        self.issues = []
        self.warnings = []
        
    def validate_all(self) -> Dict[str, Any]:
        """Run all validation checks."""
        print("🔍 Validating VoiceFlow E2E Test Environment")
        print("=" * 50)
        
        validations = [
            ('Python Environment', self._validate_python_environment),
            ('Project Structure', self._validate_project_structure),
            ('Dependencies', self._validate_dependencies),
            ('Core Modules', self._validate_core_modules),
            ('Test Infrastructure', self._validate_test_infrastructure),
            ('Audio Processing', self._validate_audio_processing),
            ('Database Operations', self._validate_database_operations),
            ('Configuration System', self._validate_configuration_system),
            ('Mock Services', self._validate_mock_services),
            ('File Permissions', self._validate_file_permissions)
        ]
        
        for name, validation_func in validations:
            print(f"📋 {name}...", end=' ')
            try:
                result = validation_func()
                if result['success']:
                    print("✅")
                else:
                    print("❌")
                    self.issues.extend(result.get('issues', []))
                    
                self.validation_results[name] = result
                
            except Exception as e:
                print(f"❌ ({str(e)})")
                self.issues.append(f"{name}: {str(e)}")
                self.validation_results[name] = {
                    'success': False,
                    'error': str(e)
                }
        
        # Summary
        self._print_validation_summary()
        
        return {
            'success': len(self.issues) == 0,
            'issues': self.issues,
            'warnings': self.warnings,
            'results': self.validation_results
        }
    
    def _validate_python_environment(self) -> Dict[str, Any]:
        """Validate Python environment."""
        issues = []
        
        # Check Python version
        if sys.version_info < (3, 7):
            issues.append(f"Python 3.7+ required, found {sys.version}")
        
        # Check virtual environment (recommended)
        if not hasattr(sys, 'real_prefix') and not sys.base_prefix != sys.prefix:
            self.warnings.append("Virtual environment not detected (recommended)")
        
        # Check pip
        try:
            import pip
        except ImportError:
            issues.append("pip not available")
        
        return {
            'success': len(issues) == 0,
            'issues': issues,
            'python_version': sys.version,
            'python_path': sys.executable
        }
    
    def _validate_project_structure(self) -> Dict[str, Any]:
        """Validate project structure."""
        issues = []
        
        required_dirs = [
            'core',
            'utils', 
            'implementations',
            'python',
            'native',
            'tests',
            'electron'
        ]
        
        required_files = [
            'core/__init__.py',
            'core/voiceflow_core.py',
            'core/ai_enhancement.py',
            'utils/config.py',
            'implementations/simple.py',
            'python/stt_server.py',
            'native/voiceflow_native.py',
            'voiceflow_mcp_server.py',
            'tests/test_end_to_end.py'
        ]
        
        # Check directories
        for dir_name in required_dirs:
            dir_path = self.project_root / dir_name
            if not dir_path.exists():
                issues.append(f"Missing directory: {dir_name}")
            elif not dir_path.is_dir():
                issues.append(f"Not a directory: {dir_name}")
        
        # Check files
        for file_path in required_files:
            full_path = self.project_root / file_path
            if not full_path.exists():
                issues.append(f"Missing file: {file_path}")
            elif not full_path.is_file():
                issues.append(f"Not a file: {file_path}")
        
        return {
            'success': len(issues) == 0,
            'issues': issues,
            'project_root': str(self.project_root)
        }
    
    def _validate_dependencies(self) -> Dict[str, Any]:
        """Validate required dependencies."""
        issues = []
        
        # Core dependencies
        core_deps = [
            'pytest',
            'sqlite3',
            'json',
            'threading',
            'tempfile',
            'wave',
            'pathlib'
        ]
        
        # Optional dependencies (for full functionality)
        optional_deps = [
            'numpy',
            'requests',
            'asyncio',
            'websockets'
        ]
        
        missing_core = []
        missing_optional = []
        
        for dep in core_deps:
            try:
                __import__(dep)
            except ImportError:
                missing_core.append(dep)
        
        for dep in optional_deps:
            try:
                __import__(dep)
            except ImportError:
                missing_optional.append(dep)
        
        if missing_core:
            issues.append(f"Missing core dependencies: {', '.join(missing_core)}")
        
        if missing_optional:
            self.warnings.append(f"Missing optional dependencies: {', '.join(missing_optional)}")
        
        return {
            'success': len(missing_core) == 0,
            'issues': issues,
            'missing_core': missing_core,
            'missing_optional': missing_optional
        }
    
    def _validate_core_modules(self) -> Dict[str, Any]:
        """Validate core VoiceFlow modules."""
        issues = []
        
        try:
            # Test core module imports
            from core.voiceflow_core import VoiceFlowEngine, create_engine
            from core.ai_enhancement import AIEnhancer, create_enhancer
            from utils.config import VoiceFlowConfig, get_config
            
            # Test basic functionality
            config = get_config()
            if config is None:
                issues.append("Config system not working")
            
        except ImportError as e:
            issues.append(f"Core module import failed: {e}")
        except Exception as e:
            issues.append(f"Core module error: {e}")
        
        return {
            'success': len(issues) == 0,
            'issues': issues
        }
    
    def _validate_test_infrastructure(self) -> Dict[str, Any]:
        """Validate test infrastructure."""
        issues = []
        
        # Check pytest configuration
        pytest_ini = self.project_root / 'pytest.ini'
        if not pytest_ini.exists():
            self.warnings.append("pytest.ini not found")
        
        # Check test requirements
        test_requirements = self.project_root / 'requirements_testing.txt'
        if not test_requirements.exists():
            self.warnings.append("requirements_testing.txt not found")
        
        # Test pytest execution
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pytest', '--version'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                issues.append("pytest not working properly")
        except Exception as e:
            issues.append(f"pytest test failed: {e}")
        
        return {
            'success': len(issues) == 0,
            'issues': issues
        }
    
    def _validate_audio_processing(self) -> Dict[str, Any]:
        """Validate audio processing capabilities."""
        issues = []
        
        try:
            # Test audio file creation
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create test audio file
                audio_path = Path(temp_dir) / "test.wav"
                
                # Simple WAV file creation
                sample_rate = 16000
                duration = 1.0
                samples = int(sample_rate * duration)
                
                with wave.open(str(audio_path), 'wb') as wav_file:
                    wav_file.setnchannels(1)
                    wav_file.setsampwidth(2)
                    wav_file.setframerate(sample_rate)
                    wav_file.writeframes(b'\x00' * samples * 2)
                
                if not audio_path.exists():
                    issues.append("Cannot create audio files")
                
                # Test audio file reading
                with wave.open(str(audio_path), 'rb') as wav_file:
                    frames = wav_file.getnframes()
                    if frames == 0:
                        issues.append("Cannot read audio files")
                        
        except Exception as e:
            issues.append(f"Audio processing error: {e}")
        
        return {
            'success': len(issues) == 0,
            'issues': issues
        }
    
    def _validate_database_operations(self) -> Dict[str, Any]:
        """Validate database operations."""
        issues = []
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                db_path = Path(temp_dir) / "test.db"
                
                # Test database creation
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                
                # Create test table
                cursor.execute('''
                    CREATE TABLE test_table (
                        id INTEGER PRIMARY KEY,
                        text TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Insert test data
                cursor.execute("INSERT INTO test_table (text) VALUES (?)", ("test",))
                conn.commit()
                
                # Query test data
                cursor.execute("SELECT * FROM test_table")
                rows = cursor.fetchall()
                
                if len(rows) != 1:
                    issues.append("Database operations not working")
                
                conn.close()
                
        except Exception as e:
            issues.append(f"Database error: {e}")
        
        return {
            'success': len(issues) == 0,
            'issues': issues
        }
    
    def _validate_configuration_system(self) -> Dict[str, Any]:
        """Validate configuration system."""
        issues = []
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                config_path = Path(temp_dir) / "config.json"
                
                # Test config creation
                test_config = {
                    "audio": {"model": "base", "device": "cpu"},
                    "ai": {"enabled": True, "model": "test"}
                }
                
                with open(config_path, 'w') as f:
                    json.dump(test_config, f)
                
                # Test config reading
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                
                if loaded_config != test_config:
                    issues.append("Config serialization not working")
                
        except Exception as e:
            issues.append(f"Configuration system error: {e}")
        
        return {
            'success': len(issues) == 0,
            'issues': issues
        }
    
    def _validate_mock_services(self) -> Dict[str, Any]:
        """Validate mock service capabilities."""
        issues = []
        
        try:
            # Test HTTP server mock
            from http.server import HTTPServer, BaseHTTPRequestHandler
            
            class TestHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'OK')
                
                def log_message(self, format, *args):
                    pass
            
            # Try to start server briefly
            server = HTTPServer(('localhost', 0), TestHandler)
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            time.sleep(0.1)
            server.shutdown()
            
        except Exception as e:
            issues.append(f"Mock service error: {e}")
        
        return {
            'success': len(issues) == 0,
            'issues': issues
        }
    
    def _validate_file_permissions(self) -> Dict[str, Any]:
        """Validate file system permissions."""
        issues = []
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Test directory creation
                test_dir = temp_path / "test_dir"
                test_dir.mkdir()
                
                if not test_dir.exists():
                    issues.append("Cannot create directories")
                
                # Test file creation
                test_file = test_dir / "test.txt"
                test_file.write_text("test content")
                
                if not test_file.exists():
                    issues.append("Cannot create files")
                
                # Test file reading
                content = test_file.read_text()
                if content != "test content":
                    issues.append("Cannot read files")
                
        except Exception as e:
            issues.append(f"File permission error: {e}")
        
        return {
            'success': len(issues) == 0,
            'issues': issues
        }
    
    def _print_validation_summary(self):
        """Print validation summary."""
        print("\n" + "=" * 50)
        print("📊 Validation Summary")
        print("=" * 50)
        
        total_checks = len(self.validation_results)
        passed_checks = sum(1 for r in self.validation_results.values() if r['success'])
        failed_checks = total_checks - passed_checks
        
        print(f"Total Checks: {total_checks}")
        print(f"✅ Passed: {passed_checks}")
        print(f"❌ Failed: {failed_checks}")
        print(f"⚠️  Warnings: {len(self.warnings)}")
        
        if self.issues:
            print("\n🔴 Issues Found:")
            for issue in self.issues:
                print(f"  • {issue}")
        
        if self.warnings:
            print("\n🟡 Warnings:")
            for warning in self.warnings:
                print(f"  • {warning}")
        
        # Overall status
        if len(self.issues) == 0:
            print("\n✅ Environment validation PASSED")
            print("🚀 Ready to run E2E tests!")
        else:
            print("\n❌ Environment validation FAILED")
            print("🔧 Please resolve the issues above before running E2E tests")
        
        print("=" * 50)


def main():
    """Main entry point for validation."""
    validator = E2EValidator()
    result = validator.validate_all()
    
    # Exit with appropriate code
    sys.exit(0 if result['success'] else 1)


if __name__ == '__main__':
    main()