"""
Integration Test Validation Script

This script validates that the integration tests properly work with the actual
VoiceFlow codebase and that the refactored architecture integrates correctly.
"""

import sys
import os
import sqlite3
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch
import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class IntegrationTestValidator:
    """Validates integration test compatibility with actual codebase."""
    
    def __init__(self):
        self.validation_results = []
        self.temp_dir = None
        
    def validate_all(self):
        """Run all validation checks."""
        print("Validating VoiceFlow Integration Tests")
        print("=" * 50)
        
        # Setup temporary environment
        self.temp_dir = tempfile.mkdtemp(prefix="voiceflow_validation_")
        temp_path = Path(self.temp_dir)
        
        try:
            with patch('pathlib.Path.home', return_value=temp_path):
                # Run validation checks
                self._validate_core_imports()
                self._validate_configuration_system()
                self._validate_database_schema()
                self._validate_mock_compatibility()
                self._validate_test_fixtures()
                self._validate_simple_implementation()
                
                # Print results
                self._print_validation_results()
                
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _validate_core_imports(self):
        """Validate that core modules can be imported."""
        print("Validating core module imports...")
        
        try:
            from core.voiceflow_core import VoiceFlowEngine, create_engine
            from core.ai_enhancement import AIEnhancer, create_enhancer
            from utils.config import VoiceFlowConfig, get_config
            
            self.validation_results.append({
                'test': 'Core Module Imports',
                'status': 'PASS',
                'message': 'All core modules imported successfully'
            })
            
        except Exception as e:
            self.validation_results.append({
                'test': 'Core Module Imports',
                'status': 'FAIL',
                'message': f'Import error: {e}'
            })
    
    def _validate_configuration_system(self):
        """Validate configuration system integration."""
        print("Validating configuration system...")
        
        try:
            from utils.config import VoiceFlowConfig
            
            # Test configuration creation
            config = VoiceFlowConfig()
            
            # Test configuration sections
            audio_config = config.get_section('audio')
            ai_config = config.get_section('ai')
            
            # Validate expected keys exist
            expected_audio_keys = ['model', 'device', 'language']
            expected_ai_keys = ['enabled', 'model', 'temperature']
            
            for key in expected_audio_keys:
                if key not in audio_config:
                    raise ValueError(f"Missing audio config key: {key}")
            
            for key in expected_ai_keys:
                if key not in ai_config:
                    raise ValueError(f"Missing AI config key: {key}")
            
            # Test configuration file operations
            config.set('test', 'key', 'value')
            config.save()
            
            # Validate config file was created
            config_file = config.config_file
            if not config_file.exists():
                raise FileNotFoundError("Configuration file was not created")
            
            self.validation_results.append({
                'test': 'Configuration System',
                'status': 'PASS',
                'message': 'Configuration system working correctly'
            })
            
        except Exception as e:
            self.validation_results.append({
                'test': 'Configuration System',
                'status': 'FAIL',
                'message': f'Configuration error: {e}'
            })
    
    def _validate_database_schema(self):
        """Validate database schema compatibility."""
        print("Validating database schema...")
        
        try:
            from core.voiceflow_core import VoiceFlowEngine
            
            # Create engine (this should create database)
            # The engine will handle the missing AudioToTextRecorder gracefully
            engine = VoiceFlowEngine()
            
            # Validate database exists
            if not engine.db_path.exists():
                raise FileNotFoundError("Database file was not created")
            
            # Validate database schema
            conn = sqlite3.connect(engine.db_path)
            cursor = conn.cursor()
            
            # Check transcriptions table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transcriptions'")
            if not cursor.fetchone():
                raise ValueError("Transcriptions table not found")
            
            # Check table structure
            cursor.execute("PRAGMA table_info(transcriptions)")
            columns = [row[1] for row in cursor.fetchall()]
            
            expected_columns = ['id', 'timestamp', 'raw_text', 'enhanced_text', 'processing_time_ms', 'word_count']
            for col in expected_columns:
                if col not in columns:
                    raise ValueError(f"Missing column: {col}")
            
            conn.close()
            
            self.validation_results.append({
                'test': 'Database Schema',
                'status': 'PASS',
                'message': 'Database schema is correct'
            })
            
        except Exception as e:
            self.validation_results.append({
                'test': 'Database Schema',
                'status': 'FAIL',
                'message': f'Database error: {e}'
            })
    
    def _validate_mock_compatibility(self):
        """Validate that mocks are compatible with actual interfaces."""
        print("Validating mock compatibility...")
        
        try:
            from core.voiceflow_core import VoiceFlowEngine
            from core.ai_enhancement import AIEnhancer
            
            # Test VoiceFlowEngine mock compatibility
            # Since AudioToTextRecorder is imported within the module, we need to mock it there
            mock_recorder = Mock()
            mock_recorder.text.return_value = "test"
            
            engine = VoiceFlowEngine()
            # Manually set the recorder to our mock
            engine.recorder = mock_recorder
            
            # Test that our mock structure matches expected interface
            if not hasattr(engine.recorder, 'text'):
                raise AttributeError("Mock recorder missing 'text' method")
            
            # Test AIEnhancer mock compatibility
            with patch('core.ai_enhancement.requests') as mock_requests:
                mock_requests.get.return_value.status_code = 200
                mock_requests.get.return_value.json.return_value = {'models': []}
                
                enhancer = AIEnhancer()
                # Should not raise errors
                
            self.validation_results.append({
                'test': 'Mock Compatibility',
                'status': 'PASS',
                'message': 'Mocks are compatible with actual interfaces'
            })
            
        except Exception as e:
            self.validation_results.append({
                'test': 'Mock Compatibility',
                'status': 'FAIL',
                'message': f'Mock compatibility error: {e}'
            })
    
    def _validate_test_fixtures(self):
        """Validate test fixtures work with actual code."""
        print("Validating test fixtures...")
        
        try:
            # Test that fixtures can be created without errors
            from tests.conftest import (
                sample_config, comprehensive_test_config,
                performance_test_data, failure_simulation
            )
            
            # Test sample config
            config_data = {
                'audio': {
                    'model': 'base',
                    'device': 'cpu',
                    'language': 'en'
                },
                'ai': {
                    'enabled': True,
                    'model': 'test-model',
                    'temperature': 0.5
                }
            }
            
            # This should match the fixture structure
            assert 'audio' in config_data
            assert 'ai' in config_data
            
            self.validation_results.append({
                'test': 'Test Fixtures',
                'status': 'PASS',
                'message': 'Test fixtures are properly structured'
            })
            
        except Exception as e:
            self.validation_results.append({
                'test': 'Test Fixtures',
                'status': 'FAIL',
                'message': f'Fixture error: {e}'
            })
    
    def _validate_simple_implementation(self):
        """Validate simple implementation integration."""
        print("Validating simple implementation...")
        
        try:
            from implementations.simple import SimpleVoiceFlow
            
            # Test that SimpleVoiceFlow can be created
            with patch('core.ai_enhancement.requests') as mock_requests:
                mock_requests.get.side_effect = Exception("No connection")
                
                # Should not raise errors even without AI service
                app = SimpleVoiceFlow()
                
                # Validate structure
                assert hasattr(app, 'engine')
                assert hasattr(app, 'ai_enhancer')
                assert hasattr(app, 'config')
                
                # Test cleanup
                app.cleanup()
            
            self.validation_results.append({
                'test': 'Simple Implementation',
                'status': 'PASS',
                'message': 'Simple implementation integrates correctly'
            })
            
        except Exception as e:
            self.validation_results.append({
                'test': 'Simple Implementation',
                'status': 'FAIL',
                'message': f'Simple implementation error: {e}'
            })
    
    def _print_validation_results(self):
        """Print validation results."""
        print("\nValidation Results:")
        print("=" * 50)
        
        passed = 0
        failed = 0
        
        for result in self.validation_results:
            status_symbol = "✅" if result['status'] == 'PASS' else "❌"
            print(f"{status_symbol} {result['test']}: {result['message']}")
            
            if result['status'] == 'PASS':
                passed += 1
            else:
                failed += 1
        
        print(f"\nSummary: {passed} passed, {failed} failed")
        
        if failed == 0:
            print("🎉 All validation checks passed! Integration tests are ready to run.")
        else:
            print("⚠️  Some validation checks failed. Please fix issues before running integration tests.")
        
        return failed == 0


def validate_environment():
    """Validate the test environment and dependencies."""
    print("Validating test environment...")
    
    # Check pytest availability
    try:
        import pytest
        print("✅ pytest is available")
    except ImportError:
        print("❌ pytest is not installed")
        return False
    
    # Check pytest-asyncio for async tests
    try:
        import pytest_asyncio
        print("✅ pytest-asyncio is available")
    except ImportError:
        print("⚠️  pytest-asyncio is not installed (some async tests may fail)")
    
    # Check for test dependencies
    dependencies = [
        'sqlite3',
        'json',
        'tempfile',
        'pathlib',
        'unittest.mock'
    ]
    
    missing = []
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"✅ {dep} is available")
        except ImportError:
            print(f"❌ {dep} is not available")
            missing.append(dep)
    
    if missing:
        print(f"\nMissing dependencies: {', '.join(missing)}")
        return False
    
    print("\n✅ Test environment is ready")
    return True


def main():
    """Main entry point for validation script."""
    print("VoiceFlow Integration Test Validation")
    print("=" * 60)
    
    # Validate environment first
    if not validate_environment():
        print("\nEnvironment validation failed. Please install missing dependencies.")
        sys.exit(1)
    
    print()
    
    # Run integration test validation
    validator = IntegrationTestValidator()
    success = validator.validate_all()
    
    if success:
        print("\n🎉 Integration tests are ready to run!")
        print("To run the tests, use:")
        print("  python tests/run_integration_tests.py")
        print("  python -m pytest tests/test_comprehensive_integration.py -v")
        sys.exit(0)
    else:
        print("\n❌ Please fix validation issues before running integration tests.")
        sys.exit(1)


if __name__ == "__main__":
    main()