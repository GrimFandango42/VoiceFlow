#!/usr/bin/env python3
"""
Basic CI test that doesn't require GUI components.
This is a simplified test to validate our CI/CD pipeline.
"""

import sys
import os
from pathlib import Path

def test_python_version():
    """Test that we have the right Python version."""
    assert sys.version_info >= (3, 8), f"Python 3.8+ required, got {sys.version_info}"
    print("✅ Python version check passed")

def test_import_basic_modules():
    """Test that basic modules can be imported."""
    try:
        import pytest
        import yaml
        import psutil
        print("✅ Basic module imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_file_structure():
    """Test that expected files exist."""
    expected_files = [
        "requirements_testing.txt",
        "test_orchestrator.py", 
        "utils/config.py",
        "core/voiceflow_core.py"
    ]
    
    missing_files = []
    for file_path in expected_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    
    print("✅ File structure check passed")
    return True

def test_config_module():
    """Test that config module works without GUI dependencies."""
    try:
        # Add current directory to path for imports
        sys.path.insert(0, str(Path.cwd()))
        
        print(f"  Current working directory: {Path.cwd()}")
        print(f"  Python path includes: {sys.path[0]}")
        
        # Check if utils module exists
        utils_path = Path("utils")
        if not utils_path.exists():
            print(f"  ❌ utils directory not found at {utils_path.absolute()}")
            return False
        
        config_path = utils_path / "config.py"
        if not config_path.exists():
            print(f"  ❌ config.py not found at {config_path.absolute()}")
            return False
        
        print(f"  ✅ Found config module at {config_path.absolute()}")
        
        from utils.config import VoiceFlowConfig
        config = VoiceFlowConfig()
        
        # Test basic config access
        model = config.get('audio', 'model')
        silence_duration = config.get('audio', 'post_speech_silence_duration')
        
        print(f"  Config audio.model: {model}")
        print(f"  Config audio.post_speech_silence_duration: {silence_duration}")
        
        assert model == 'base', f"Expected 'base', got '{model}'"
        assert silence_duration == 1.3, f"Expected 1.3, got {silence_duration}"
        
        print("✅ Config module test passed")
        return True
    except Exception as e:
        print(f"❌ Config test failed: {e}")
        print(f"  Exception type: {type(e).__name__}")
        import traceback
        print(f"  Traceback: {traceback.format_exc()}")
        return False

def main():
    """Run all basic tests."""
    print("🚀 Running VoiceFlow Basic CI Tests")
    print("=" * 50)
    
    tests = [
        test_python_version,
        test_import_basic_modules,
        test_file_structure,
        test_config_module
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            result = test()
            if result is None or result:  # None or True means success
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test.__name__} failed with exception: {e}")
            failed += 1
    
    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All basic tests passed!")
        return 0
    else:
        print("💥 Some tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())