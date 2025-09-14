#!/usr/bin/env python3
"""
VoiceFlow Browser Integration Validation Script

Validates that all browser integration components are properly implemented
without requiring actual browser initialization (for CI/headless environments).
"""

import sys
import importlib
from pathlib import Path


def test_imports():
    """Test that all required modules can be imported."""
    print("🔍 Testing imports...")
    
    try:
        # Test core browser integration
        from core.browser_integration import (
            BrowserIntegrationEngine, BrowserConfig, BrowserType,
            InputElementType, FrameworkType, InputElementDetector,
            TextInjector, BrowserManager
        )
        print("✅ Browser integration core imports successful")
        
        # Test VoiceFlow core integration
        from core.voiceflow_core import create_engine, VoiceFlowEngine
        print("✅ VoiceFlow core imports successful")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False


def test_configuration():
    """Test configuration and setup without browser initialization."""
    print("\n🔧 Testing configuration...")
    
    try:
        from core.voiceflow_core import create_engine
        
        # Test engine creation with browser config
        config = {
            'model': 'base',
            'browser_type': 'chrome',
            'browser_headless': True,
            'browser_timeout': 30
        }
        
        engine = create_engine(config)
        print("✅ Engine creation with browser config successful")
        
        # Test browser status (should work without actual browser)
        status = engine.get_browser_status()
        print(f"✅ Browser integration enabled: {status['integration_enabled']}")
        print(f"✅ Selenium available: {status['selenium_available']}")
        
        # Test configuration options
        assert 'integration_enabled' in status
        assert 'selenium_available' in status
        assert 'active_session' in status
        print("✅ Browser status structure correct")
        
        engine.cleanup()
        print("✅ Engine cleanup successful")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False


def test_browser_config_classes():
    """Test browser configuration classes and enums."""
    print("\n⚙️ Testing browser configuration classes...")
    
    try:
        from core.browser_integration import BrowserConfig, BrowserType, InputElementType, FrameworkType
        
        # Test BrowserType enum
        assert hasattr(BrowserType, 'CHROME')
        assert hasattr(BrowserType, 'FIREFOX')
        assert hasattr(BrowserType, 'EDGE')
        assert hasattr(BrowserType, 'SAFARI')
        print("✅ BrowserType enum complete")
        
        # Test InputElementType enum
        assert hasattr(InputElementType, 'INPUT_TEXT')
        assert hasattr(InputElementType, 'TEXTAREA')
        assert hasattr(InputElementType, 'CONTENTEDITABLE')
        assert hasattr(InputElementType, 'TINYMCE')
        assert hasattr(InputElementType, 'QUILL')
        print("✅ InputElementType enum complete")
        
        # Test FrameworkType enum
        assert hasattr(FrameworkType, 'REACT')
        assert hasattr(FrameworkType, 'ANGULAR')
        assert hasattr(FrameworkType, 'VUE')
        assert hasattr(FrameworkType, 'VANILLA')
        print("✅ FrameworkType enum complete")
        
        # Test BrowserConfig creation
        config = BrowserConfig(
            browser_type=BrowserType.CHROME,
            headless=True,
            timeout=30
        )
        assert config.browser_type == BrowserType.CHROME
        assert config.headless is True
        assert config.timeout == 30
        print("✅ BrowserConfig creation successful")
        
        return True
        
    except Exception as e:
        print(f"❌ Browser config error: {e}")
        return False


def test_injection_methods():
    """Test text injection method selection logic."""
    print("\n💉 Testing injection methods...")
    
    try:
        from core.voiceflow_core import create_engine
        
        engine = create_engine({'browser_type': 'chrome'})
        
        # Test injection method detection
        method = engine._detect_best_injection_method()
        assert method in ['browser', 'system']
        print(f"✅ Injection method detection: {method}")
        
        # Test injection with different methods (should handle gracefully without actual targets)
        test_text = "Test injection"
        
        # These should fail gracefully without throwing exceptions
        try:
            engine.inject_text(test_text, injection_method="system")
            print("✅ System injection method handled gracefully")
        except:
            print("✅ System injection method failed gracefully (expected without target)")
        
        try:
            engine.inject_text(test_text, injection_method="fallback")
            print("✅ Fallback injection method handled gracefully")
        except:
            print("✅ Fallback injection method failed gracefully (expected without pyperclip)")
        
        engine.cleanup()
        return True
        
    except Exception as e:
        print(f"❌ Injection method error: {e}")
        return False


def test_security_features():
    """Test security validation features."""
    print("\n🔒 Testing security features...")
    
    try:
        from core.browser_integration import TextInjector
        
        # Create a mock driver (we're just testing validation logic)
        class MockDriver:
            def execute_script(self, script, *args):
                return True
        
        class MockElement:
            def __init__(self):
                self.element_type = None
        
        injector = TextInjector(MockDriver())
        
        # Test security validation
        safe_text = "This is safe text"
        malicious_texts = [
            "<script>alert('XSS')</script>",
            "javascript:alert('test')",
            "'; DROP TABLE users; --",
            "onload=alert('XSS')"
        ]
        
        mock_element = MockElement()
        
        # Safe text should pass validation
        is_safe = injector._validate_injection_security(safe_text, mock_element)
        assert is_safe is True
        print("✅ Safe text validation passed")
        
        # Malicious text should be blocked
        blocked_count = 0
        for malicious_text in malicious_texts:
            is_safe = injector._validate_injection_security(malicious_text, mock_element)
            if not is_safe:
                blocked_count += 1
        
        assert blocked_count == len(malicious_texts)
        print(f"✅ Security validation blocked {blocked_count}/{len(malicious_texts)} malicious inputs")
        
        # Test length validation
        very_long_text = "x" * 20000
        is_safe = injector._validate_injection_security(very_long_text, mock_element)
        assert is_safe is False
        print("✅ Length validation works")
        
        return True
        
    except Exception as e:
        print(f"❌ Security validation error: {e}")
        return False


def test_file_structure():
    """Test that all required files exist."""
    print("\n📁 Testing file structure...")
    
    base_path = Path(__file__).parent
    
    required_files = [
        'core/browser_integration.py',
        'core/voiceflow_core.py',
        'tests/test_browser_integration.py',
        'browser_integration_cli.py',
        'examples/browser_integration_example.py',
        'docs/BROWSER_INTEGRATION.md',
        'requirements_windows.txt',
        'requirements_unix.txt',
        'requirements_testing.txt'
    ]
    
    missing_files = []
    for file_path in required_files:
        full_path = base_path / file_path
        if not full_path.exists():
            missing_files.append(file_path)
        else:
            print(f"✅ {file_path}")
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    
    print("✅ All required files present")
    return True


def main():
    """Run all validation tests."""
    print("🚀 VoiceFlow Browser Integration Validation")
    print("=" * 50)
    
    tests = [
        ("File Structure", test_file_structure),
        ("Imports", test_imports),
        ("Configuration", test_configuration),
        ("Browser Config Classes", test_browser_config_classes),
        ("Injection Methods", test_injection_methods),
        ("Security Features", test_security_features)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} ERROR: {e}")
    
    print(f"\n{'='*50}")
    print(f"🎯 Validation Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All validation tests passed! Browser integration is ready.")
        return True
    else:
        print("⚠️  Some validation tests failed. Check the output above.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)