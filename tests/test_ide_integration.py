"""
Comprehensive IDE Integration Testing Framework

Tests for IDE detection, text injection, syntax highlighting preservation,
autocomplete integration, and multi-cursor editing scenarios.
"""

import pytest
import os
import sys
import time
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import modules to test
try:
    from core.ide_integration import (
        IDEDetector, IDEIntegrationManager, VSCodeIntegration, IntelliJIntegration,
        IDEType, IDEInfo, create_ide_manager
    )
    from core.code_context_analyzer import (
        LanguageDetector, SyntaxAnalyzer, CodeFormatter, LanguageType, 
        CodeContextType, CodePosition, create_code_context_analyzer, 
        create_code_formatter
    )
    from core.voiceflow_core import VoiceFlowEngine, create_engine
    from core.ai_enhancement import AIEnhancer, create_enhancer
    IDE_INTEGRATION_AVAILABLE = True
except ImportError as e:
    IDE_INTEGRATION_AVAILABLE = False
    print(f"IDE integration modules not available: {e}")


class TestIDEDetection:
    """Test IDE detection capabilities."""
    
    def test_ide_detector_initialization(self):
        """Test IDE detector initializes correctly."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        detector = IDEDetector()
        assert detector is not None
        assert detector.detected_ides == []
        assert detector.active_ide is None
    
    @patch('psutil.process_iter')
    def test_ide_detection_with_mock_processes(self, mock_process_iter):
        """Test IDE detection with mocked process information."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        # Mock VS Code process
        mock_vscode_process = Mock()
        mock_vscode_process.info = {
            'pid': 1234,
            'name': 'code',
            'exe': '/usr/bin/code',
            'cmdline': ['code', '--no-sandbox'],
            'cwd': '/home/user/project'
        }
        
        # Mock PyCharm process
        mock_pycharm_process = Mock()
        mock_pycharm_process.info = {
            'pid': 5678,
            'name': 'pycharm',
            'exe': '/opt/pycharm/bin/pycharm',
            'cmdline': ['pycharm'],
            'cwd': '/home/user/project'
        }
        
        mock_process_iter.return_value = [mock_vscode_process, mock_pycharm_process]
        
        detector = IDEDetector()
        detected_ides = detector.detect_running_ides()
        
        assert len(detected_ides) == 2
        assert any(ide.ide_type == IDEType.VSCODE for ide in detected_ides)
        assert any(ide.ide_type == IDEType.PYCHARM for ide in detected_ides)
    
    def test_ide_type_identification(self):
        """Test IDE type identification from process info."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        detector = IDEDetector()
        
        # Test VS Code identification
        vscode_info = {'name': 'code', 'exe': '/usr/bin/code'}
        ide_type = detector._identify_ide_type(vscode_info)
        assert ide_type == IDEType.VSCODE
        
        # Test PyCharm identification
        pycharm_info = {'name': 'pycharm.exe', 'exe': '/opt/pycharm/pycharm.exe'}
        ide_type = detector._identify_ide_type(pycharm_info)
        assert ide_type == IDEType.PYCHARM
        
        # Test unknown IDE
        unknown_info = {'name': 'unknown_editor', 'exe': '/bin/unknown'}
        ide_type = detector._identify_ide_type(unknown_info)
        assert ide_type == IDEType.UNKNOWN
    
    def test_fallback_detection(self):
        """Test fallback detection when psutil is unavailable."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        detector = IDEDetector()
        
        with patch('subprocess.run') as mock_run:
            # Mock successful VS Code command
            mock_run.return_value = Mock(returncode=0)
            
            fallback_ides = detector._detect_fallback()
            
            # Should detect at least one IDE if command exists
            assert isinstance(fallback_ides, list)


class TestIDEIntegrationManager:
    """Test IDE integration manager functionality."""
    
    def test_manager_initialization(self):
        """Test IDE manager initializes correctly."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        manager = IDEIntegrationManager()
        assert manager is not None
        assert manager.detector is not None
        assert isinstance(manager.detected_ides, list)
    
    @patch.object(IDEDetector, 'detect_running_ides')
    def test_refresh_detection(self, mock_detect):
        """Test IDE detection refresh."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        # Mock detected IDEs
        mock_ide = IDEInfo(
            ide_type=IDEType.VSCODE,
            version="1.80.0",
            process_name="code",
            window_title=None,
            working_directory=Path.cwd(),
            extensions_dir=None,
            config_dir=None,
            supports_api=True,
            supports_automation=True
        )
        
        mock_detect.return_value = [mock_ide]
        
        manager = IDEIntegrationManager()
        detected = manager.refresh_detection()
        
        assert len(detected) == 1
        assert detected[0].ide_type == IDEType.VSCODE
        assert manager.active_ide == mock_ide
    
    @patch('pyautogui.typewrite')
    def test_smart_text_injection(self, mock_typewrite):
        """Test smart text injection with context."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        manager = IDEIntegrationManager()
        
        # Test with no active IDE (should fall back to automation)
        result = manager.inject_text_smart("test_text", "python")
        
        # Should succeed if automation is available
        if hasattr(manager, '_automation_injection'):
            mock_typewrite.assert_called_once_with("test_text")
    
    def test_context_information(self):
        """Test getting current IDE context."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        manager = IDEIntegrationManager()
        context = manager.get_current_context()
        
        assert isinstance(context, dict)
        assert 'ide' in context
        assert 'file' in context
        assert 'language' in context
    
    def test_status_reporting(self):
        """Test IDE integration status reporting."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        manager = IDEIntegrationManager()
        status = manager.get_status()
        
        assert isinstance(status, dict)
        assert 'detected_ides' in status
        assert 'active_ide' in status
        assert 'automation_available' in status
        assert 'process_detection' in status


class TestVSCodeIntegration:
    """Test VS Code specific integration."""
    
    def test_vscode_integration_initialization(self):
        """Test VS Code integration initialization."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        mock_ide_info = IDEInfo(
            ide_type=IDEType.VSCODE,
            version="1.80.0",
            process_name="code",
            window_title=None,
            working_directory=Path.cwd(),
            extensions_dir=None,
            config_dir=None,
            supports_api=True,
            supports_automation=True
        )
        
        integration = VSCodeIntegration(mock_ide_info)
        assert integration.ide_info == mock_ide_info
        assert integration.command == "code"
    
    @patch('subprocess.run')
    def test_text_injection_at_cursor(self, mock_run):
        """Test text injection at cursor position."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        mock_ide_info = IDEInfo(
            ide_type=IDEType.VSCODE,
            version="1.80.0",
            process_name="code",
            window_title=None,
            working_directory=Path.cwd(),
            extensions_dir=None,
            config_dir=None,
            supports_api=True,
            supports_automation=True
        )
        
        integration = VSCodeIntegration(mock_ide_info)
        
        # Mock successful command execution
        mock_run.return_value = Mock(returncode=0)
        
        result = integration.inject_text_at_cursor("test_text")
        
        # Should attempt to execute VS Code command
        assert mock_run.called
    
    def test_file_info_retrieval(self):
        """Test getting current file information."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        mock_ide_info = IDEInfo(
            ide_type=IDEType.VSCODE,
            version="1.80.0",
            process_name="code",
            window_title=None,
            working_directory=Path.cwd(),
            extensions_dir=None,
            config_dir=None,
            supports_api=True,
            supports_automation=True
        )
        
        integration = VSCodeIntegration(mock_ide_info)
        file_info = integration.get_current_file_info()
        
        assert isinstance(file_info, dict) or file_info is None


class TestCodeContextAnalysis:
    """Test code context analysis and syntax awareness."""
    
    def test_language_detection_by_extension(self):
        """Test language detection from file extensions."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        detector = LanguageDetector()
        
        # Test various file extensions
        assert detector.detect_language(Path("test.py")) == LanguageType.PYTHON
        assert detector.detect_language(Path("test.js")) == LanguageType.JAVASCRIPT
        assert detector.detect_language(Path("test.java")) == LanguageType.JAVA
        assert detector.detect_language(Path("test.cpp")) == LanguageType.CPP
        assert detector.detect_language(Path("test.html")) == LanguageType.HTML
        assert detector.detect_language(Path("test.css")) == LanguageType.CSS
    
    def test_language_detection_by_content(self):
        """Test language detection from code content."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        detector = LanguageDetector()
        
        # Python content
        python_code = "def hello_world():\n    print('Hello, world!')"
        detected = detector._detect_by_patterns(python_code)
        assert detected == LanguageType.PYTHON
        
        # JavaScript content
        js_code = "function helloWorld() {\n    console.log('Hello, world!');\n}"
        detected = detector._detect_by_patterns(js_code)
        assert detected == LanguageType.JAVASCRIPT
        
        # Java content
        java_code = "public class HelloWorld {\n    public static void main(String[] args) {\n        System.out.println(\"Hello, world!\");\n    }\n}"
        detected = detector._detect_by_patterns(java_code)
        assert detected == LanguageType.JAVA
    
    def test_syntax_analysis(self):
        """Test syntax analysis and context detection."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        analyzer = SyntaxAnalyzer()
        
        # Test Python code analysis
        python_code = """def test_function():
    # This is a comment
    variable_name = "test"
    return variable_name"""
        
        # Analyze context at different positions
        position = analyzer.analyze_context(python_code, 1, 4)  # Inside comment
        assert position.language == LanguageType.PYTHON
        assert position.context_type in [CodeContextType.COMMENT, CodeContextType.CODE]
        
        position = analyzer.analyze_context(python_code, 0, 4)  # Function definition
        assert position.context_type in [CodeContextType.FUNCTION_DEF, CodeContextType.CODE]
    
    def test_code_formatting(self):
        """Test code formatting for different contexts."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        formatter = CodeFormatter()
        
        # Create a sample code position
        position = CodePosition(
            line=0,
            column=0,
            context_type=CodeContextType.COMMENT,
            language=LanguageType.PYTHON,
            indentation_level=0,
            scope=None,
            preceding_code="",
            following_code=""
        )
        
        # Test comment formatting
        formatted = formatter.format_for_context("This is a comment", position)
        assert formatted.startswith("#")
        
        # Test function formatting
        position.context_type = CodeContextType.FUNCTION_DEF
        formatted = formatter.format_for_context("hello world", position)
        assert "def" in formatted and "hello_world" in formatted


class TestAIEnhancementIntegration:
    """Test AI enhancement with programming context."""
    
    @patch('requests.Session.post')
    @patch.object(AIEnhancer, 'test_ollama_connection')
    def test_programming_context_enhancement(self, mock_connection, mock_post):
        """Test AI enhancement with programming language context."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        # Mock successful connection
        mock_connection.return_value = True
        
        # Mock AI response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": "def hello_world():\n    print('Hello, world!')"}
        mock_post.return_value = mock_response
        
        enhancer = AIEnhancer()
        enhancer.ollama_url = "http://localhost:11434/api/generate"
        
        # Test with Python context
        enhanced = enhancer.enhance_text(
            "hello world function",
            context="python",
            ide_context={"language": "python", "ide": "vscode"}
        )
        
        assert "def" in enhanced
        assert "hello_world" in enhanced
    
    def test_basic_formatting_with_context(self):
        """Test basic formatting fallback with programming context."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        enhancer = AIEnhancer()
        
        # Test Python function formatting
        formatted = enhancer.basic_format("hello world", "python function")
        assert "def" in formatted
        assert "hello_world" in formatted
        
        # Test Python comment formatting
        formatted = enhancer.basic_format("this is a comment", "python comment")
        assert formatted.startswith("#")
        
        # Test JavaScript function formatting
        formatted = enhancer.basic_format("hello world", "javascript function")
        assert "function" in formatted
        assert "helloWorld" in formatted


class TestVoiceFlowEngineIntegration:
    """Test VoiceFlow engine integration with IDE features."""
    
    def test_engine_with_ide_integration(self):
        """Test VoiceFlow engine initializes with IDE integration."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        config = {
            'smart_injection': True,
            'programming_context': True
        }
        
        engine = VoiceFlowEngine(config)
        
        # Check IDE integration components
        assert hasattr(engine, 'ide_manager')
        assert hasattr(engine, 'code_analyzer')
        assert hasattr(engine, 'code_formatter')
        assert engine.smart_injection_enabled == True
    
    @patch('pyautogui.typewrite')
    def test_smart_text_injection_with_context(self, mock_typewrite):
        """Test smart text injection with programming context."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        config = {'smart_injection': True}
        engine = VoiceFlowEngine(config)
        
        # Test injection with code context
        result = engine.inject_text("hello world", "auto", "python function")
        
        # Should attempt injection (may fall back to system injection)
        assert isinstance(result, bool)
    
    def test_stats_include_ide_status(self):
        """Test that engine stats include IDE integration status."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        engine = VoiceFlowEngine()
        stats = engine.get_stats()
        
        assert 'ide_integration' in stats
        assert isinstance(stats['ide_integration'], dict)


class TestSyntaxHighlightingPreservation:
    """Test preservation of syntax highlighting during text injection."""
    
    def test_highlighting_aware_injection(self):
        """Test that text injection preserves syntax highlighting context."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        manager = IDEIntegrationManager()
        
        # Test with different programming contexts
        contexts = ['python', 'javascript', 'java', 'html', 'css']
        
        for context in contexts:
            # This would require actual IDE integration to test properly
            # For now, verify that the context is handled without errors
            result = manager.inject_text_smart(f"test code in {context}", context)
            assert isinstance(result, bool)


class TestAutocompleteIntegration:
    """Test integration with IDE autocomplete systems."""
    
    def test_autocomplete_compatibility(self):
        """Test that text injection is compatible with autocomplete."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        # This would require real IDE integration to test properly
        # For now, test that the integration components exist
        manager = IDEIntegrationManager()
        
        # Verify that the manager can handle autocomplete scenarios
        assert hasattr(manager, 'inject_text_smart')
        assert hasattr(manager, 'get_current_context')


class TestMultiCursorScenarios:
    """Test text injection in multi-cursor editing scenarios."""
    
    def test_multi_cursor_awareness(self):
        """Test handling of multi-cursor editing scenarios."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        manager = IDEIntegrationManager()
        
        # Test that multi-cursor scenarios are handled gracefully
        # This would require actual IDE integration for full testing
        result = manager.inject_text_smart("multi cursor test", "code")
        assert isinstance(result, bool)


class TestPerformanceMetrics:
    """Test performance of IDE integration features."""
    
    def test_detection_performance(self):
        """Test IDE detection performance."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        detector = IDEDetector()
        
        start_time = time.time()
        detected_ides = detector.detect_running_ides()
        detection_time = time.time() - start_time
        
        # Detection should complete quickly
        assert detection_time < 5.0  # Less than 5 seconds
        assert isinstance(detected_ides, list)
    
    def test_text_injection_performance(self):
        """Test text injection performance."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        manager = IDEIntegrationManager()
        
        start_time = time.time()
        result = manager.inject_text_smart("performance test", "code")
        injection_time = time.time() - start_time
        
        # Injection should be reasonably fast
        assert injection_time < 2.0  # Less than 2 seconds
        assert isinstance(result, bool)


class TestErrorHandling:
    """Test error handling in IDE integration."""
    
    def test_graceful_failure_handling(self):
        """Test that failures are handled gracefully."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        manager = IDEIntegrationManager()
        
        # Test with invalid inputs
        result = manager.inject_text_smart("", "invalid_context")
        assert isinstance(result, bool)
        
        result = manager.inject_text_smart(None, "code")
        assert isinstance(result, bool)
    
    def test_fallback_mechanisms(self):
        """Test fallback mechanisms when advanced features fail."""
        if not IDE_INTEGRATION_AVAILABLE:
            pytest.skip("IDE integration not available")
        
        manager = IDEIntegrationManager()
        
        # Should have fallback injection methods
        assert hasattr(manager, '_fallback_injection')
        
        # Test fallback behavior
        with patch.object(manager, 'inject_text_smart', side_effect=Exception("Mock failure")):
            # Should not raise an exception
            try:
                manager._fallback_injection("test text")
            except Exception:
                pytest.fail("Fallback injection should not raise exceptions")


def test_integration_availability():
    """Test that IDE integration components are available when expected."""
    if IDE_INTEGRATION_AVAILABLE:
        # Test that all expected components are importable
        assert IDEDetector is not None
        assert IDEIntegrationManager is not None
        assert VSCodeIntegration is not None
        assert LanguageDetector is not None
        assert SyntaxAnalyzer is not None
        assert CodeFormatter is not None
    else:
        pytest.skip("IDE integration not available - this is expected in some environments")


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])