"""
Test suite for VoiceFlow Terminal Integration

Tests terminal detection, text injection, and command processing across different terminal types.
"""

import pytest
import sys
import os
import time
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from core.terminal_integration import (
        TerminalType, TerminalDetector, TerminalTextInjector, 
        TerminalCommandProcessor, TerminalEnhancedInjector,
        create_terminal_injector, test_terminal_detection, test_text_injection
    )
    TERMINAL_INTEGRATION_AVAILABLE = True
except ImportError as e:
    TERMINAL_INTEGRATION_AVAILABLE = False
    print(f"Terminal integration not available for testing: {e}")


class TestTerminalType(unittest.TestCase):
    """Test TerminalType enumeration."""
    
    def test_terminal_types_exist(self):
        """Test that all expected terminal types exist."""
        expected_types = [
            'UNKNOWN', 'CMD', 'POWERSHELL', 'POWERSHELL_CORE', 'WSL', 
            'GIT_BASH', 'VSCODE_TERMINAL', 'WINDOWS_TERMINAL', 'CONEMU',
            'MINTTY', 'HYPER', 'TERMINUS'
        ]
        
        for type_name in expected_types:
            self.assertTrue(hasattr(TerminalType, type_name))
    
    def test_terminal_type_values(self):
        """Test terminal type string values."""
        self.assertEqual(TerminalType.CMD.value, "cmd")
        self.assertEqual(TerminalType.POWERSHELL.value, "powershell")
        self.assertEqual(TerminalType.WSL.value, "wsl")
        self.assertEqual(TerminalType.VSCODE_TERMINAL.value, "vscode_terminal")


@pytest.mark.skipif(not TERMINAL_INTEGRATION_AVAILABLE, reason="Terminal integration not available")
class TestTerminalDetector(unittest.TestCase):
    """Test terminal detection functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = TerminalDetector()
    
    def test_detector_initialization(self):
        """Test detector initializes correctly."""
        self.assertIsInstance(self.detector, TerminalDetector)
        self.assertIsInstance(self.detector.terminal_signatures, dict)
        self.assertIsInstance(self.detector.window_classes, dict)
    
    def test_terminal_signatures(self):
        """Test terminal signature mappings."""
        # Test some key signatures
        self.assertEqual(self.detector.terminal_signatures['cmd.exe'], TerminalType.CMD)
        self.assertEqual(self.detector.terminal_signatures['powershell.exe'], TerminalType.POWERSHELL)
        self.assertEqual(self.detector.terminal_signatures['Code.exe'], TerminalType.VSCODE_TERMINAL)
    
    @patch('win32gui.GetForegroundWindow')
    @patch('win32gui.GetWindowText')
    @patch('win32gui.GetClassName')
    @patch('win32process.GetWindowThreadProcessId')
    @patch('win32api.OpenProcess')
    @patch('win32process.GetModuleFileNameEx')
    @patch('win32api.CloseHandle')
    def test_get_active_window_info(self, mock_close, mock_get_module, mock_open, 
                                   mock_get_thread, mock_get_class, mock_get_text, mock_get_window):
        """Test getting active window information."""
        # Mock Windows API calls
        mock_get_window.return_value = 12345
        mock_get_text.return_value = "Command Prompt"
        mock_get_class.return_value = "ConsoleWindowClass"
        mock_get_thread.return_value = (1, 5678)
        mock_open.return_value = 9999
        mock_get_module.return_value = "C:\\Windows\\System32\\cmd.exe"
        
        result = self.detector.get_active_window_info()
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result['hwnd'], 12345)
        self.assertEqual(result['title'], "Command Prompt")
        self.assertEqual(result['class'], "ConsoleWindowClass")
        self.assertEqual(result['executable'], "cmd.exe")
    
    def test_detect_by_executable_name(self):
        """Test terminal detection by executable name."""
        # Mock window info for different terminals
        test_cases = [
            {
                'window_info': {'executable': 'cmd.exe', 'title': 'Command Prompt', 'class': 'ConsoleWindowClass'},
                'expected_type': TerminalType.CMD
            },
            {
                'window_info': {'executable': 'powershell.exe', 'title': 'PowerShell', 'class': 'ConsoleWindowClass'},
                'expected_type': TerminalType.POWERSHELL
            },
            {
                'window_info': {'executable': 'wt.exe', 'title': 'Windows Terminal', 'class': 'WindowsTerminal'},
                'expected_type': TerminalType.WINDOWS_TERMINAL
            }
        ]
        
        for case in test_cases:
            terminal_type, metadata = self.detector.detect_terminal_type(case['window_info'])
            self.assertEqual(terminal_type, case['expected_type'])
            self.assertEqual(metadata['detection_method'], 'executable')
    
    def test_detect_by_title_heuristics(self):
        """Test terminal detection using title heuristics."""
        test_cases = [
            {
                'window_info': {'executable': 'unknown.exe', 'title': 'PowerShell 7.3.0', 'class': 'Unknown'},
                'expected_type': TerminalType.POWERSHELL_CORE
            },
            {
                'window_info': {'executable': 'unknown.exe', 'title': 'Ubuntu on Windows', 'class': 'Unknown'},
                'expected_type': TerminalType.WSL
            },
            {
                'window_info': {'executable': 'unknown.exe', 'title': 'Git Bash', 'class': 'Unknown'},
                'expected_type': TerminalType.GIT_BASH
            }
        ]
        
        for case in test_cases:
            terminal_type, metadata = self.detector.detect_terminal_type(case['window_info'])
            self.assertEqual(terminal_type, case['expected_type'])
            self.assertEqual(metadata['detection_method'], 'title_heuristic')
    
    def test_vscode_terminal_detection(self):
        """Test VS Code integrated terminal detection."""
        vscode_window_info = {
            'executable': 'code.exe',
            'title': 'Terminal - Visual Studio Code',
            'class': 'Chrome_WidgetWin_1'
        }
        
        terminal_type, metadata = self.detector.detect_terminal_type(vscode_window_info)
        self.assertEqual(terminal_type, TerminalType.VSCODE_TERMINAL)
    
    def test_unknown_terminal_detection(self):
        """Test detection of unknown terminal types."""
        unknown_window_info = {
            'executable': 'unknown_app.exe',
            'title': 'Some Random Application',
            'class': 'UnknownClass'
        }
        
        terminal_type, metadata = self.detector.detect_terminal_type(unknown_window_info)
        self.assertEqual(terminal_type, TerminalType.UNKNOWN)


@pytest.mark.skipif(not TERMINAL_INTEGRATION_AVAILABLE, reason="Terminal integration not available")
class TestTerminalTextInjector(unittest.TestCase):
    """Test terminal text injection functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.injector = TerminalTextInjector()
    
    def test_injector_initialization(self):
        """Test injector initializes correctly."""
        self.assertIsInstance(self.injector, TerminalTextInjector)
        self.assertIsInstance(self.injector.detector, TerminalDetector)
        self.assertIsInstance(self.injector.injection_strategies, dict)
        self.assertIsInstance(self.injector.terminal_configs, dict)
    
    def test_preprocess_text_cmd(self):
        """Test text preprocessing for CMD."""
        test_text = "echo Hello & echo World"
        processed = self.injector._preprocess_text(test_text, TerminalType.CMD)
        self.assertIn('^', processed)  # Should escape & character
    
    def test_preprocess_text_powershell(self):
        """Test text preprocessing for PowerShell."""
        test_text = "Write-Host 'Hello $world'"
        processed = self.injector._preprocess_text(test_text, TerminalType.POWERSHELL)
        self.assertIn('`', processed)  # Should escape $ character
    
    def test_preprocess_text_wsl(self):
        """Test text preprocessing for WSL."""
        test_text = "echo 'Hello $USER'"
        processed = self.injector._preprocess_text(test_text, TerminalType.WSL)
        self.assertIn('\\', processed)  # Should escape $ character
    
    @patch('keyboard.write')
    def test_direct_typing_injection(self, mock_keyboard_write):
        """Test direct typing injection method."""
        test_text = "echo 'test'"
        result = self.injector._inject_via_direct_typing(test_text)
        
        self.assertTrue(result)
        mock_keyboard_write.assert_called_once_with(test_text, delay=0.01)
    
    @patch('pyautogui.paste')
    @patch('pyautogui.copy')
    @patch('keyboard.send')
    def test_clipboard_injection(self, mock_keyboard_send, mock_copy, mock_paste):
        """Test clipboard-based injection method."""
        test_text = "echo 'test'"
        mock_paste.return_value = "original_clipboard"
        
        result = self.injector._inject_via_clipboard_paste(test_text)
        
        self.assertTrue(result)
        mock_copy.assert_called_with(test_text)
        mock_keyboard_send.assert_called_with('ctrl+v')
    
    def test_injection_strategy_mapping(self):
        """Test that all terminal types have injection strategies."""
        for terminal_type in TerminalType:
            self.assertIn(terminal_type, self.injector.injection_strategies)


@pytest.mark.skipif(not TERMINAL_INTEGRATION_AVAILABLE, reason="Terminal integration not available")
class TestTerminalCommandProcessor(unittest.TestCase):
    """Test terminal command processing functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = TerminalCommandProcessor()
    
    def test_processor_initialization(self):
        """Test processor initializes correctly."""
        self.assertIsInstance(self.processor, TerminalCommandProcessor)
        self.assertIsInstance(self.processor.command_patterns, dict)
    
    def test_navigation_commands(self):
        """Test navigation command processing."""
        test_cases = [
            ("change directory home", 'cd "home"'),
            ("go to downloads", 'cd "downloads"'),
            ("list files", "dir"),  # Windows adaptation
            ("show directory", "pwd"),
        ]
        
        for voice_input, expected_output in test_cases:
            result = self.processor.process_voice_command(voice_input, TerminalType.CMD)
            # For CMD, commands get adapted to Windows equivalents
            if "list files" in voice_input:
                self.assertEqual(result, "dir")
            elif "show directory" in voice_input:
                self.assertEqual(result, "cd")  # pwd becomes cd in Windows
            else:
                self.assertIn("cd", result)
    
    def test_file_operations(self):
        """Test file operation command processing."""
        test_cases = [
            ("create file test.txt", 'touch "test.txt"'),
            ("remove file test.txt", 'rm "test.txt"'),
            ("copy file1.txt to file2.txt", 'cp "file1.txt" "file2.txt"'),
        ]
        
        for voice_input, expected_pattern in test_cases:
            result = self.processor.process_voice_command(voice_input, TerminalType.WSL)
            self.assertIsNotNone(result)
            # For WSL, commands remain Unix-style
            if "create" in voice_input:
                self.assertIn("touch", result)
            elif "remove" in voice_input:
                self.assertIn("rm", result)
            elif "copy" in voice_input:
                self.assertIn("cp", result)
    
    def test_git_commands(self):
        """Test Git command processing."""
        test_cases = [
            ("git status", "git status"),
            ("git add all", "git add ."),
            ("git commit initial commit", 'git commit -m "initial commit"'),
            ("git push", "git push"),
        ]
        
        for voice_input, expected_output in test_cases:
            result = self.processor.process_voice_command(voice_input, TerminalType.GIT_BASH)
            self.assertEqual(result, expected_output)
    
    def test_windows_command_adaptation(self):
        """Test command adaptation for Windows terminals."""
        # Unix command that should be adapted for Windows
        unix_command = "ls -la"
        result = self.processor._adapt_command_for_terminal(unix_command, TerminalType.CMD)
        self.assertEqual(result, "dir")
        
        # PowerShell should also get Windows adaptations
        result = self.processor._adapt_command_for_terminal(unix_command, TerminalType.POWERSHELL)
        self.assertEqual(result, "dir")
    
    def test_unix_command_preservation(self):
        """Test that Unix commands are preserved for WSL/Git Bash."""
        unix_command = "ls -la"
        result = self.processor._adapt_command_for_terminal(unix_command, TerminalType.WSL)
        self.assertEqual(result, unix_command)  # Should remain unchanged
        
        result = self.processor._adapt_command_for_terminal(unix_command, TerminalType.GIT_BASH)
        self.assertEqual(result, unix_command)  # Should remain unchanged


@pytest.mark.skipif(not TERMINAL_INTEGRATION_AVAILABLE, reason="Terminal integration not available")
class TestTerminalEnhancedInjector(unittest.TestCase):
    """Test enhanced terminal injector with statistics."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.enhanced_injector = TerminalEnhancedInjector()
    
    def test_enhanced_injector_initialization(self):
        """Test enhanced injector initializes correctly."""
        self.assertIsInstance(self.enhanced_injector, TerminalEnhancedInjector)
        self.assertIsInstance(self.enhanced_injector.injector, TerminalTextInjector)
        self.assertIsInstance(self.enhanced_injector.processor, TerminalCommandProcessor)
        self.assertIsInstance(self.enhanced_injector.detector, TerminalDetector)
        self.assertIsInstance(self.enhanced_injector.stats, dict)
    
    def test_statistics_initialization(self):
        """Test statistics are properly initialized."""
        stats = self.enhanced_injector.stats
        expected_keys = [
            'total_injections', 'successful_injections', 'failed_injections', 
            'terminal_types_used'
        ]
        
        for key in expected_keys:
            self.assertIn(key, stats)
            if key == 'terminal_types_used':
                self.assertIsInstance(stats[key], dict)
            else:
                self.assertEqual(stats[key], 0)
    
    def test_get_statistics(self):
        """Test statistics reporting."""
        stats = self.enhanced_injector.get_statistics()
        
        expected_keys = [
            'total_injections', 'successful_injections', 'failed_injections',
            'success_rate_percent', 'terminal_types_used'
        ]
        
        for key in expected_keys:
            self.assertIn(key, stats)
        
        # Initially should have 0% success rate
        self.assertEqual(stats['success_rate_percent'], 0)
    
    @patch.object(TerminalDetector, 'detect_terminal_type')
    @patch.object(TerminalTextInjector, 'inject_text')
    def test_successful_injection_stats(self, mock_inject, mock_detect):
        """Test statistics tracking for successful injections."""
        # Mock successful injection
        mock_detect.return_value = (TerminalType.CMD, {'detection_method': 'executable'})
        mock_inject.return_value = True
        
        result = self.enhanced_injector.inject_enhanced_text("echo test")
        
        self.assertTrue(result)
        
        stats = self.enhanced_injector.get_statistics()
        self.assertEqual(stats['total_injections'], 1)
        self.assertEqual(stats['successful_injections'], 1)
        self.assertEqual(stats['failed_injections'], 0)
        self.assertEqual(stats['success_rate_percent'], 100.0)
        self.assertEqual(stats['terminal_types_used']['cmd'], 1)
    
    @patch.object(TerminalDetector, 'detect_terminal_type')
    @patch.object(TerminalTextInjector, 'inject_text')
    def test_failed_injection_stats(self, mock_inject, mock_detect):
        """Test statistics tracking for failed injections."""
        # Mock failed injection
        mock_detect.return_value = (TerminalType.CMD, {'detection_method': 'executable'})
        mock_inject.return_value = False
        
        result = self.enhanced_injector.inject_enhanced_text("echo test")
        
        self.assertFalse(result)
        
        stats = self.enhanced_injector.get_statistics()
        self.assertEqual(stats['total_injections'], 1)
        self.assertEqual(stats['successful_injections'], 0)
        self.assertEqual(stats['failed_injections'], 1)
        self.assertEqual(stats['success_rate_percent'], 0.0)


class TestIntegrationFunctions(unittest.TestCase):
    """Test integration and utility functions."""
    
    @pytest.mark.skipif(not TERMINAL_INTEGRATION_AVAILABLE, reason="Terminal integration not available")
    def test_create_terminal_injector(self):
        """Test terminal injector factory function."""
        injector = create_terminal_injector()
        self.assertIsInstance(injector, TerminalEnhancedInjector)
    
    @pytest.mark.skipif(not TERMINAL_INTEGRATION_AVAILABLE, reason="Terminal integration not available")
    def test_test_functions_exist(self):
        """Test that testing functions exist and are callable."""
        self.assertTrue(callable(test_terminal_detection))
        self.assertTrue(callable(test_text_injection))


class TestTerminalIntegrationEndToEnd(unittest.TestCase):
    """End-to-end tests for terminal integration."""
    
    @pytest.mark.skipif(not TERMINAL_INTEGRATION_AVAILABLE, reason="Terminal integration not available")
    def test_full_workflow_simulation(self):
        """Test complete workflow from detection to injection."""
        # Create enhanced injector
        injector = create_terminal_injector()
        
        # Test with empty text (should return False)
        result = injector.inject_enhanced_text("")
        self.assertFalse(result)
        
        # Test with valid text (may succeed or fail depending on environment)
        result = injector.inject_enhanced_text("echo 'integration test'")
        # Just check that it doesn't crash and returns a boolean
        self.assertIsInstance(result, bool)
        
        # Check statistics are updated
        stats = injector.get_statistics()
        self.assertGreaterEqual(stats['total_injections'], 1)


def run_terminal_integration_tests():
    """Run all terminal integration tests."""
    if not TERMINAL_INTEGRATION_AVAILABLE:
        print("❌ Terminal integration not available - skipping tests")
        return False
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestTerminalType,
        TestTerminalDetector,
        TestTerminalTextInjector,
        TestTerminalCommandProcessor,
        TestTerminalEnhancedInjector,
        TestIntegrationFunctions,
        TestTerminalIntegrationEndToEnd
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestClass(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Terminal Integration Test Results:")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print(f"{'='*50}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("VoiceFlow Terminal Integration Test Suite")
    print("=" * 50)
    
    success = run_terminal_integration_tests()
    
    if success:
        print("\n✅ All terminal integration tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some terminal integration tests failed!")
        sys.exit(1)