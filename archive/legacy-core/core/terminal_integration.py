"""
Terminal Integration Module for VoiceFlow

Provides specialized text injection methods for terminal environments including:
- Command Prompt, PowerShell, WSL
- VS Code integrated terminal
- Windows Terminal, ConEmu, Git Bash
- Terminal detection and context awareness
"""

import os
import re
import sys
import time
import json
import subprocess
import threading
from typing import Dict, Optional, Tuple, List, Any
from enum import Enum
from pathlib import Path

# Platform-specific imports with graceful fallbacks
try:
    if sys.platform.startswith('win'):
        import win32api
        import win32con
        import win32gui
        import win32process
        import win32clipboard
        import ctypes
        from ctypes import wintypes
        WINDOWS_AVAILABLE = True
    else:
        WINDOWS_AVAILABLE = False
except ImportError:
    WINDOWS_AVAILABLE = False

try:
    import pyautogui
    import keyboard
    AUTOMATION_AVAILABLE = True
except ImportError:
    AUTOMATION_AVAILABLE = False

# Import VS Code integration
try:
    from .vscode_terminal_api import create_vscode_terminal_integration
    VSCODE_INTEGRATION_AVAILABLE = True
except ImportError:
    try:
        from vscode_terminal_api import create_vscode_terminal_integration
        VSCODE_INTEGRATION_AVAILABLE = True
    except ImportError:
        VSCODE_INTEGRATION_AVAILABLE = False


class TerminalType(Enum):
    """Enumeration of supported terminal types."""
    UNKNOWN = "unknown"
    CMD = "cmd"
    POWERSHELL = "powershell"
    POWERSHELL_CORE = "pwsh" 
    WSL = "wsl"
    GIT_BASH = "git_bash"
    VSCODE_TERMINAL = "vscode_terminal"
    WINDOWS_TERMINAL = "windows_terminal"
    CONEMU = "conemu"
    MINTTY = "mintty"
    HYPER = "hyper"
    TERMINUS = "terminus"


class TerminalDetector:
    """Detects terminal applications and their types."""
    
    def __init__(self):
        self.terminal_signatures = {
            # Windows built-in terminals
            'cmd.exe': TerminalType.CMD,
            'powershell.exe': TerminalType.POWERSHELL,
            'pwsh.exe': TerminalType.POWERSHELL_CORE,
            
            # WSL
            'wsl.exe': TerminalType.WSL,
            'bash.exe': TerminalType.WSL,  # WSL bash
            
            # Third-party terminals
            'WindowsTerminal.exe': TerminalType.WINDOWS_TERMINAL,
            'wt.exe': TerminalType.WINDOWS_TERMINAL,
            'ConEmu64.exe': TerminalType.CONEMU,
            'ConEmu.exe': TerminalType.CONEMU,
            'mintty.exe': TerminalType.MINTTY,
            'sh.exe': TerminalType.GIT_BASH,  # Git Bash
            'Hyper.exe': TerminalType.HYPER,
            'Terminus.exe': TerminalType.TERMINUS,
            
            # VS Code
            'Code.exe': TerminalType.VSCODE_TERMINAL,  # Requires additional detection
        }
        
        # Window class names for additional detection
        self.window_classes = {
            'ConsoleWindowClass': TerminalType.CMD,
            'WindowsTerminal': TerminalType.WINDOWS_TERMINAL,
            'ConEmuConsole': TerminalType.CONEMU,
            'mintty': TerminalType.MINTTY,
            'Chrome_WidgetWin_1': TerminalType.VSCODE_TERMINAL,  # VS Code window class
        }
    
    def get_active_window_info(self) -> Optional[Dict[str, Any]]:
        """Get detailed information about the active window."""
        if not WINDOWS_AVAILABLE:
            return None
        
        try:
            hwnd = win32gui.GetForegroundWindow()
            if not hwnd:
                return None
            
            # Get window title and class
            window_title = win32gui.GetWindowText(hwnd)
            window_class = win32gui.GetClassName(hwnd)
            
            # Get process information
            _, process_id = win32process.GetWindowThreadProcessId(hwnd)
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, 
                False, 
                process_id
            )
            
            try:
                executable_path = win32process.GetModuleFileNameEx(process_handle, 0)
                executable_name = os.path.basename(executable_path).lower()
            except:
                executable_name = "unknown"
            finally:
                win32api.CloseHandle(process_handle)
            
            return {
                'hwnd': hwnd,
                'title': window_title,
                'class': window_class,
                'executable': executable_name,
                'executable_path': executable_path if 'executable_path' in locals() else '',
                'process_id': process_id
            }
            
        except Exception as e:
            print(f"[TERMINAL] Error getting window info: {e}")
            return None
    
    def detect_terminal_type(self, window_info: Optional[Dict[str, Any]] = None) -> Tuple[TerminalType, Dict[str, Any]]:
        """
        Detect the type of terminal currently active.
        
        Returns:
            Tuple of (TerminalType, detection_metadata)
        """
        if not window_info:
            window_info = self.get_active_window_info()
        
        if not window_info:
            return TerminalType.UNKNOWN, {'reason': 'no_window_info'}
        
        executable = window_info.get('executable', '').lower()
        window_title = window_info.get('title', '').lower()
        window_class = window_info.get('class', '')
        
        metadata = {
            'executable': executable,
            'title': window_title,
            'class': window_class,
            'detection_method': 'unknown'
        }
        
        # Primary detection by executable name
        if executable in self.terminal_signatures:
            terminal_type = self.terminal_signatures[executable]
            metadata['detection_method'] = 'executable'
            
            # Special handling for VS Code to detect integrated terminal
            if terminal_type == TerminalType.VSCODE_TERMINAL:
                if self._is_vscode_terminal_active(window_info):
                    metadata['detection_method'] = 'vscode_terminal_heuristic'
                    return TerminalType.VSCODE_TERMINAL, metadata
                else:
                    # VS Code is open but terminal may not be active
                    return TerminalType.UNKNOWN, metadata
            
            return terminal_type, metadata
        
        # Secondary detection by window class
        if window_class in self.window_classes:
            terminal_type = self.window_classes[window_class]
            metadata['detection_method'] = 'window_class'
            return terminal_type, metadata
        
        # Heuristic detection based on window title patterns
        terminal_type = self._detect_by_title_heuristics(window_title)
        if terminal_type != TerminalType.UNKNOWN:
            metadata['detection_method'] = 'title_heuristic'
            return terminal_type, metadata
        
        # Check if it's a console window
        if self._is_console_window(window_info):
            metadata['detection_method'] = 'console_detection'
            return TerminalType.CMD, metadata  # Default to CMD for console windows
        
        return TerminalType.UNKNOWN, metadata
    
    def _is_vscode_terminal_active(self, window_info: Dict[str, Any]) -> bool:
        """Check if VS Code's integrated terminal is currently active."""
        title = window_info.get('title', '').lower()
        
        # VS Code terminal indicators in title
        terminal_indicators = [
            'terminal',
            'powershell',
            'cmd',
            'bash',
            'wsl',
            'git bash'
        ]
        
        # Check if title contains terminal indicators along with VS Code patterns
        if any(indicator in title for indicator in terminal_indicators):
            if 'visual studio code' in title or 'vscode' in title:
                return True
        
        # Additional heuristic: check for common VS Code terminal title patterns
        vscode_patterns = [
            r'.*terminal.*visual studio code',
            r'.*vscode.*terminal',
            r'.*code.exe.*terminal'
        ]
        
        for pattern in vscode_patterns:
            if re.search(pattern, title, re.IGNORECASE):
                return True
        
        return False
    
    def _detect_by_title_heuristics(self, title: str) -> TerminalType:
        """Detect terminal type using window title heuristics."""
        title_lower = title.lower()
        
        # PowerShell patterns
        if any(pattern in title_lower for pattern in ['powershell', 'ps>', 'ps1']):
            if 'core' in title_lower or 'pwsh' in title_lower:
                return TerminalType.POWERSHELL_CORE
            return TerminalType.POWERSHELL
        
        # CMD patterns
        if any(pattern in title_lower for pattern in ['command prompt', 'cmd.exe', 'c:\\windows\\system32\\cmd.exe']):
            return TerminalType.CMD
        
        # WSL patterns
        if any(pattern in title_lower for pattern in ['ubuntu', 'debian', 'wsl', 'bash', 'linux']):
            return TerminalType.WSL
        
        # Git Bash patterns
        if any(pattern in title_lower for pattern in ['git bash', 'mingw', 'msys']):
            return TerminalType.GIT_BASH
        
        # Windows Terminal patterns
        if 'windows terminal' in title_lower:
            return TerminalType.WINDOWS_TERMINAL
        
        return TerminalType.UNKNOWN
    
    def _is_console_window(self, window_info: Dict[str, Any]) -> bool:
        """Check if the window is a console application."""
        if not WINDOWS_AVAILABLE:
            return False
        
        try:
            hwnd = window_info.get('hwnd')
            if not hwnd:
                return False
            
            # Get console window for current process
            console_hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            
            # Check if this window is a console window
            window_class = window_info.get('class', '')
            return window_class == 'ConsoleWindowClass' or hwnd == console_hwnd
            
        except Exception:
            return False


class TerminalTextInjector:
    """Handles text injection for different terminal types."""
    
    def __init__(self):
        self.detector = TerminalDetector()
        
        # Initialize VS Code integration if available
        if VSCODE_INTEGRATION_AVAILABLE:
            self.vscode_integration = create_vscode_terminal_integration()
        else:
            self.vscode_integration = None
        
        self.injection_strategies = {
            TerminalType.CMD: self._inject_cmd,
            TerminalType.POWERSHELL: self._inject_powershell,
            TerminalType.POWERSHELL_CORE: self._inject_powershell,
            TerminalType.WSL: self._inject_wsl,
            TerminalType.GIT_BASH: self._inject_git_bash,
            TerminalType.VSCODE_TERMINAL: self._inject_vscode_terminal,
            TerminalType.WINDOWS_TERMINAL: self._inject_windows_terminal,
            TerminalType.CONEMU: self._inject_conemu,
            TerminalType.MINTTY: self._inject_mintty,
            TerminalType.HYPER: self._inject_generic,
            TerminalType.TERMINUS: self._inject_generic,
            TerminalType.UNKNOWN: self._inject_fallback,
        }
        
        # Terminal-specific configuration
        self.terminal_configs = {
            TerminalType.CMD: {
                'escape_chars': ['^', '&', '<', '>', '|'],
                'line_continuation': '^',
                'command_separator': '&',
                'supports_multiline': False
            },
            TerminalType.POWERSHELL: {
                'escape_chars': ['`', '$', '"', "'"],
                'line_continuation': '`',
                'command_separator': ';',
                'supports_multiline': True
            },
            TerminalType.WSL: {
                'escape_chars': ['\\', '$', '"', "'", '`'],
                'line_continuation': '\\',
                'command_separator': '&&',
                'supports_multiline': True
            }
        }
    
    def inject_text(self, text: str, force_terminal_type: Optional[TerminalType] = None) -> bool:
        """
        Main entry point for terminal text injection.
        
        Args:
            text: Text to inject
            force_terminal_type: Override automatic detection
            
        Returns:
            True if injection succeeded, False otherwise
        """
        if not text:
            return False
        
        # Detect terminal type
        if force_terminal_type:
            terminal_type = force_terminal_type
            metadata = {'forced_type': True}
        else:
            terminal_type, metadata = self.detector.detect_terminal_type()
        
        print(f"[TERMINAL] Detected: {terminal_type.value} ({metadata.get('detection_method', 'unknown')})")
        
        # Get injection strategy
        injection_func = self.injection_strategies.get(terminal_type, self._inject_fallback)
        
        try:
            # Pre-process text for terminal
            processed_text = self._preprocess_text(text, terminal_type)
            
            # Attempt injection
            success = injection_func(processed_text, metadata)
            
            if success:
                safe_text = text[:50] + ('...' if len(text) > 50 else '')
                print(f"[TERMINAL] ✅ Injected via {terminal_type.value}: '{safe_text}'")
            else:
                print(f"[TERMINAL] ❌ Injection failed for {terminal_type.value}")
            
            return success
            
        except Exception as e:
            print(f"[TERMINAL] ❌ Injection error: {e}")
            return False
    
    def _preprocess_text(self, text: str, terminal_type: TerminalType) -> str:
        """Preprocess text for specific terminal type."""
        config = self.terminal_configs.get(terminal_type, {})
        escape_chars = config.get('escape_chars', [])
        
        processed_text = text
        
        # Escape special characters for terminal
        for char in escape_chars:
            if char in processed_text:
                if terminal_type in [TerminalType.POWERSHELL, TerminalType.POWERSHELL_CORE]:
                    processed_text = processed_text.replace(char, f'`{char}')
                elif terminal_type == TerminalType.CMD:
                    processed_text = processed_text.replace(char, f'^{char}')
                elif terminal_type in [TerminalType.WSL, TerminalType.GIT_BASH]:
                    processed_text = processed_text.replace(char, f'\\{char}')
        
        return processed_text
    
    def _inject_cmd(self, text: str, metadata: Dict[str, Any]) -> bool:
        """Inject text into Command Prompt."""
        return self._inject_via_direct_typing(text)
    
    def _inject_powershell(self, text: str, metadata: Dict[str, Any]) -> bool:
        """Inject text into PowerShell."""
        return self._inject_via_direct_typing(text)
    
    def _inject_wsl(self, text: str, metadata: Dict[str, Any]) -> bool:
        """Inject text into WSL terminal."""
        # WSL may need special handling for Unicode
        return self._inject_via_clipboard_paste(text)
    
    def _inject_git_bash(self, text: str, metadata: Dict[str, Any]) -> bool:
        """Inject text into Git Bash."""
        return self._inject_via_clipboard_paste(text)
    
    def _inject_vscode_terminal(self, text: str, metadata: Dict[str, Any]) -> bool:
        """Inject text into VS Code integrated terminal."""
        # Try advanced VS Code integration first
        if self.vscode_integration and self.vscode_integration.is_vscode_terminal_active():
            success = self.vscode_integration.inject_text(text)
            if success:
                return True
        
        # Fallback to standard methods
        # VS Code terminals work well with clipboard paste
        success = self._inject_via_clipboard_paste(text)
        if not success:
            # Fallback to direct typing
            success = self._inject_via_direct_typing(text)
        return success
    
    def _inject_windows_terminal(self, text: str, metadata: Dict[str, Any]) -> bool:
        """Inject text into Windows Terminal."""
        # Windows Terminal has excellent clipboard support
        return self._inject_via_clipboard_paste(text)
    
    def _inject_conemu(self, text: str, metadata: Dict[str, Any]) -> bool:
        """Inject text into ConEmu."""
        return self._inject_via_clipboard_paste(text)
    
    def _inject_mintty(self, text: str, metadata: Dict[str, Any]) -> bool:
        """Inject text into mintty (Git Bash, MSYS2)."""
        return self._inject_via_clipboard_paste(text)
    
    def _inject_generic(self, text: str, metadata: Dict[str, Any]) -> bool:
        """Generic injection for unknown terminal types."""
        # Try clipboard first, then direct typing
        return (self._inject_via_clipboard_paste(text) or 
                self._inject_via_direct_typing(text))
    
    def _inject_fallback(self, text: str, metadata: Dict[str, Any]) -> bool:
        """Fallback injection method."""
        print("[TERMINAL] Using fallback injection method")
        return self._inject_generic(text, metadata)
    
    def _inject_via_direct_typing(self, text: str) -> bool:
        """Inject text by simulating direct keyboard input."""
        if not AUTOMATION_AVAILABLE:
            return False
        
        try:
            # Use keyboard library for more reliable typing in terminals
            keyboard.write(text, delay=0.01)  # Small delay for reliability
            return True
        except Exception as e:
            print(f"[TERMINAL] Direct typing failed: {e}")
            return False
    
    def _inject_via_clipboard_paste(self, text: str) -> bool:
        """Inject text via clipboard and Ctrl+V."""
        if not AUTOMATION_AVAILABLE:
            return self._inject_via_windows_clipboard(text)
        
        try:
            # Save current clipboard
            original_clipboard = None
            try:
                original_clipboard = pyautogui.paste()
            except:
                pass
            
            # Set our text to clipboard
            pyautogui.copy(text)
            
            # Small delay to ensure clipboard is set
            time.sleep(0.05)
            
            # Paste with Ctrl+V
            keyboard.send('ctrl+v')
            
            # Restore original clipboard after delay
            if original_clipboard is not None:
                threading.Timer(0.5, lambda: pyautogui.copy(original_clipboard)).start()
            
            return True
            
        except Exception as e:
            print(f"[TERMINAL] Clipboard paste failed: {e}")
            return self._inject_via_windows_clipboard(text)
    
    def _inject_via_windows_clipboard(self, text: str) -> bool:
        """Inject text using Windows clipboard APIs directly."""
        if not WINDOWS_AVAILABLE:
            return False
        
        try:
            # Save current clipboard
            original_data = None
            try:
                win32clipboard.OpenClipboard()
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                    original_data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                win32clipboard.CloseClipboard()
            except:
                pass
            
            # Set our text to clipboard
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32clipboard.CF_TEXT, text.encode('utf-8'))
            win32clipboard.CloseClipboard()
            
            # Send Ctrl+V using Windows API
            keybd_event = ctypes.windll.user32.keybd_event
            VK_CONTROL = 0x11
            VK_V = 0x56
            KEYEVENTF_KEYUP = 0x0002
            
            # Press Ctrl+V
            keybd_event(VK_CONTROL, 0, 0, 0)
            keybd_event(VK_V, 0, 0, 0)
            keybd_event(VK_V, 0, KEYEVENTF_KEYUP, 0)
            keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0)
            
            # Restore original clipboard after delay
            if original_data is not None:
                def restore_clipboard():
                    try:
                        win32clipboard.OpenClipboard()
                        win32clipboard.EmptyClipboard()
                        win32clipboard.SetClipboardData(win32clipboard.CF_TEXT, original_data)
                        win32clipboard.CloseClipboard()
                    except:
                        pass
                
                threading.Timer(0.5, restore_clipboard).start()
            
            return True
            
        except Exception as e:
            print(f"[TERMINAL] Windows clipboard injection failed: {e}")
            return False


class TerminalCommandProcessor:
    """Processes voice commands for terminal-specific functionality."""
    
    def __init__(self):
        self.command_patterns = {
            # Navigation commands
            r'change directory (.+)': 'cd "{}"',
            r'go to (.+)': 'cd "{}"',
            r'list (?:files|directory)': 'ls -la',  # Unix-style
            r'list files': 'dir',  # Windows-style
            r'show directory': 'pwd',
            r'where am i': 'pwd',
            
            # File operations
            r'create file (.+)': 'touch "{}"',
            r'make file (.+)': 'touch "{}"',
            r'remove file (.+)': 'rm "{}"',
            r'delete file (.+)': 'rm "{}"',
            r'copy (.+) to (.+)': 'cp "{}" "{}"',
            r'move (.+) to (.+)': 'mv "{}" "{}"',
            
            # Git commands
            r'git status': 'git status',
            r'git add all': 'git add .',
            r'git add (.+)': 'git add "{}"',
            r'git commit (.+)': 'git commit -m "{}"',
            r'git push': 'git push',
            r'git pull': 'git pull',
            
            # Process management
            r'kill process (.+)': 'kill {}',
            r'find process (.+)': 'ps aux | grep {}',
            r'show processes': 'ps aux',
            
            # System info
            r'show disk space': 'df -h',
            r'show memory': 'free -h',
            r'show uptime': 'uptime',
        }
    
    def process_voice_command(self, text: str, terminal_type: TerminalType) -> Optional[str]:
        """
        Process voice input to detect and convert terminal commands.
        
        Args:
            text: Voice transcription text
            terminal_type: Current terminal type
            
        Returns:
            Processed command string or None if no command detected
        """
        text_lower = text.lower().strip()
        
        # Check for command patterns
        for pattern, command_template in self.command_patterns.items():
            match = re.search(pattern, text_lower)
            if match:
                try:
                    # Format command with captured groups
                    if match.groups():
                        command = command_template.format(*match.groups())
                    else:
                        command = command_template
                    
                    # Adapt command for terminal type
                    adapted_command = self._adapt_command_for_terminal(command, terminal_type)
                    return adapted_command
                    
                except Exception as e:
                    print(f"[TERMINAL] Command processing error: {e}")
                    continue
        
        # If no specific command pattern matched, return original text
        return text
    
    def _adapt_command_for_terminal(self, command: str, terminal_type: TerminalType) -> str:
        """Adapt Unix/Linux commands for different terminal types."""
        
        if terminal_type in [TerminalType.CMD, TerminalType.POWERSHELL, TerminalType.POWERSHELL_CORE]:
            # Windows adaptations
            adaptations = {
                'ls -la': 'dir',
                'ls': 'dir',
                'pwd': 'cd',
                'rm ': 'del ',
                'cp ': 'copy ',
                'mv ': 'move ',
                'touch ': 'echo. > ',
                'cat ': 'type ',
                'grep ': 'findstr ',
                'ps aux': 'tasklist',
                'kill ': 'taskkill /PID ',
                'df -h': 'wmic logicaldisk get size,freespace,caption',
                'free -h': 'wmic OS get TotalVisibleMemorySize,FreePhysicalMemory',
                'uptime': 'systeminfo | findstr "System Boot Time"'
            }
            
            for unix_cmd, windows_cmd in adaptations.items():
                if command.startswith(unix_cmd):
                    command = command.replace(unix_cmd, windows_cmd, 1)
                    break
        
        return command


class TerminalEnhancedInjector:
    """Enhanced terminal text injector with intelligent processing."""
    
    def __init__(self):
        self.injector = TerminalTextInjector()
        self.processor = TerminalCommandProcessor()
        self.detector = TerminalDetector()
        
        # Statistics
        self.stats = {
            'total_injections': 0,
            'successful_injections': 0,
            'failed_injections': 0,
            'terminal_types_used': {}
        }
    
    def inject_enhanced_text(self, text: str, enable_command_processing: bool = True) -> bool:
        """
        Enhanced text injection with terminal-aware processing.
        
        Args:
            text: Text to inject
            enable_command_processing: Whether to process voice commands
            
        Returns:
            True if injection succeeded, False otherwise
        """
        if not text:
            return False
        
        self.stats['total_injections'] += 1
        
        try:
            # Detect terminal type
            terminal_type, metadata = self.detector.detect_terminal_type()
            
            # Track terminal type usage
            type_name = terminal_type.value
            self.stats['terminal_types_used'][type_name] = self.stats['terminal_types_used'].get(type_name, 0) + 1
            
            # Process voice commands if enabled
            if enable_command_processing:
                processed_text = self.processor.process_voice_command(text, terminal_type)
                if processed_text != text:
                    print(f"[TERMINAL] Command processed: '{text}' -> '{processed_text}'")
                    text = processed_text
            
            # Inject text
            success = self.injector.inject_text(text, terminal_type)
            
            if success:
                self.stats['successful_injections'] += 1
            else:
                self.stats['failed_injections'] += 1
            
            return success
            
        except Exception as e:
            print(f"[TERMINAL] Enhanced injection error: {e}")
            self.stats['failed_injections'] += 1
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get injection statistics."""
        success_rate = 0
        if self.stats['total_injections'] > 0:
            success_rate = (self.stats['successful_injections'] / self.stats['total_injections']) * 100
        
        return {
            'total_injections': self.stats['total_injections'],
            'successful_injections': self.stats['successful_injections'],
            'failed_injections': self.stats['failed_injections'],
            'success_rate_percent': round(success_rate, 1),
            'terminal_types_used': self.stats['terminal_types_used']
        }


# Main factory function for easy integration
def create_terminal_injector() -> TerminalEnhancedInjector:
    """Create a terminal-aware text injector."""
    return TerminalEnhancedInjector()


# Testing and validation functions
def test_terminal_detection():
    """Test terminal detection functionality."""
    detector = TerminalDetector()
    terminal_type, metadata = detector.detect_terminal_type()
    
    print(f"Terminal Detection Test:")
    print(f"  Type: {terminal_type.value}")
    print(f"  Metadata: {metadata}")
    
    return terminal_type != TerminalType.UNKNOWN


def test_text_injection(test_text: str = "echo 'Terminal injection test'"):
    """Test text injection functionality."""
    injector = create_terminal_injector()
    
    print(f"Testing injection with text: '{test_text}'")
    success = injector.inject_enhanced_text(test_text)
    
    stats = injector.get_statistics()
    print(f"Injection result: {'SUCCESS' if success else 'FAILED'}")
    print(f"Statistics: {stats}")
    
    return success


if __name__ == "__main__":
    print("VoiceFlow Terminal Integration Module")
    print("=" * 40)
    
    # Run tests
    print("\n1. Testing terminal detection...")
    detection_success = test_terminal_detection()
    
    print("\n2. Testing text injection...")
    injection_success = test_text_injection()
    
    print(f"\nOverall test results:")
    print(f"  Detection: {'PASS' if detection_success else 'FAIL'}")
    print(f"  Injection: {'PASS' if injection_success else 'FAIL'}")