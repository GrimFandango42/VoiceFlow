"""
VS Code Terminal API Integration for VoiceFlow

Advanced integration with VS Code's integrated terminal using Windows Terminal APIs
and VS Code extension APIs where available.
"""

import os
import json
import subprocess
import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

try:
    import win32api
    import win32con
    import win32gui
    import win32process
    import psutil
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

try:
    import requests
    import websocket
    NETWORKING_AVAILABLE = True
except ImportError:
    NETWORKING_AVAILABLE = False


class VSCodeTerminalDetector:
    """Advanced VS Code terminal detection and interaction."""
    
    def __init__(self):
        self.vscode_processes = []
        self.terminal_sessions = {}
        self.extension_port = None
        
    def find_vscode_processes(self) -> List[Dict[str, Any]]:
        """Find all running VS Code processes."""
        vscode_processes = []
        
        if not WINDOWS_AVAILABLE:
            return vscode_processes
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    if proc.info['name'] and 'code' in proc.info['name'].lower():
                        if proc.info['exe'] and 'code.exe' in proc.info['exe'].lower():
                            vscode_processes.append({
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'exe': proc.info['exe'],
                                'cmdline': proc.info['cmdline'] or []
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"[VSCODE] Error finding VS Code processes: {e}")
        
        self.vscode_processes = vscode_processes
        return vscode_processes
    
    def detect_vscode_terminal_windows(self) -> List[Dict[str, Any]]:
        """Detect VS Code windows that have active terminals."""
        terminal_windows = []
        
        if not WINDOWS_AVAILABLE:
            return terminal_windows
        
        def enum_windows_callback(hwnd, lParam):
            try:
                # Get window title and class
                window_title = win32gui.GetWindowText(hwnd)
                window_class = win32gui.GetClassName(hwnd)
                
                # Check if it's a VS Code window
                if ('visual studio code' in window_title.lower() or 
                    'code' in window_title.lower()) and window_class:
                    
                    # Get process info
                    _, process_id = win32process.GetWindowThreadProcessId(hwnd)
                    
                    # Check if the title suggests an active terminal
                    terminal_indicators = [
                        'terminal', 'powershell', 'cmd', 'bash', 'wsl',
                        'node', 'python', 'npm', 'git', 'shell'
                    ]
                    
                    if any(indicator in window_title.lower() for indicator in terminal_indicators):
                        terminal_windows.append({
                            'hwnd': hwnd,
                            'title': window_title,
                            'class': window_class,
                            'process_id': process_id,
                            'terminal_type': self._infer_terminal_type(window_title)
                        })
                        
            except Exception:
                pass  # Skip windows we can't access
            
            return True
        
        try:
            win32gui.EnumWindows(enum_windows_callback, None)
        except Exception as e:
            print(f"[VSCODE] Error enumerating windows: {e}")
        
        return terminal_windows
    
    def _infer_terminal_type(self, window_title: str) -> str:
        """Infer terminal type from VS Code window title."""
        title_lower = window_title.lower()
        
        if 'powershell' in title_lower:
            return 'powershell'
        elif 'cmd' in title_lower or 'command' in title_lower:
            return 'cmd'
        elif any(term in title_lower for term in ['bash', 'wsl', 'ubuntu', 'debian']):
            return 'wsl'
        elif 'git' in title_lower:
            return 'git_bash'
        elif 'node' in title_lower:
            return 'node'
        elif 'python' in title_lower:
            return 'python'
        else:
            return 'unknown'
    
    def get_vscode_workspace_info(self, process_id: int) -> Optional[Dict[str, Any]]:
        """Get workspace information for a VS Code process."""
        try:
            proc = psutil.Process(process_id)
            cmdline = proc.cmdline()
            
            workspace_info = {
                'process_id': process_id,
                'working_directory': proc.cwd(),
                'workspace_path': None,
                'project_name': None
            }
            
            # Try to extract workspace path from command line
            for i, arg in enumerate(cmdline):
                if arg and not arg.startswith('-') and i > 0:
                    if os.path.exists(arg):
                        workspace_info['workspace_path'] = arg
                        workspace_info['project_name'] = os.path.basename(arg)
                        break
            
            return workspace_info
            
        except Exception as e:
            print(f"[VSCODE] Error getting workspace info: {e}")
            return None


class VSCodeExtensionCommunicator:
    """Communicates with VS Code extensions for terminal control."""
    
    def __init__(self):
        self.extension_ports = [3000, 3001, 3002, 8080, 8081]  # Common dev server ports
        self.active_connections = {}
        
    def detect_extension_api(self) -> Optional[str]:
        """Detect if a VoiceFlow VS Code extension is available."""
        if not NETWORKING_AVAILABLE:
            return None
        
        for port in self.extension_ports:
            try:
                response = requests.get(
                    f"http://localhost:{port}/voiceflow/status",
                    timeout=1
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('service') == 'voiceflow-vscode':
                        print(f"[VSCODE] Found VoiceFlow extension on port {port}")
                        return f"http://localhost:{port}"
            except:
                continue
        
        return None
    
    def send_text_to_terminal(self, text: str, terminal_id: Optional[str] = None) -> bool:
        """Send text to VS Code terminal via extension API."""
        api_base = self.detect_extension_api()
        if not api_base:
            return False
        
        try:
            payload = {
                'text': text,
                'terminal_id': terminal_id,
                'action': 'inject_text'
            }
            
            response = requests.post(
                f"{api_base}/voiceflow/terminal/inject",
                json=payload,
                timeout=5
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"[VSCODE] Extension API error: {e}")
            return False
    
    def get_terminal_list(self) -> List[Dict[str, Any]]:
        """Get list of active terminals from VS Code extension."""
        api_base = self.detect_extension_api()
        if not api_base:
            return []
        
        try:
            response = requests.get(
                f"{api_base}/voiceflow/terminals",
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json().get('terminals', [])
                
        except Exception as e:
            print(f"[VSCODE] Error getting terminal list: {e}")
        
        return []


class VSCodeTerminalInjector:
    """Advanced terminal injection for VS Code using multiple methods."""
    
    def __init__(self):
        self.detector = VSCodeTerminalDetector()
        self.extension_comm = VSCodeExtensionCommunicator()
        self.fallback_methods = ['extension_api', 'windows_api', 'clipboard', 'direct_typing']
        
    def inject_text_to_vscode_terminal(self, text: str) -> bool:
        """
        Inject text to VS Code terminal using the best available method.
        
        Args:
            text: Text to inject
            
        Returns:
            True if injection succeeded, False otherwise
        """
        if not text:
            return False
        
        success = False
        method_used = None
        
        # Method 1: VS Code Extension API (most reliable)
        if not success:
            success = self._try_extension_api_injection(text)
            if success:
                method_used = 'extension_api'
        
        # Method 2: Windows API direct control
        if not success:
            success = self._try_windows_api_injection(text)
            if success:
                method_used = 'windows_api'
        
        # Method 3: Clipboard paste
        if not success:
            success = self._try_clipboard_injection(text)
            if success:
                method_used = 'clipboard'
        
        # Method 4: Direct typing simulation
        if not success:
            success = self._try_direct_typing(text)
            if success:
                method_used = 'direct_typing'
        
        if success:
            safe_text = text[:50] + ('...' if len(text) > 50 else '')
            print(f"[VSCODE] ✅ Terminal injection via {method_used}: '{safe_text}'")
        else:
            print(f"[VSCODE] ❌ All injection methods failed")
        
        return success
    
    def _try_extension_api_injection(self, text: str) -> bool:
        """Try injection via VS Code extension API."""
        try:
            return self.extension_comm.send_text_to_terminal(text)
        except Exception as e:
            print(f"[VSCODE] Extension API injection failed: {e}")
            return False
    
    def _try_windows_api_injection(self, text: str) -> bool:
        """Try injection via Windows API to VS Code terminal."""
        if not WINDOWS_AVAILABLE:
            return False
        
        try:
            # Find VS Code terminal windows
            terminal_windows = self.detector.detect_vscode_terminal_windows()
            
            if not terminal_windows:
                return False
            
            # Use the first terminal window found
            target_window = terminal_windows[0]
            hwnd = target_window['hwnd']
            
            # Focus the window
            win32gui.SetForegroundWindow(hwnd)
            time.sleep(0.1)
            
            # Send text using Windows messages
            for char in text:
                win32gui.SendMessage(hwnd, win32con.WM_CHAR, ord(char), 0)
                time.sleep(0.01)  # Small delay between characters
            
            return True
            
        except Exception as e:
            print(f"[VSCODE] Windows API injection failed: {e}")
            return False
    
    def _try_clipboard_injection(self, text: str) -> bool:
        """Try injection via clipboard paste."""
        if not WINDOWS_AVAILABLE:
            return False
        
        try:
            import win32clipboard
            import keyboard
            
            # Find and focus VS Code terminal
            terminal_windows = self.detector.detect_vscode_terminal_windows()
            if not terminal_windows:
                return False
            
            hwnd = terminal_windows[0]['hwnd']
            win32gui.SetForegroundWindow(hwnd)
            time.sleep(0.1)
            
            # Save current clipboard
            original_clipboard = None
            try:
                win32clipboard.OpenClipboard()
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                    original_clipboard = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                win32clipboard.CloseClipboard()
            except:
                pass
            
            # Set our text to clipboard
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32clipboard.CF_TEXT, text.encode('utf-8'))
            win32clipboard.CloseClipboard()
            
            # Send Ctrl+V
            keyboard.send('ctrl+v')
            
            # Restore original clipboard after delay
            if original_clipboard:
                def restore_clipboard():
                    try:
                        win32clipboard.OpenClipboard()
                        win32clipboard.EmptyClipboard()
                        win32clipboard.SetClipboardData(win32clipboard.CF_TEXT, original_clipboard)
                        win32clipboard.CloseClipboard()
                    except:
                        pass
                
                threading.Timer(0.5, restore_clipboard).start()
            
            return True
            
        except Exception as e:
            print(f"[VSCODE] Clipboard injection failed: {e}")
            return False
    
    def _try_direct_typing(self, text: str) -> bool:
        """Try injection via direct keyboard simulation."""
        try:
            import keyboard
            
            # Find and focus VS Code terminal
            terminal_windows = self.detector.detect_vscode_terminal_windows()
            if not terminal_windows:
                return False
            
            hwnd = terminal_windows[0]['hwnd']
            win32gui.SetForegroundWindow(hwnd)
            time.sleep(0.1)
            
            # Type the text
            keyboard.write(text, delay=0.01)
            
            return True
            
        except Exception as e:
            print(f"[VSCODE] Direct typing failed: {e}")
            return False
    
    def get_injection_status(self) -> Dict[str, Any]:
        """Get status of available injection methods."""
        status = {
            'extension_api': False,
            'windows_api': WINDOWS_AVAILABLE,
            'clipboard': WINDOWS_AVAILABLE,
            'direct_typing': True,  # keyboard library usually works
            'vscode_processes': len(self.detector.find_vscode_processes()),
            'terminal_windows': len(self.detector.detect_vscode_terminal_windows())
        }
        
        # Check extension API
        api_base = self.extension_comm.detect_extension_api()
        status['extension_api'] = api_base is not None
        
        return status


class VSCodeTerminalIntegration:
    """Main integration class for VS Code terminal support."""
    
    def __init__(self):
        self.detector = VSCodeTerminalDetector()
        self.injector = VSCodeTerminalInjector()
        self.extension_comm = VSCodeExtensionCommunicator()
        
        # Statistics
        self.stats = {
            'total_injections': 0,
            'successful_injections': 0,
            'failed_injections': 0,
            'methods_used': {}
        }
        
    def inject_text(self, text: str) -> bool:
        """
        Main entry point for VS Code terminal text injection.
        
        Args:
            text: Text to inject
            
        Returns:
            True if injection succeeded, False otherwise
        """
        self.stats['total_injections'] += 1
        
        success = self.injector.inject_text_to_vscode_terminal(text)
        
        if success:
            self.stats['successful_injections'] += 1
        else:
            self.stats['failed_injections'] += 1
        
        return success
    
    def is_vscode_terminal_active(self) -> bool:
        """Check if a VS Code terminal is currently active."""
        try:
            terminal_windows = self.detector.detect_vscode_terminal_windows()
            return len(terminal_windows) > 0
        except:
            return False
    
    def get_integration_info(self) -> Dict[str, Any]:
        """Get comprehensive information about VS Code integration."""
        vscode_processes = self.detector.find_vscode_processes()
        terminal_windows = self.detector.detect_vscode_terminal_windows()
        injection_status = self.injector.get_injection_status()
        
        return {
            'vscode_running': len(vscode_processes) > 0,
            'vscode_processes': vscode_processes,
            'terminal_windows': terminal_windows,
            'active_terminals': len(terminal_windows),
            'injection_methods': injection_status,
            'statistics': self.stats
        }
    
    def diagnose_integration(self) -> Dict[str, Any]:
        """Diagnose VS Code integration issues."""
        diagnosis = {
            'status': 'unknown',
            'issues': [],
            'recommendations': []
        }
        
        info = self.get_integration_info()
        
        # Check if VS Code is running
        if not info['vscode_running']:
            diagnosis['issues'].append("VS Code is not running")
            diagnosis['recommendations'].append("Start VS Code to enable terminal integration")
            diagnosis['status'] = 'no_vscode'
            return diagnosis
        
        # Check if terminals are active
        if info['active_terminals'] == 0:
            diagnosis['issues'].append("No active VS Code terminals detected")
            diagnosis['recommendations'].append("Open a terminal in VS Code (Ctrl+` or Terminal → New Terminal)")
        
        # Check injection methods
        methods = info['injection_methods']
        available_methods = sum(1 for method, available in methods.items() 
                               if available and method != 'vscode_processes' and method != 'terminal_windows')
        
        if available_methods == 0:
            diagnosis['issues'].append("No injection methods available")
            diagnosis['recommendations'].append("Install required packages (keyboard, win32api, etc.)")
            diagnosis['status'] = 'no_methods'
        elif available_methods == 1:
            diagnosis['status'] = 'limited'
            diagnosis['recommendations'].append("Consider installing VoiceFlow VS Code extension for better integration")
        else:
            diagnosis['status'] = 'good'
        
        if not methods.get('extension_api'):
            diagnosis['recommendations'].append("Install VoiceFlow VS Code extension for optimal performance")
        
        return diagnosis


# Factory function
def create_vscode_terminal_integration() -> VSCodeTerminalIntegration:
    """Create VS Code terminal integration instance."""
    return VSCodeTerminalIntegration()


# Testing functions
def test_vscode_detection():
    """Test VS Code detection functionality."""
    detector = VSCodeTerminalDetector()
    
    processes = detector.find_vscode_processes()
    terminals = detector.detect_vscode_terminal_windows()
    
    print(f"VS Code Detection Test:")
    print(f"  VS Code processes found: {len(processes)}")
    print(f"  Terminal windows found: {len(terminals)}")
    
    for i, terminal in enumerate(terminals):
        print(f"    Terminal {i+1}: {terminal['title']} ({terminal['terminal_type']})")
    
    return len(processes) > 0 or len(terminals) > 0


def test_vscode_injection(test_text: str = "echo 'VS Code terminal test'"):
    """Test VS Code terminal injection."""
    integration = create_vscode_terminal_integration()
    
    print(f"\nVS Code Injection Test:")
    print(f"  Test text: '{test_text}'")
    
    # Get integration info
    info = integration.get_integration_info()
    print(f"  VS Code running: {info['vscode_running']}")
    print(f"  Active terminals: {info['active_terminals']}")
    
    # Attempt injection
    success = integration.inject_text(test_text)
    print(f"  Injection result: {'SUCCESS' if success else 'FAILED'}")
    
    # Show statistics
    stats = info['statistics']
    print(f"  Statistics: {stats}")
    
    return success


if __name__ == "__main__":
    print("VoiceFlow VS Code Terminal Integration")
    print("=" * 40)
    
    # Run tests
    print("1. Testing VS Code detection...")
    detection_success = test_vscode_detection()
    
    print("\n2. Testing VS Code injection...")
    injection_success = test_vscode_injection()
    
    # Show diagnosis
    integration = create_vscode_terminal_integration()
    diagnosis = integration.diagnose_integration()
    
    print(f"\n3. Integration Diagnosis:")
    print(f"  Status: {diagnosis['status']}")
    if diagnosis['issues']:
        print(f"  Issues: {', '.join(diagnosis['issues'])}")
    if diagnosis['recommendations']:
        print(f"  Recommendations:")
        for rec in diagnosis['recommendations']:
            print(f"    - {rec}")
    
    print(f"\nOverall test results:")
    print(f"  Detection: {'PASS' if detection_success else 'FAIL'}")
    print(f"  Injection: {'PASS' if injection_success else 'FAIL'}")
    print(f"  Integration: {diagnosis['status'].upper()}")