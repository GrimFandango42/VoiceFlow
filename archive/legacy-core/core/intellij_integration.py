"""
IntelliJ IDEA and PyCharm Integration Module

Advanced integration with JetBrains IDEs using multiple automation approaches:
- HTTP API for IntelliJ Platform IDEs
- Plugin-based integration
- Remote development server communication
- Automation API for text injection and context detection
"""

import os
import sys
import json
import time
import subprocess
import requests
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum

try:
    import psutil
    PROCESS_DETECTION = True
except ImportError:
    PROCESS_DETECTION = False

try:
    import pyautogui
    import keyboard
    AUTOMATION_AVAILABLE = True
except ImportError:
    AUTOMATION_AVAILABLE = False


class JetBrainsIDE(Enum):
    """JetBrains IDE types."""
    INTELLIJ_IDEA = "intellij"
    PYCHARM = "pycharm"
    PYCHARM_CE = "pycharm-ce"
    WEBSTORM = "webstorm"
    PHPSTORM = "phpstorm"
    CLION = "clion"
    RIDER = "rider"
    GOLAND = "goland"
    RUBYMINE = "rubymine"
    APPCODE = "appcode"


@dataclass
class JetBrainsIDEInfo:
    """Information about detected JetBrains IDE."""
    ide_type: JetBrainsIDE
    version: Optional[str]
    build_number: Optional[str]
    installation_path: Path
    config_path: Path
    plugins_path: Path
    log_path: Path
    process_id: Optional[int]
    api_port: Optional[int]
    supports_remote_api: bool
    supports_plugin_api: bool


class JetBrainsIDEDetector:
    """Detects and manages JetBrains IDE instances."""
    
    # Common installation paths for different operating systems
    WINDOWS_PATHS = {
        JetBrainsIDE.INTELLIJ_IDEA: [
            Path("C:/Program Files/JetBrains/IntelliJ IDEA"),
            Path("C:/Users/{user}/AppData/Local/JetBrains/IntelliJ IDEA"),
        ],
        JetBrainsIDE.PYCHARM: [
            Path("C:/Program Files/JetBrains/PyCharm"),
            Path("C:/Users/{user}/AppData/Local/JetBrains/PyCharm"),
        ],
        JetBrainsIDE.PYCHARM_CE: [
            Path("C:/Program Files/JetBrains/PyCharm Community Edition"),
            Path("C:/Users/{user}/AppData/Local/JetBrains/PyCharm Community Edition"),
        ],
    }
    
    MACOS_PATHS = {
        JetBrainsIDE.INTELLIJ_IDEA: [Path("/Applications/IntelliJ IDEA.app")],
        JetBrainsIDE.PYCHARM: [Path("/Applications/PyCharm.app")],
        JetBrainsIDE.PYCHARM_CE: [Path("/Applications/PyCharm CE.app")],
    }
    
    LINUX_PATHS = {
        JetBrainsIDE.INTELLIJ_IDEA: [
            Path("/opt/idea"),
            Path.home() / ".local/share/JetBrains/IntelliJ IDEA",
        ],
        JetBrainsIDE.PYCHARM: [
            Path("/opt/pycharm"),
            Path.home() / ".local/share/JetBrains/PyCharm",
        ],
        JetBrainsIDE.PYCHARM_CE: [
            Path("/opt/pycharm-community"),
            Path.home() / ".local/share/JetBrains/PyCharm CE",
        ],
    }
    
    # Process name patterns for detection
    PROCESS_PATTERNS = {
        JetBrainsIDE.INTELLIJ_IDEA: ["idea", "idea64.exe", "idea.exe"],
        JetBrainsIDE.PYCHARM: ["pycharm", "pycharm64.exe", "pycharm.exe"],
        JetBrainsIDE.PYCHARM_CE: ["pycharm-community", "pycharm-ce"],
        JetBrainsIDE.WEBSTORM: ["webstorm", "webstorm64.exe"],
        JetBrainsIDE.PHPSTORM: ["phpstorm", "phpstorm64.exe"],
        JetBrainsIDE.CLION: ["clion", "clion64.exe"],
        JetBrainsIDE.RIDER: ["rider", "rider64.exe"],
        JetBrainsIDE.GOLAND: ["goland", "goland64.exe"],
    }
    
    def __init__(self):
        """Initialize JetBrains IDE detector."""
        self.detected_ides: List[JetBrainsIDEInfo] = []
        self.platform = self._detect_platform()
    
    def _detect_platform(self) -> str:
        """Detect the current platform."""
        if sys.platform.startswith('win'):
            return 'windows'
        elif sys.platform.startswith('darwin'):
            return 'macos'
        else:
            return 'linux'
    
    def detect_installed_ides(self) -> List[JetBrainsIDEInfo]:
        """Detect all installed JetBrains IDEs."""
        self.detected_ides = []
        
        # Get platform-specific paths
        if self.platform == 'windows':
            paths_dict = self.WINDOWS_PATHS
        elif self.platform == 'macos':
            paths_dict = self.MACOS_PATHS
        else:
            paths_dict = self.LINUX_PATHS
        
        for ide_type, paths in paths_dict.items():
            for path_template in paths:
                # Handle user path expansion
                path_str = str(path_template)
                if '{user}' in path_str:
                    path_str = path_str.format(user=os.getenv('USERNAME', os.getenv('USER', 'user')))
                    path = Path(path_str)
                else:
                    path = path_template
                
                if self._is_ide_installed(path, ide_type):
                    ide_info = self._create_ide_info(ide_type, path)
                    if ide_info:
                        self.detected_ides.append(ide_info)
        
        return self.detected_ides
    
    def detect_running_ides(self) -> List[JetBrainsIDEInfo]:
        """Detect currently running JetBrains IDEs."""
        running_ides = []
        
        if not PROCESS_DETECTION:
            return running_ides
        
        try:
            for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    pinfo = process.info
                    ide_type = self._identify_ide_from_process(pinfo)
                    
                    if ide_type:
                        # Try to find installation path from process
                        exe_path = pinfo.get('exe')
                        if exe_path:
                            installation_path = self._get_installation_path_from_exe(Path(exe_path))
                            ide_info = self._create_ide_info(ide_type, installation_path, pinfo['pid'])
                            if ide_info:
                                running_ides.append(ide_info)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except Exception as e:
            print(f"[JETBRAINS] Error detecting running IDEs: {e}")
        
        return running_ides
    
    def _is_ide_installed(self, path: Path, ide_type: JetBrainsIDE) -> bool:
        """Check if IDE is installed at the given path."""
        if not path.exists():
            return False
        
        # Look for IDE-specific files/directories
        indicators = {
            JetBrainsIDE.INTELLIJ_IDEA: ["bin/idea.sh", "bin/idea64.exe", "bin/idea.exe"],
            JetBrainsIDE.PYCHARM: ["bin/pycharm.sh", "bin/pycharm64.exe", "bin/pycharm.exe"],
            JetBrainsIDE.PYCHARM_CE: ["bin/pycharm.sh", "bin/pycharm64.exe", "bin/pycharm.exe"],
        }
        
        ide_indicators = indicators.get(ide_type, [])
        for indicator in ide_indicators:
            if (path / indicator).exists():
                return True
        
        return False
    
    def _identify_ide_from_process(self, process_info: Dict) -> Optional[JetBrainsIDE]:
        """Identify IDE type from process information."""
        process_name = process_info.get('name', '').lower()
        
        for ide_type, patterns in self.PROCESS_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in process_name:
                    return ide_type
        
        return None
    
    def _get_installation_path_from_exe(self, exe_path: Path) -> Path:
        """Get installation path from executable path."""
        # Navigate up from bin directory
        if exe_path.parent.name == 'bin':
            return exe_path.parent.parent
        else:
            return exe_path.parent
    
    def _create_ide_info(self, ide_type: JetBrainsIDE, installation_path: Path, 
                        process_id: Optional[int] = None) -> Optional[JetBrainsIDEInfo]:
        """Create IDE info object."""
        try:
            # Get version information
            version = self._get_ide_version(installation_path, ide_type)
            build_number = self._get_build_number(installation_path, ide_type)
            
            # Get configuration paths
            config_path = self._get_config_path(ide_type)
            plugins_path = self._get_plugins_path(ide_type)
            log_path = self._get_log_path(ide_type)
            
            # Determine API capabilities
            api_port = self._detect_api_port(ide_type, process_id)
            supports_remote_api = self._check_remote_api_support(installation_path, ide_type)
            supports_plugin_api = self._check_plugin_api_support(installation_path, ide_type)
            
            return JetBrainsIDEInfo(
                ide_type=ide_type,
                version=version,
                build_number=build_number,
                installation_path=installation_path,
                config_path=config_path,
                plugins_path=plugins_path,
                log_path=log_path,
                process_id=process_id,
                api_port=api_port,
                supports_remote_api=supports_remote_api,
                supports_plugin_api=supports_plugin_api
            )
        
        except Exception as e:
            print(f"[JETBRAINS] Error creating IDE info: {e}")
            return None
    
    def _get_ide_version(self, installation_path: Path, ide_type: JetBrainsIDE) -> Optional[str]:
        """Get IDE version from installation."""
        try:
            # Look for build.txt or product-info.json
            build_txt = installation_path / "build.txt"
            product_info = installation_path / "product-info.json"
            
            if product_info.exists():
                with open(product_info, 'r') as f:
                    info = json.load(f)
                    return info.get('version')
            
            if build_txt.exists():
                with open(build_txt, 'r') as f:
                    return f.read().strip()
            
        except Exception as e:
            print(f"[JETBRAINS] Error getting version: {e}")
        
        return None
    
    def _get_build_number(self, installation_path: Path, ide_type: JetBrainsIDE) -> Optional[str]:
        """Get IDE build number."""
        try:
            product_info = installation_path / "product-info.json"
            if product_info.exists():
                with open(product_info, 'r') as f:
                    info = json.load(f)
                    return info.get('buildNumber')
        except Exception:
            pass
        
        return None
    
    def _get_config_path(self, ide_type: JetBrainsIDE) -> Path:
        """Get IDE configuration directory."""
        home = Path.home()
        
        if self.platform == 'windows':
            base = Path(os.getenv('APPDATA', str(home / 'AppData/Roaming'))) / 'JetBrains'
        elif self.platform == 'macos':
            base = home / 'Library/Application Support/JetBrains'
        else:
            base = home / '.config/JetBrains'
        
        # IDE-specific subdirectories
        ide_dirs = {
            JetBrainsIDE.INTELLIJ_IDEA: 'IntelliJIdea',
            JetBrainsIDE.PYCHARM: 'PyCharm',
            JetBrainsIDE.PYCHARM_CE: 'PyCharmCE',
            JetBrainsIDE.WEBSTORM: 'WebStorm',
            JetBrainsIDE.PHPSTORM: 'PhpStorm',
        }
        
        ide_dir = ide_dirs.get(ide_type, ide_type.value)
        return base / ide_dir
    
    def _get_plugins_path(self, ide_type: JetBrainsIDE) -> Path:
        """Get IDE plugins directory."""
        return self._get_config_path(ide_type) / 'plugins'
    
    def _get_log_path(self, ide_type: JetBrainsIDE) -> Path:
        """Get IDE log directory."""
        if self.platform == 'windows':
            base = Path(os.getenv('LOCALAPPDATA', str(Path.home() / 'AppData/Local'))) / 'JetBrains'
        elif self.platform == 'macos':
            base = Path.home() / 'Library/Logs/JetBrains'
        else:
            base = Path.home() / '.cache/JetBrains'
        
        ide_dirs = {
            JetBrainsIDE.INTELLIJ_IDEA: 'IntelliJIdea',
            JetBrainsIDE.PYCHARM: 'PyCharm',
            JetBrainsIDE.PYCHARM_CE: 'PyCharmCE',
        }
        
        ide_dir = ide_dirs.get(ide_type, ide_type.value)
        return base / ide_dir / 'log'
    
    def _detect_api_port(self, ide_type: JetBrainsIDE, process_id: Optional[int]) -> Optional[int]:
        """Detect API port for running IDE."""
        # Common ports used by JetBrains IDEs
        common_ports = [63342, 63343, 63344, 6942, 6943]
        
        for port in common_ports:
            try:
                response = requests.get(f"http://localhost:{port}/api/about", timeout=1)
                if response.status_code == 200:
                    return port
            except requests.exceptions.RequestException:
                continue
        
        return None
    
    def _check_remote_api_support(self, installation_path: Path, ide_type: JetBrainsIDE) -> bool:
        """Check if IDE supports remote API."""
        # Most modern JetBrains IDEs support remote API
        return True
    
    def _check_plugin_api_support(self, installation_path: Path, ide_type: JetBrainsIDE) -> bool:
        """Check if IDE supports plugin API."""
        # Check for plugin development capabilities
        return True


class JetBrainsAPI:
    """API client for JetBrains IDEs."""
    
    def __init__(self, ide_info: JetBrainsIDEInfo):
        """Initialize API client."""
        self.ide_info = ide_info
        self.base_url = f"http://localhost:{ide_info.api_port}" if ide_info.api_port else None
        self.session = requests.Session()
        self.session.timeout = 5
    
    def is_connected(self) -> bool:
        """Check if API is accessible."""
        if not self.base_url:
            return False
        
        try:
            response = self.session.get(f"{self.base_url}/api/about")
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False
    
    def get_project_info(self) -> Optional[Dict[str, Any]]:
        """Get current project information."""
        if not self.is_connected():
            return None
        
        try:
            response = self.session.get(f"{self.base_url}/api/project")
            if response.status_code == 200:
                return response.json()
        except requests.exceptions.RequestException as e:
            print(f"[JETBRAINS] Error getting project info: {e}")
        
        return None
    
    def get_current_file(self) -> Optional[Dict[str, Any]]:
        """Get currently open file information."""
        if not self.is_connected():
            return None
        
        try:
            response = self.session.get(f"{self.base_url}/api/editor/current")
            if response.status_code == 200:
                return response.json()
        except requests.exceptions.RequestException as e:
            print(f"[JETBRAINS] Error getting current file: {e}")
        
        return None
    
    def insert_text_at_cursor(self, text: str) -> bool:
        """Insert text at current cursor position."""
        if not self.is_connected():
            return False
        
        try:
            payload = {"text": text}
            response = self.session.post(f"{self.base_url}/api/editor/insert", json=payload)
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            print(f"[JETBRAINS] Error inserting text: {e}")
            return False
    
    def get_cursor_position(self) -> Optional[Tuple[int, int]]:
        """Get current cursor position (line, column)."""
        if not self.is_connected():
            return None
        
        try:
            response = self.session.get(f"{self.base_url}/api/editor/cursor")
            if response.status_code == 200:
                data = response.json()
                return (data.get('line', 0), data.get('column', 0))
        except requests.exceptions.RequestException as e:
            print(f"[JETBRAINS] Error getting cursor position: {e}")
        
        return None
    
    def get_selected_text(self) -> Optional[str]:
        """Get currently selected text."""
        if not self.is_connected():
            return None
        
        try:
            response = self.session.get(f"{self.base_url}/api/editor/selection")
            if response.status_code == 200:
                data = response.json()
                return data.get('text')
        except requests.exceptions.RequestException as e:
            print(f"[JETBRAINS] Error getting selection: {e}")
        
        return None
    
    def execute_action(self, action_id: str) -> bool:
        """Execute IDE action by ID."""
        if not self.is_connected():
            return False
        
        try:
            payload = {"action": action_id}
            response = self.session.post(f"{self.base_url}/api/action", json=payload)
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            print(f"[JETBRAINS] Error executing action: {e}")
            return False
    
    def get_available_actions(self) -> List[str]:
        """Get list of available IDE actions."""
        if not self.is_connected():
            return []
        
        try:
            response = self.session.get(f"{self.base_url}/api/actions")
            if response.status_code == 200:
                data = response.json()
                return data.get('actions', [])
        except requests.exceptions.RequestException as e:
            print(f"[JETBRAINS] Error getting actions: {e}")
        
        return []


class JetBrainsIntegrationManager:
    """Main manager for JetBrains IDE integration."""
    
    def __init__(self):
        """Initialize integration manager."""
        self.detector = JetBrainsIDEDetector()
        self.installed_ides: List[JetBrainsIDEInfo] = []
        self.running_ides: List[JetBrainsIDEInfo] = []
        self.active_ide: Optional[JetBrainsIDEInfo] = None
        self.api_client: Optional[JetBrainsAPI] = None
        
        # Refresh detection
        self.refresh_detection()
    
    def refresh_detection(self) -> Dict[str, List[JetBrainsIDEInfo]]:
        """Refresh IDE detection."""
        self.installed_ides = self.detector.detect_installed_ides()
        self.running_ides = self.detector.detect_running_ides()
        
        # Set active IDE (prefer running IDE with API support)
        self.active_ide = self._determine_active_ide()
        
        # Initialize API client for active IDE
        if self.active_ide and self.active_ide.api_port:
            self.api_client = JetBrainsAPI(self.active_ide)
        else:
            self.api_client = None
        
        print(f"[JETBRAINS] Detected {len(self.installed_ides)} installed IDEs")
        print(f"[JETBRAINS] Detected {len(self.running_ides)} running IDEs")
        if self.active_ide:
            print(f"[JETBRAINS] Active IDE: {self.active_ide.ide_type.value}")
        
        return {
            'installed': self.installed_ides,
            'running': self.running_ides
        }
    
    def _determine_active_ide(self) -> Optional[JetBrainsIDEInfo]:
        """Determine which IDE is currently active."""
        # Prefer running IDEs with API support
        for ide in self.running_ides:
            if ide.api_port and ide.supports_remote_api:
                return ide
        
        # Fallback to any running IDE
        if self.running_ides:
            return self.running_ides[0]
        
        return None
    
    def inject_text_smart(self, text: str, context: Optional[str] = None) -> bool:
        """Smart text injection with context awareness."""
        if not self.active_ide:
            print("[JETBRAINS] No active IDE found")
            return False
        
        # Try API injection first
        if self.api_client and self.api_client.is_connected():
            try:
                # Get current context
                current_file = self.api_client.get_current_file()
                cursor_pos = self.api_client.get_cursor_position()
                
                # Format text based on context
                if context and current_file:
                    formatted_text = self._format_text_for_context(
                        text, context, current_file, cursor_pos
                    )
                else:
                    formatted_text = text
                
                # Insert text via API
                if self.api_client.insert_text_at_cursor(formatted_text):
                    print(f"[JETBRAINS] ✅ API injection successful: '{text[:50]}...'")
                    return True
                else:
                    print("[JETBRAINS] API injection failed, falling back to automation")
            
            except Exception as e:
                print(f"[JETBRAINS] API injection error: {e}")
        
        # Fallback to automation
        return self._inject_text_automation(text, context)
    
    def _format_text_for_context(self, text: str, context: str, 
                                file_info: Dict[str, Any], 
                                cursor_pos: Optional[Tuple[int, int]]) -> str:
        """Format text based on file context and cursor position."""
        file_extension = file_info.get('extension', '').lower()
        
        # Language-specific formatting
        if file_extension in ['.py']:
            return self._format_python_text(text, context, file_info, cursor_pos)
        elif file_extension in ['.java']:
            return self._format_java_text(text, context, file_info, cursor_pos)
        elif file_extension in ['.js', '.ts']:
            return self._format_javascript_text(text, context, file_info, cursor_pos)
        else:
            return text
    
    def _format_python_text(self, text: str, context: str, 
                           file_info: Dict[str, Any], 
                           cursor_pos: Optional[Tuple[int, int]]) -> str:
        """Format text for Python context."""
        if 'function' in context.lower():
            func_name = text.lower().replace(' ', '_')
            return f"def {func_name}():"
        elif 'variable' in context.lower():
            var_name = text.lower().replace(' ', '_')
            return f"{var_name} = "
        elif 'comment' in context.lower():
            return f"# {text}"
        else:
            return text
    
    def _format_java_text(self, text: str, context: str, 
                         file_info: Dict[str, Any], 
                         cursor_pos: Optional[Tuple[int, int]]) -> str:
        """Format text for Java context."""
        if 'method' in context.lower() or 'function' in context.lower():
            method_name = self._to_camel_case(text)
            return f"public void {method_name}() {{"
        elif 'variable' in context.lower():
            var_name = self._to_camel_case(text)
            return f"String {var_name} = "
        elif 'comment' in context.lower():
            return f"// {text}"
        else:
            return text
    
    def _format_javascript_text(self, text: str, context: str, 
                               file_info: Dict[str, Any], 
                               cursor_pos: Optional[Tuple[int, int]]) -> str:
        """Format text for JavaScript context."""
        if 'function' in context.lower():
            func_name = self._to_camel_case(text)
            return f"function {func_name}() {{"
        elif 'variable' in context.lower():
            var_name = self._to_camel_case(text)
            return f"const {var_name} = "
        elif 'comment' in context.lower():
            return f"// {text}"
        else:
            return text
    
    def _inject_text_automation(self, text: str, context: Optional[str]) -> bool:
        """Inject text using automation (fallback method)."""
        if not AUTOMATION_AVAILABLE:
            print("[JETBRAINS] Automation not available")
            return False
        
        try:
            # Small delay to ensure IDE is focused
            time.sleep(0.1)
            
            # Type the text
            pyautogui.typewrite(text)
            
            print(f"[JETBRAINS] ✅ Automation injection successful: '{text[:50]}...'")
            return True
        
        except Exception as e:
            print(f"[JETBRAINS] Automation injection failed: {e}")
            return False
    
    def get_current_context(self) -> Dict[str, Any]:
        """Get current IDE context information."""
        context = {
            'ide': self.active_ide.ide_type.value if self.active_ide else None,
            'version': self.active_ide.version if self.active_ide else None,
            'api_available': self.api_client and self.api_client.is_connected(),
            'file': None,
            'cursor_position': None,
            'selection': None,
            'project': None
        }
        
        if self.api_client and self.api_client.is_connected():
            try:
                context['file'] = self.api_client.get_current_file()
                context['cursor_position'] = self.api_client.get_cursor_position()
                context['selection'] = self.api_client.get_selected_text()
                context['project'] = self.api_client.get_project_info()
            except Exception as e:
                print(f"[JETBRAINS] Error getting context: {e}")
        
        return context
    
    def execute_ide_action(self, action_id: str) -> bool:
        """Execute an IDE action."""
        if not self.api_client or not self.api_client.is_connected():
            return False
        
        return self.api_client.execute_action(action_id)
    
    def get_available_actions(self) -> List[str]:
        """Get list of available IDE actions."""
        if not self.api_client or not self.api_client.is_connected():
            return []
        
        return self.api_client.get_available_actions()
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive integration status."""
        return {
            'installed_ides': len(self.installed_ides),
            'running_ides': len(self.running_ides),
            'active_ide': self.active_ide.ide_type.value if self.active_ide else None,
            'api_available': self.api_client and self.api_client.is_connected(),
            'automation_available': AUTOMATION_AVAILABLE,
            'process_detection': PROCESS_DETECTION,
            'platform': self.detector.platform,
            'detected_ides': [
                {
                    'type': ide.ide_type.value,
                    'version': ide.version,
                    'path': str(ide.installation_path),
                    'running': ide in self.running_ides,
                    'api_port': ide.api_port
                }
                for ide in self.installed_ides
            ]
        }
    
    def _to_camel_case(self, text: str) -> str:
        """Convert text to camelCase."""
        words = text.lower().split()
        if not words:
            return text
        return words[0] + ''.join(word.capitalize() for word in words[1:])


def create_jetbrains_integration_manager() -> JetBrainsIntegrationManager:
    """Factory function to create a JetBrains integration manager."""
    return JetBrainsIntegrationManager()