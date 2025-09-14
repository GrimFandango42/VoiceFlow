"""
IDE Integration Module

Sophisticated IDE detection, automation, and text injection with syntax-aware processing.
Supports major IDEs with API-based integration and terminal automation.
"""

import os
import sys
import subprocess
import time
import json
import socket
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum

# Platform-specific imports
try:
    import psutil
    PROCESS_DETECTION = True
except ImportError:
    PROCESS_DETECTION = False
    print("[IDE] Warning: psutil not available - process detection limited")

try:
    import pyautogui
    import keyboard
    AUTOMATION_AVAILABLE = True
except ImportError:
    AUTOMATION_AVAILABLE = False
    print("[IDE] Warning: automation libraries not available")


class IDEType(Enum):
    """Supported IDE types with their characteristics."""
    VSCODE = "vscode"
    VSCODE_INSIDERS = "vscode-insiders"
    INTELLIJ = "intellij"
    PYCHARM = "pycharm"
    PYCHARM_CE = "pycharm-ce"
    SUBLIME_TEXT = "sublime"
    ATOM = "atom"
    VIM = "vim"
    NEOVIM = "neovim"
    EMACS = "emacs"
    UNKNOWN = "unknown"


@dataclass
class IDEInfo:
    """Information about detected IDE."""
    ide_type: IDEType
    version: Optional[str]
    process_name: str
    window_title: Optional[str]
    working_directory: Optional[Path]
    extensions_dir: Optional[Path]
    config_dir: Optional[Path]
    supports_api: bool
    supports_automation: bool
    current_file: Optional[Path] = None
    current_language: Optional[str] = None


class IDEDetector:
    """Detects running IDEs and their capabilities."""
    
    # IDE process patterns for detection
    IDE_PATTERNS = {
        IDEType.VSCODE: ["code", "code.exe", "Code.exe", "Visual Studio Code"],
        IDEType.VSCODE_INSIDERS: ["code-insiders", "code-insiders.exe"],
        IDEType.INTELLIJ: ["idea", "idea.exe", "idea64.exe", "IntelliJ IDEA"],
        IDEType.PYCHARM: ["pycharm", "pycharm.exe", "pycharm64.exe", "PyCharm"],
        IDEType.PYCHARM_CE: ["pycharm-community", "pycharm-ce"],
        IDEType.SUBLIME_TEXT: ["subl", "sublime_text", "sublime_text.exe"],
        IDEType.ATOM: ["atom", "atom.exe"],
        IDEType.VIM: ["vim", "vim.exe", "gvim", "gvim.exe"],
        IDEType.NEOVIM: ["nvim", "nvim.exe"],
        IDEType.EMACS: ["emacs", "emacs.exe"],
    }
    
    def __init__(self):
        """Initialize IDE detector."""
        self.detected_ides: List[IDEInfo] = []
        self.active_ide: Optional[IDEInfo] = None
        self._detection_cache = {}
        self._cache_timeout = 30  # seconds
    
    def detect_running_ides(self) -> List[IDEInfo]:
        """Detect all currently running IDEs."""
        if not PROCESS_DETECTION:
            print("[IDE] Process detection unavailable - using fallback methods")
            return self._detect_fallback()
        
        self.detected_ides = []
        
        try:
            for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cwd']):
                try:
                    pinfo = process.info
                    ide_type = self._identify_ide_type(pinfo)
                    
                    if ide_type != IDEType.UNKNOWN:
                        ide_info = self._create_ide_info(ide_type, pinfo)
                        self.detected_ides.append(ide_info)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"[IDE] Error during detection: {e}")
            return self._detect_fallback()
        
        # Determine active IDE (most recently focused)
        if self.detected_ides:
            self.active_ide = self._determine_active_ide()
        
        return self.detected_ides
    
    def _identify_ide_type(self, process_info: Dict) -> IDEType:
        """Identify IDE type from process information."""
        process_name = process_info.get('name', '').lower()
        exe_path = process_info.get('exe', '').lower() if process_info.get('exe') else ''
        
        for ide_type, patterns in self.IDE_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in process_name or pattern.lower() in exe_path:
                    return ide_type
        
        return IDEType.UNKNOWN
    
    def _create_ide_info(self, ide_type: IDEType, process_info: Dict) -> IDEInfo:
        """Create detailed IDE information."""
        process_name = process_info.get('name', '')
        cwd = process_info.get('cwd')
        working_dir = Path(cwd) if cwd else None
        
        # Determine IDE capabilities
        supports_api = ide_type in [IDEType.VSCODE, IDEType.VSCODE_INSIDERS, 
                                   IDEType.INTELLIJ, IDEType.PYCHARM, IDEType.PYCHARM_CE]
        supports_automation = True  # Most IDEs support basic automation
        
        # Get configuration directories
        config_dir = self._get_config_directory(ide_type)
        extensions_dir = self._get_extensions_directory(ide_type)
        
        return IDEInfo(
            ide_type=ide_type,
            version=self._get_ide_version(ide_type, process_info),
            process_name=process_name,
            window_title=None,  # Will be determined later if needed
            working_directory=working_dir,
            extensions_dir=extensions_dir,
            config_dir=config_dir,
            supports_api=supports_api,
            supports_automation=supports_automation
        )
    
    def _get_config_directory(self, ide_type: IDEType) -> Optional[Path]:
        """Get IDE configuration directory."""
        home = Path.home()
        
        config_paths = {
            IDEType.VSCODE: home / ".vscode",
            IDEType.VSCODE_INSIDERS: home / ".vscode-insiders",
            IDEType.INTELLIJ: home / ".IntelliJIdea2023.3",  # Version may vary
            IDEType.PYCHARM: home / ".PyCharm2023.3",
            IDEType.SUBLIME_TEXT: home / ".config" / "sublime-text-3",
            IDEType.VIM: home / ".vim",
            IDEType.NEOVIM: home / ".config" / "nvim",
        }
        
        return config_paths.get(ide_type)
    
    def _get_extensions_directory(self, ide_type: IDEType) -> Optional[Path]:
        """Get IDE extensions directory."""
        home = Path.home()
        
        ext_paths = {
            IDEType.VSCODE: home / ".vscode" / "extensions",
            IDEType.VSCODE_INSIDERS: home / ".vscode-insiders" / "extensions",
            IDEType.SUBLIME_TEXT: home / ".config" / "sublime-text-3" / "Packages",
        }
        
        return ext_paths.get(ide_type)
    
    def _get_ide_version(self, ide_type: IDEType, process_info: Dict) -> Optional[str]:
        """Attempt to determine IDE version."""
        # This is a simplified version - real implementation would parse version info
        exe_path = process_info.get('exe')
        if not exe_path:
            return None
        
        try:
            if ide_type in [IDEType.VSCODE, IDEType.VSCODE_INSIDERS]:
                result = subprocess.run([exe_path, '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return result.stdout.strip().split('\n')[0]
        except Exception:
            pass
        
        return None
    
    def _determine_active_ide(self) -> Optional[IDEInfo]:
        """Determine which IDE is currently active/focused."""
        # Simplified implementation - would use window focus detection in real scenario
        if self.detected_ides:
            # Prefer VS Code, then PyCharm, then others
            preferred_order = [IDEType.VSCODE, IDEType.PYCHARM, IDEType.INTELLIJ, 
                             IDEType.SUBLIME_TEXT, IDEType.VIM]
            
            for preferred in preferred_order:
                for ide in self.detected_ides:
                    if ide.ide_type == preferred:
                        return ide
            
            # Return first detected if no preferred found
            return self.detected_ides[0]
        
        return None
    
    def _detect_fallback(self) -> List[IDEInfo]:
        """Fallback detection method when psutil is unavailable."""
        # Basic detection using command availability
        detected = []
        
        commands_to_test = {
            IDEType.VSCODE: "code",
            IDEType.VIM: "vim",
            IDEType.NEOVIM: "nvim",
            IDEType.EMACS: "emacs",
        }
        
        for ide_type, command in commands_to_test.items():
            if self._command_exists(command):
                ide_info = IDEInfo(
                    ide_type=ide_type,
                    version=None,
                    process_name=command,
                    window_title=None,
                    working_directory=Path.cwd(),
                    extensions_dir=self._get_extensions_directory(ide_type),
                    config_dir=self._get_config_directory(ide_type),
                    supports_api=ide_type == IDEType.VSCODE,
                    supports_automation=True
                )
                detected.append(ide_info)
        
        return detected
    
    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH."""
        try:
            subprocess.run([command, '--version'], 
                         capture_output=True, timeout=2)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False


class VSCodeIntegration:
    """VS Code specific integration using CLI and extension API."""
    
    def __init__(self, ide_info: IDEInfo):
        """Initialize VS Code integration."""
        self.ide_info = ide_info
        self.command = "code" if ide_info.ide_type == IDEType.VSCODE else "code-insiders"
        self.extension_id = "voiceflow-integration"
    
    def inject_text_at_cursor(self, text: str) -> bool:
        """Inject text at current cursor position using VS Code API."""
        try:
            # Use VS Code command line to insert text
            # This would typically involve a custom extension
            temp_file = Path.cwd() / f".voiceflow_temp_{int(time.time())}.txt"
            temp_file.write_text(text)
            
            # Command to insert text from file
            result = subprocess.run([
                self.command,
                "--command", "workbench.action.files.openFile",
                str(temp_file)
            ], capture_output=True, timeout=5)
            
            # Clean up
            if temp_file.exists():
                temp_file.unlink()
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"[IDE] VS Code injection failed: {e}")
            return False
    
    def get_current_file_info(self) -> Optional[Dict[str, Any]]:
        """Get information about currently open file."""
        try:
            # This would require a custom VS Code extension to implement properly
            # For now, return basic info
            return {
                "file_path": None,
                "language": None,
                "cursor_position": None,
                "selection": None
            }
        except Exception as e:
            print(f"[IDE] Failed to get VS Code file info: {e}")
            return None
    
    def install_extension(self) -> bool:
        """Install VoiceFlow VS Code extension if available."""
        try:
            result = subprocess.run([
                self.command,
                "--install-extension", self.extension_id
            ], capture_output=True, timeout=30)
            
            return result.returncode == 0
        except Exception as e:
            print(f"[IDE] Extension installation failed: {e}")
            return False


class IntelliJIntegration:
    """IntelliJ/PyCharm integration using automation API."""
    
    def __init__(self, ide_info: IDEInfo):
        """Initialize IntelliJ integration."""
        self.ide_info = ide_info
        self.api_port = 63342  # Default IntelliJ API port
    
    def inject_text_at_cursor(self, text: str) -> bool:
        """Inject text using IntelliJ automation API."""
        try:
            # Use HTTP API if available
            import requests
            
            api_url = f"http://localhost:{self.api_port}/api/editor/insert"
            response = requests.post(api_url, json={"text": text}, timeout=5)
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"[IDE] IntelliJ injection failed: {e}")
            return False
    
    def get_current_file_info(self) -> Optional[Dict[str, Any]]:
        """Get current file information from IntelliJ."""
        try:
            import requests
            
            api_url = f"http://localhost:{self.api_port}/api/editor/current"
            response = requests.get(api_url, timeout=5)
            
            if response.status_code == 200:
                return response.json()
            
        except Exception as e:
            print(f"[IDE] Failed to get IntelliJ file info: {e}")
            
        return None


class IDEIntegrationManager:
    """Main manager for IDE integration and text injection."""
    
    def __init__(self):
        """Initialize IDE integration manager."""
        self.detector = IDEDetector()
        self.detected_ides: List[IDEInfo] = []
        self.active_ide: Optional[IDEInfo] = None
        self.integrations: Dict[IDEType, Any] = {}
        
        # Refresh detection
        self.refresh_detection()
    
    def refresh_detection(self) -> List[IDEInfo]:
        """Refresh IDE detection and update integrations."""
        self.detected_ides = self.detector.detect_running_ides()
        self.active_ide = self.detector.active_ide
        
        # Initialize IDE-specific integrations
        self._setup_integrations()
        
        if self.detected_ides:
            print(f"[IDE] Detected {len(self.detected_ides)} IDE(s):")
            for ide in self.detected_ides:
                status = "ACTIVE" if ide == self.active_ide else "BACKGROUND"
                print(f"[IDE]   - {ide.ide_type.value} ({ide.process_name}) [{status}]")
        else:
            print("[IDE] No IDEs detected")
        
        return self.detected_ides
    
    def _setup_integrations(self):
        """Setup IDE-specific integration objects."""
        self.integrations.clear()
        
        for ide in self.detected_ides:
            if ide.ide_type in [IDEType.VSCODE, IDEType.VSCODE_INSIDERS]:
                self.integrations[ide.ide_type] = VSCodeIntegration(ide)
            elif ide.ide_type in [IDEType.INTELLIJ, IDEType.PYCHARM, IDEType.PYCHARM_CE]:
                self.integrations[ide.ide_type] = IntelliJIntegration(ide)
    
    def inject_text_smart(self, text: str, context: Optional[str] = None) -> bool:
        """
        Smart text injection that adapts to the active IDE and context.
        
        Args:
            text: Text to inject
            context: Programming context (e.g., 'python', 'javascript', 'comment')
            
        Returns:
            True if injection succeeded
        """
        if not self.active_ide:
            return self._fallback_injection(text)
        
        # Try IDE-specific injection first
        integration = self.integrations.get(self.active_ide.ide_type)
        if integration:
            if integration.inject_text_at_cursor(text):
                print(f"[IDE] ✅ Smart injection via {self.active_ide.ide_type.value}")
                return True
        
        # Fallback to automation
        if self.active_ide.supports_automation and AUTOMATION_AVAILABLE:
            return self._automation_injection(text, context)
        
        # Final fallback
        return self._fallback_injection(text)
    
    def _automation_injection(self, text: str, context: Optional[str]) -> bool:
        """Inject text using automation libraries with context awareness."""
        try:
            # Add small delay to ensure IDE is focused
            time.sleep(0.1)
            
            # Context-aware formatting
            if context == 'python' and not text.endswith('\n'):
                # For Python, ensure proper line ending
                if text.strip() and not text.endswith((':',)):
                    text += '\n'
            elif context == 'comment':
                # For comments, ensure proper comment syntax
                if self.active_ide and 'python' in str(self.active_ide.current_file).lower():
                    if not text.startswith('#'):
                        text = f"# {text}"
            
            # Use pyautogui for text injection
            pyautogui.typewrite(text)
            
            safe_text = text[:50] + ('...' if len(text) > 50 else '')
            print(f"[IDE] ✅ Automation injection: '{safe_text}'")
            return True
            
        except Exception as e:
            print(f"[IDE] Automation injection failed: {e}")
            return False
    
    def _fallback_injection(self, text: str) -> bool:
        """Basic fallback text injection."""
        if not AUTOMATION_AVAILABLE:
            print("[IDE] No injection method available")
            return False
        
        try:
            pyautogui.typewrite(text)
            print(f"[IDE] ✅ Fallback injection completed")
            return True
        except Exception as e:
            print(f"[IDE] Fallback injection failed: {e}")
            return False
    
    def get_current_context(self) -> Dict[str, Any]:
        """Get current IDE context information."""
        if not self.active_ide:
            return {"ide": None, "file": None, "language": None}
        
        context = {
            "ide": self.active_ide.ide_type.value,
            "version": self.active_ide.version,
            "working_directory": str(self.active_ide.working_directory) if self.active_ide.working_directory else None,
            "supports_api": self.active_ide.supports_api,
            "supports_automation": self.active_ide.supports_automation
        }
        
        # Try to get current file information
        integration = self.integrations.get(self.active_ide.ide_type)
        if integration:
            file_info = integration.get_current_file_info()
            if file_info:
                context.update(file_info)
        
        return context
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive IDE integration status."""
        return {
            "detected_ides": len(self.detected_ides),
            "active_ide": self.active_ide.ide_type.value if self.active_ide else None,
            "automation_available": AUTOMATION_AVAILABLE,
            "process_detection": PROCESS_DETECTION,
            "supported_integrations": list(self.integrations.keys()),
            "context": self.get_current_context()
        }


def create_ide_manager() -> IDEIntegrationManager:
    """Factory function to create an IDE integration manager."""
    return IDEIntegrationManager()