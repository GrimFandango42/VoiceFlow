"""
Language Server Protocol (LSP) Integration Module

Provides integration with Language Server Protocol for advanced syntax validation,
code completion, error detection, and intelligent code analysis during voice-to-text
transcription and text injection.
"""

import json
import asyncio
import subprocess
import time
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Union, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import queue

try:
    import websockets
    import aiohttp
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False
    print("[LSP] Warning: async libraries not available")


class MessageType(Enum):
    """LSP message types."""
    REQUEST = 1
    RESPONSE = 2
    NOTIFICATION = 3
    ERROR = 4


class DiagnosticSeverity(Enum):
    """LSP diagnostic severity levels."""
    ERROR = 1
    WARNING = 2
    INFORMATION = 3
    HINT = 4


@dataclass
class Position:
    """LSP Position."""
    line: int
    character: int


@dataclass
class Range:
    """LSP Range."""
    start: Position
    end: Position


@dataclass
class Location:
    """LSP Location."""
    uri: str
    range: Range


@dataclass
class Diagnostic:
    """LSP Diagnostic."""
    range: Range
    severity: Optional[DiagnosticSeverity]
    code: Optional[Union[int, str]]
    source: Optional[str]
    message: str
    related_information: Optional[List[Dict]] = None


@dataclass
class CompletionItem:
    """LSP Completion Item."""
    label: str
    kind: Optional[int]
    detail: Optional[str]
    documentation: Optional[str]
    sort_text: Optional[str]
    filter_text: Optional[str]
    insert_text: Optional[str]
    text_edit: Optional[Dict]


@dataclass
class TextDocumentIdentifier:
    """LSP Text Document Identifier."""
    uri: str


@dataclass
class VersionedTextDocumentIdentifier(TextDocumentIdentifier):
    """LSP Versioned Text Document Identifier."""
    version: int


@dataclass
class TextDocumentItem:
    """LSP Text Document Item."""
    uri: str
    language_id: str
    version: int
    text: str


class LanguageServerConfig:
    """Configuration for language servers."""
    
    # Common language server configurations
    SERVERS = {
        'python': {
            'command': ['pylsp'],  # Python LSP Server
            'args': [],
            'extensions': ['.py'],
            'supports_completion': True,
            'supports_diagnostics': True,
            'supports_formatting': True,
            'supports_hover': True
        },
        'javascript': {
            'command': ['typescript-language-server', '--stdio'],
            'args': [],
            'extensions': ['.js', '.jsx'],
            'supports_completion': True,
            'supports_diagnostics': True,
            'supports_formatting': True,
            'supports_hover': True
        },
        'typescript': {
            'command': ['typescript-language-server', '--stdio'],
            'args': [],
            'extensions': ['.ts', '.tsx'],
            'supports_completion': True,
            'supports_diagnostics': True,
            'supports_formatting': True,
            'supports_hover': True
        },
        'java': {
            'command': ['jdtls'],  # Eclipse JDT Language Server
            'args': [],
            'extensions': ['.java'],
            'supports_completion': True,
            'supports_diagnostics': True,
            'supports_formatting': True,
            'supports_hover': True
        },
        'cpp': {
            'command': ['clangd'],
            'args': ['--background-index'],
            'extensions': ['.cpp', '.cxx', '.cc', '.c', '.h', '.hpp'],
            'supports_completion': True,
            'supports_diagnostics': True,
            'supports_formatting': True,
            'supports_hover': True
        },
        'rust': {
            'command': ['rust-analyzer'],
            'args': [],
            'extensions': ['.rs'],
            'supports_completion': True,
            'supports_diagnostics': True,
            'supports_formatting': True,
            'supports_hover': True
        },
        'go': {
            'command': ['gopls'],
            'args': [],
            'extensions': ['.go'],
            'supports_completion': True,
            'supports_diagnostics': True,
            'supports_formatting': True,
            'supports_hover': True
        }
    }
    
    @classmethod
    def get_server_config(cls, language: str) -> Optional[Dict[str, Any]]:
        """Get server configuration for a language."""
        return cls.SERVERS.get(language.lower())
    
    @classmethod
    def detect_language_from_extension(cls, file_path: Path) -> Optional[str]:
        """Detect language from file extension."""
        extension = file_path.suffix.lower()
        
        for language, config in cls.SERVERS.items():
            if extension in config['extensions']:
                return language
        
        return None


class LSPClient:
    """Language Server Protocol client."""
    
    def __init__(self, language: str, workspace_root: Optional[Path] = None):
        """Initialize LSP client for a specific language."""
        self.language = language
        self.workspace_root = workspace_root or Path.cwd()
        self.config = LanguageServerConfig.get_server_config(language)
        
        if not self.config:
            raise ValueError(f"No LSP configuration found for language: {language}")
        
        self.process: Optional[subprocess.Popen] = None
        self.request_id = 0
        self.pending_requests: Dict[int, asyncio.Future] = {}
        self.diagnostics: Dict[str, List[Diagnostic]] = {}
        self.completion_cache: Dict[str, List[CompletionItem]] = {}
        
        # Event handlers
        self.on_diagnostic = None
        self.on_completion = None
        self.on_error = None
        
        # Initialize server
        self._initialize_server()
    
    def _initialize_server(self):
        """Initialize the language server process."""
        try:
            command = self.config['command'] + self.config.get('args', [])
            
            # Check if language server is available
            if not self._check_server_availability(command[0]):
                raise FileNotFoundError(f"Language server not found: {command[0]}")
            
            # Start the language server process
            self.process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=0
            )
            
            # Send initialize request
            self._send_initialize_request()
            
            print(f"[LSP] ✅ {self.language} language server started")
            
        except Exception as e:
            print(f"[LSP] ❌ Failed to start {self.language} language server: {e}")
            self.process = None
    
    def _check_server_availability(self, command: str) -> bool:
        """Check if language server command is available."""
        try:
            result = subprocess.run(
                ['which', command] if not command.endswith('.exe') else ['where', command],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _send_initialize_request(self):
        """Send LSP initialize request."""
        if not self.process or not self.process.stdin:
            return
        
        initialize_params = {
            "processId": None,
            "rootUri": f"file://{self.workspace_root}",
            "workspaceFolders": [
                {
                    "uri": f"file://{self.workspace_root}",
                    "name": self.workspace_root.name
                }
            ],
            "capabilities": {
                "textDocument": {
                    "completion": {
                        "completionItem": {
                            "snippetSupport": True,
                            "commitCharactersSupport": True,
                            "documentationFormat": ["markdown", "plaintext"]
                        }
                    },
                    "hover": {
                        "contentFormat": ["markdown", "plaintext"]
                    },
                    "publishDiagnostics": {
                        "relatedInformation": True,
                        "tagSupport": {"valueSet": [1, 2]}
                    }
                },
                "workspace": {
                    "workspaceFolders": True
                }
            }
        }
        
        request = self._create_request("initialize", initialize_params)
        self._send_message(request)
        
        # Send initialized notification
        initialized_notification = self._create_notification("initialized", {})
        self._send_message(initialized_notification)
    
    def _create_request(self, method: str, params: Any) -> Dict[str, Any]:
        """Create LSP request message."""
        self.request_id += 1
        return {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }
    
    def _create_notification(self, method: str, params: Any) -> Dict[str, Any]:
        """Create LSP notification message."""
        return {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }
    
    def _send_message(self, message: Dict[str, Any]):
        """Send message to language server."""
        if not self.process or not self.process.stdin:
            return
        
        content = json.dumps(message)
        header = f"Content-Length: {len(content)}\r\n\r\n"
        full_message = header + content
        
        try:
            self.process.stdin.write(full_message)
            self.process.stdin.flush()
        except Exception as e:
            print(f"[LSP] Error sending message: {e}")
    
    def open_document(self, file_path: Path, content: str):
        """Open a document in the language server."""
        if not self.process:
            return
        
        uri = f"file://{file_path.absolute()}"
        
        params = {
            "textDocument": {
                "uri": uri,
                "languageId": self.language,
                "version": 1,
                "text": content
            }
        }
        
        notification = self._create_notification("textDocument/didOpen", params)
        self._send_message(notification)
    
    def update_document(self, file_path: Path, content: str, version: int = 1):
        """Update document content in the language server."""
        if not self.process:
            return
        
        uri = f"file://{file_path.absolute()}"
        
        params = {
            "textDocument": {
                "uri": uri,
                "version": version
            },
            "contentChanges": [
                {
                    "text": content
                }
            ]
        }
        
        notification = self._create_notification("textDocument/didChange", params)
        self._send_message(notification)
    
    def close_document(self, file_path: Path):
        """Close a document in the language server."""
        if not self.process:
            return
        
        uri = f"file://{file_path.absolute()}"
        
        params = {
            "textDocument": {
                "uri": uri
            }
        }
        
        notification = self._create_notification("textDocument/didClose", params)
        self._send_message(notification)
    
    def get_completions(self, file_path: Path, position: Position) -> List[CompletionItem]:
        """Get code completions at a specific position."""
        if not self.process or not self.config.get('supports_completion'):
            return []
        
        uri = f"file://{file_path.absolute()}"
        
        params = {
            "textDocument": {"uri": uri},
            "position": {"line": position.line, "character": position.character}
        }
        
        request = self._create_request("textDocument/completion", params)
        self._send_message(request)
        
        # In a real implementation, this would wait for the response
        # For now, return cached completions or empty list
        return self.completion_cache.get(uri, [])
    
    def get_diagnostics(self, file_path: Path) -> List[Diagnostic]:
        """Get diagnostics for a file."""
        uri = f"file://{file_path.absolute()}"
        return self.diagnostics.get(uri, [])
    
    def validate_text_injection(self, file_path: Path, text: str, 
                               position: Position) -> Dict[str, Any]:
        """Validate text that would be injected at a position."""
        if not self.process:
            return {"valid": True, "diagnostics": [], "suggestions": []}
        
        try:
            # Read current file content
            current_content = file_path.read_text() if file_path.exists() else ""
            
            # Create new content with injected text
            lines = current_content.split('\n')
            if position.line < len(lines):
                line = lines[position.line]
                new_line = line[:position.character] + text + line[position.character:]
                lines[position.line] = new_line
            else:
                # Extend lines if necessary
                while len(lines) <= position.line:
                    lines.append("")
                lines[position.line] = text
            
            new_content = '\n'.join(lines)
            
            # Update document and get diagnostics
            self.update_document(file_path, new_content)
            
            # Wait a bit for diagnostics (in real implementation, use async)
            time.sleep(0.1)
            
            diagnostics = self.get_diagnostics(file_path)
            
            # Filter diagnostics related to the injection area
            relevant_diagnostics = [
                d for d in diagnostics
                if d.range.start.line <= position.line <= d.range.end.line
            ]
            
            # Get completions for suggestions
            completions = self.get_completions(file_path, position)
            
            return {
                "valid": len(relevant_diagnostics) == 0,
                "diagnostics": [asdict(d) for d in relevant_diagnostics],
                "suggestions": [asdict(c) for c in completions[:5]]  # Top 5 suggestions
            }
            
        except Exception as e:
            print(f"[LSP] Error validating text injection: {e}")
            return {"valid": True, "diagnostics": [], "suggestions": []}
    
    def format_document(self, file_path: Path) -> Optional[str]:
        """Format document using language server."""
        if not self.process or not self.config.get('supports_formatting'):
            return None
        
        uri = f"file://{file_path.absolute()}"
        
        params = {
            "textDocument": {"uri": uri},
            "options": {
                "tabSize": 4,
                "insertSpaces": True
            }
        }
        
        request = self._create_request("textDocument/formatting", params)
        self._send_message(request)
        
        # In a real implementation, this would wait for the response
        return None
    
    def get_hover_info(self, file_path: Path, position: Position) -> Optional[str]:
        """Get hover information at a position."""
        if not self.process or not self.config.get('supports_hover'):
            return None
        
        uri = f"file://{file_path.absolute()}"
        
        params = {
            "textDocument": {"uri": uri},
            "position": {"line": position.line, "character": position.character}
        }
        
        request = self._create_request("textDocument/hover", params)
        self._send_message(request)
        
        # In a real implementation, this would wait for the response
        return None
    
    def shutdown(self):
        """Shutdown the language server."""
        if not self.process:
            return
        
        # Send shutdown request
        request = self._create_request("shutdown", None)
        self._send_message(request)
        
        # Send exit notification
        notification = self._create_notification("exit", None)
        self._send_message(notification)
        
        # Terminate process
        try:
            self.process.terminate()
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
        
        self.process = None
        print(f"[LSP] {self.language} language server shutdown")


class LSPManager:
    """Manages multiple LSP clients for different languages."""
    
    def __init__(self, workspace_root: Optional[Path] = None):
        """Initialize LSP manager."""
        self.workspace_root = workspace_root or Path.cwd()
        self.clients: Dict[str, LSPClient] = {}
        self.active_documents: Dict[str, str] = {}  # URI -> language
    
    def get_or_create_client(self, language: str) -> Optional[LSPClient]:
        """Get or create LSP client for a language."""
        if language not in self.clients:
            try:
                client = LSPClient(language, self.workspace_root)
                self.clients[language] = client
                print(f"[LSP] Created client for {language}")
            except Exception as e:
                print(f"[LSP] Failed to create client for {language}: {e}")
                return None
        
        return self.clients.get(language)
    
    def open_document(self, file_path: Path, content: Optional[str] = None):
        """Open a document in the appropriate language server."""
        # Detect language
        language = LanguageServerConfig.detect_language_from_extension(file_path)
        if not language:
            print(f"[LSP] No language server available for {file_path.suffix}")
            return
        
        # Get or create client
        client = self.get_or_create_client(language)
        if not client:
            return
        
        # Read content if not provided
        if content is None:
            try:
                content = file_path.read_text()
            except Exception as e:
                print(f"[LSP] Error reading file {file_path}: {e}")
                return
        
        # Open document
        client.open_document(file_path, content)
        
        # Track active document
        uri = f"file://{file_path.absolute()}"
        self.active_documents[uri] = language
    
    def update_document(self, file_path: Path, content: str, version: int = 1):
        """Update document content."""
        uri = f"file://{file_path.absolute()}"
        language = self.active_documents.get(uri)
        
        if not language:
            # Try to open the document first
            self.open_document(file_path, content)
            return
        
        client = self.clients.get(language)
        if client:
            client.update_document(file_path, content, version)
    
    def close_document(self, file_path: Path):
        """Close a document."""
        uri = f"file://{file_path.absolute()}"
        language = self.active_documents.get(uri)
        
        if language:
            client = self.clients.get(language)
            if client:
                client.close_document(file_path)
            
            # Remove from active documents
            del self.active_documents[uri]
    
    def validate_text_injection(self, file_path: Path, text: str, 
                               line: int, column: int) -> Dict[str, Any]:
        """Validate text injection using LSP."""
        language = LanguageServerConfig.detect_language_from_extension(file_path)
        if not language:
            return {"valid": True, "diagnostics": [], "suggestions": []}
        
        client = self.get_or_create_client(language)
        if not client:
            return {"valid": True, "diagnostics": [], "suggestions": []}
        
        # Ensure document is open
        if f"file://{file_path.absolute()}" not in self.active_documents:
            self.open_document(file_path)
        
        position = Position(line=line, character=column)
        return client.validate_text_injection(file_path, text, position)
    
    def get_completions(self, file_path: Path, line: int, column: int) -> List[CompletionItem]:
        """Get code completions."""
        uri = f"file://{file_path.absolute()}"
        language = self.active_documents.get(uri)
        
        if not language:
            return []
        
        client = self.clients.get(language)
        if not client:
            return []
        
        position = Position(line=line, character=column)
        return client.get_completions(file_path, position)
    
    def get_diagnostics(self, file_path: Path) -> List[Diagnostic]:
        """Get diagnostics for a file."""
        uri = f"file://{file_path.absolute()}"
        language = self.active_documents.get(uri)
        
        if not language:
            return []
        
        client = self.clients.get(language)
        if not client:
            return []
        
        return client.get_diagnostics(file_path)
    
    def format_document(self, file_path: Path) -> bool:
        """Format a document."""
        uri = f"file://{file_path.absolute()}"
        language = self.active_documents.get(uri)
        
        if not language:
            return False
        
        client = self.clients.get(language)
        if not client:
            return False
        
        formatted_text = client.format_document(file_path)
        return formatted_text is not None
    
    def get_supported_languages(self) -> List[str]:
        """Get list of supported languages."""
        return list(LanguageServerConfig.SERVERS.keys())
    
    def get_status(self) -> Dict[str, Any]:
        """Get LSP manager status."""
        return {
            "workspace_root": str(self.workspace_root),
            "active_clients": list(self.clients.keys()),
            "active_documents": len(self.active_documents),
            "supported_languages": self.get_supported_languages(),
            "client_status": {
                language: client.process is not None
                for language, client in self.clients.items()
            }
        }
    
    def shutdown_all(self):
        """Shutdown all language server clients."""
        for client in self.clients.values():
            client.shutdown()
        
        self.clients.clear()
        self.active_documents.clear()
        print("[LSP] All language servers shutdown")


class VoiceFlowLSPIntegration:
    """Integration between VoiceFlow and Language Server Protocol."""
    
    def __init__(self, workspace_root: Optional[Path] = None):
        """Initialize VoiceFlow LSP integration."""
        self.lsp_manager = LSPManager(workspace_root)
        self.validation_enabled = True
        self.auto_format = True
        self.completion_suggestions = True
    
    def validate_voice_text_injection(self, file_path: Path, text: str, 
                                    line: int, column: int) -> Dict[str, Any]:
        """Validate voice-transcribed text before injection."""
        if not self.validation_enabled:
            return {"valid": True, "diagnostics": [], "suggestions": []}
        
        result = self.lsp_manager.validate_text_injection(file_path, text, line, column)
        
        # Add voice-specific enhancements
        if not result["valid"]:
            print(f"[LSP] Validation failed for text injection: {text}")
            for diagnostic in result["diagnostics"]:
                print(f"[LSP]   - {diagnostic['message']}")
        
        return result
    
    def get_smart_completions(self, file_path: Path, line: int, column: int, 
                            voice_context: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get smart completions enhanced with voice context."""
        if not self.completion_suggestions:
            return []
        
        completions = self.lsp_manager.get_completions(file_path, line, column)
        
        # Filter and rank completions based on voice context
        if voice_context:
            filtered_completions = self._filter_completions_by_voice_context(
                completions, voice_context
            )
        else:
            filtered_completions = completions
        
        return [asdict(c) for c in filtered_completions[:10]]  # Top 10
    
    def _filter_completions_by_voice_context(self, completions: List[CompletionItem], 
                                           voice_context: str) -> List[CompletionItem]:
        """Filter completions based on voice context."""
        # Simple filtering based on voice context keywords
        context_keywords = voice_context.lower().split()
        
        filtered = []
        for completion in completions:
            # Check if completion label matches voice context
            label_lower = completion.label.lower()
            if any(keyword in label_lower for keyword in context_keywords):
                filtered.append(completion)
        
        # If no matches, return original list
        return filtered if filtered else completions
    
    def post_injection_validation(self, file_path: Path) -> Dict[str, Any]:
        """Validate file after text injection."""
        diagnostics = self.lsp_manager.get_diagnostics(file_path)
        
        errors = [d for d in diagnostics if d.severity == DiagnosticSeverity.ERROR]
        warnings = [d for d in diagnostics if d.severity == DiagnosticSeverity.WARNING]
        
        return {
            "has_errors": len(errors) > 0,
            "has_warnings": len(warnings) > 0,
            "error_count": len(errors),
            "warning_count": len(warnings),
            "diagnostics": [asdict(d) for d in diagnostics]
        }
    
    def format_after_injection(self, file_path: Path) -> bool:
        """Format document after text injection."""
        if not self.auto_format:
            return False
        
        return self.lsp_manager.format_document(file_path)
    
    def get_integration_status(self) -> Dict[str, Any]:
        """Get integration status."""
        status = self.lsp_manager.get_status()
        status.update({
            "validation_enabled": self.validation_enabled,
            "auto_format": self.auto_format,
            "completion_suggestions": self.completion_suggestions
        })
        return status
    
    def shutdown(self):
        """Shutdown LSP integration."""
        self.lsp_manager.shutdown_all()


def create_lsp_integration(workspace_root: Optional[Path] = None) -> VoiceFlowLSPIntegration:
    """Factory function to create LSP integration."""
    return VoiceFlowLSPIntegration(workspace_root)