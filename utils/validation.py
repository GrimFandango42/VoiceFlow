"""
Input validation utilities for VoiceFlow

Provides safe input validation to prevent injection attacks
and ensure data integrity.
"""

import re
import os
from typing import Any, Dict, List, Optional
from pathlib import Path


class ValidationError(Exception):
    """Custom exception for validation errors."""
    def __init__(self, message: str, field: str = None):
        self.message = message
        self.field = field
        super().__init__(self.message)


class InputValidator:
    """Input validation utilities for VoiceFlow."""
    
    # Safe patterns for common inputs
    SAFE_TEXT_PATTERN = re.compile(r'^[a-zA-Z0-9\s\.,;:!?\-\'\"()]+$')
    SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
    SAFE_PATH_PATTERN = re.compile(r'^[a-zA-Z0-9_/\-\.\\:]+$')
    
    # Dangerous patterns to block
    DANGEROUS_PATTERNS = [
        re.compile(r'<script[^>]*>', re.IGNORECASE),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'on\w+\s*=', re.IGNORECASE),
        re.compile(r'<\s*iframe[^>]*>', re.IGNORECASE),
        re.compile(r'<\s*object[^>]*>', re.IGNORECASE),
        re.compile(r'<\s*embed[^>]*>', re.IGNORECASE),
        re.compile(r'<\s*link[^>]*>', re.IGNORECASE),
        re.compile(r'<\s*meta[^>]*>', re.IGNORECASE),
        re.compile(r'eval\s*\(', re.IGNORECASE),
        re.compile(r'exec\s*\(', re.IGNORECASE),
        re.compile(r'__import__', re.IGNORECASE),
        re.compile(r'subprocess', re.IGNORECASE),
        re.compile(r'os\.system', re.IGNORECASE),
    ]
    
    @staticmethod
    def validate_text(text: str, max_length: int = 10000, allow_empty: bool = True) -> str:
        """
        Validate text input for transcriptions.
        
        Args:
            text: Text to validate
            max_length: Maximum allowed length
            allow_empty: Whether empty text is allowed
            
        Returns:
            Sanitized text
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(text, str):
            raise ValidationError("Text must be a string", "text")
        
        if not allow_empty and not text.strip():
            raise ValidationError("Text cannot be empty", "text")
        
        if len(text) > max_length:
            raise ValidationError(f"Text too long (max {max_length} characters)", "text")
        
        # Check for dangerous patterns
        for pattern in InputValidator.DANGEROUS_PATTERNS:
            if pattern.search(text):
                raise ValidationError("Text contains potentially dangerous content", "text")
        
        # Basic sanitization
        sanitized = text.strip()
        
        return sanitized
    
    @staticmethod
    def validate_file_path(file_path: str, must_exist: bool = True, 
                          allowed_extensions: Optional[List[str]] = None) -> Path:
        """
        Validate file path for security.
        
        Args:
            file_path: Path to validate
            must_exist: Whether file must exist
            allowed_extensions: List of allowed file extensions
            
        Returns:
            Validated Path object
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(file_path, str):
            raise ValidationError("File path must be a string", "file_path")
        
        if not file_path.strip():
            raise ValidationError("File path cannot be empty", "file_path")
        
        # Convert to Path object for safe handling
        try:
            path = Path(file_path).resolve()
        except Exception:
            raise ValidationError("Invalid file path format", "file_path")
        
        # Check for path traversal attempts
        if '..' in str(path):
            raise ValidationError("Path traversal not allowed", "file_path")
        
        # Check if path is within allowed directories
        allowed_dirs = [
            Path.home() / ".voiceflow",
            Path.cwd(),
            Path("/tmp"),  # For temporary files
        ]
        
        path_allowed = any(
            str(path).startswith(str(allowed_dir)) 
            for allowed_dir in allowed_dirs
        )
        
        if not path_allowed:
            raise ValidationError("File path not in allowed directory", "file_path")
        
        # Check if file exists (if required)
        if must_exist and not path.exists():
            raise ValidationError("File does not exist", "file_path")
        
        # Check file extension
        if allowed_extensions:
            extension = path.suffix.lower()
            if extension not in allowed_extensions:
                raise ValidationError(
                    f"File extension not allowed. Allowed: {allowed_extensions}", 
                    "file_path"
                )
        
        return path
    
    @staticmethod
    def validate_json_message(message: str, max_size: int = 1024 * 1024) -> Dict[str, Any]:
        """
        Validate and parse JSON message safely.
        
        Args:
            message: JSON message string
            max_size: Maximum message size in bytes
            
        Returns:
            Parsed JSON data
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(message, str):
            raise ValidationError("Message must be a string", "message")
        
        if len(message.encode('utf-8')) > max_size:
            raise ValidationError(f"Message too large (max {max_size} bytes)", "message")
        
        try:
            import json
            data = json.loads(message)
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON format: {e}", "message")
        
        if not isinstance(data, dict):
            raise ValidationError("Message must be a JSON object", "message")
        
        # Validate required fields
        if 'type' not in data:
            raise ValidationError("Message missing 'type' field", "message")
        
        # Sanitize string values
        for key, value in data.items():
            if isinstance(value, str):
                data[key] = InputValidator.validate_text(value, max_length=1000)
        
        return data
    
    @staticmethod
    def validate_websocket_params(params: Dict[str, str]) -> Dict[str, str]:
        """
        Validate WebSocket connection parameters.
        
        Args:
            params: Dictionary of parameters
            
        Returns:
            Validated parameters
            
        Raises:
            ValidationError: If validation fails
        """
        validated = {}
        
        for key, value in params.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            
            # Validate key
            if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', key):
                continue  # Skip invalid keys
            
            # Validate value
            if len(value) > 1000:
                raise ValidationError(f"Parameter '{key}' too long", key)
            
            # Basic sanitization
            validated[key] = value.strip()
        
        return validated
    
    @staticmethod
    def sanitize_for_display(text: str, max_length: int = 100) -> str:
        """
        Sanitize text for safe display in logs/UI.
        
        Args:
            text: Text to sanitize
            max_length: Maximum display length
            
        Returns:
            Sanitized text safe for display
        """
        if not isinstance(text, str):
            return str(text)
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>&"\']', '', text)
        
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length-3] + "..."
        
        return sanitized
    
    @staticmethod
    def validate_audio_duration(duration: float, max_duration: float = 60.0) -> float:
        """
        Validate audio recording duration.
        
        Args:
            duration: Duration in seconds
            max_duration: Maximum allowed duration
            
        Returns:
            Validated duration
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(duration, (int, float)):
            raise ValidationError("Duration must be a number", "duration")
        
        if duration < 0:
            raise ValidationError("Duration cannot be negative", "duration")
        
        if duration > max_duration:
            raise ValidationError(f"Duration too long (max {max_duration}s)", "duration")
        
        return float(duration)


def safe_filename(filename: str) -> str:
    """Generate safe filename from user input."""
    # Remove dangerous characters
    safe = re.sub(r'[^\w\-_\.]', '_', filename)
    
    # Limit length
    if len(safe) > 100:
        safe = safe[:100]
    
    # Ensure extension
    if '.' not in safe:
        safe += '.txt'
    
    return safe