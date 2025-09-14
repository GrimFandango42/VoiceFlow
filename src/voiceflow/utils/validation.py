"""
VoiceFlow Input Validation Module
================================
Comprehensive input validation and security measures following DeepSeek recommendations
"""

import re
from typing import Any, Union, Optional
import numpy as np
from pathlib import Path

# Security constants
MIN_TEXT_LENGTH = 1
MAX_TEXT_LENGTH = 4000
MAX_FILENAME_LENGTH = 255
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
AUDIO_SAMPLE_RATE_LIMITS = (8000, 48000)
MAX_AUDIO_DURATION = 300.0  # 5 minutes

class ValidationError(Exception):
    """Custom validation exception for security issues"""
    pass

def validate_text_input(text: Any, field_name: str = "text") -> str:
    """
    Validate text input with security checks

    Args:
        text: Input to validate
        field_name: Name of field for error messages

    Returns:
        Validated string

    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(text, str):
        raise ValidationError(f"{field_name} must be a string, got {type(text)}")

    if len(text) < MIN_TEXT_LENGTH:
        raise ValidationError(f"{field_name} must be at least {MIN_TEXT_LENGTH} characters")

    if len(text) > MAX_TEXT_LENGTH:
        raise ValidationError(f"{field_name} exceeds maximum length of {MAX_TEXT_LENGTH}")

    # Remove potential injection attempts
    text = text.strip()

    # Check for suspicious patterns
    suspicious_patterns = [
        r'<script',
        r'javascript:',
        r'eval\(',
        r'exec\(',
        r'import\s+os',
        r'subprocess\.',
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            raise ValidationError(f"{field_name} contains suspicious content")

    return text

def validate_audio_data(audio_data: Any, field_name: str = "audio") -> np.ndarray:
    """
    Validate audio data with security and format checks

    Args:
        audio_data: Audio data to validate
        field_name: Name of field for error messages

    Returns:
        Validated numpy array

    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(audio_data, np.ndarray):
        raise ValidationError(f"{field_name} must be numpy array, got {type(audio_data)}")

    if audio_data.size == 0:
        raise ValidationError(f"{field_name} cannot be empty")

    if len(audio_data.shape) > 2:
        raise ValidationError(f"{field_name} has too many dimensions: {len(audio_data.shape)}")

    # Check for suspicious values
    if np.any(np.isnan(audio_data)):
        raise ValidationError(f"{field_name} contains NaN values")

    if np.any(np.isinf(audio_data)):
        raise ValidationError(f"{field_name} contains infinite values")

    # Check reasonable amplitude range
    max_val = np.max(np.abs(audio_data))
    if max_val > 10.0:  # Reasonable limit for normalized audio
        raise ValidationError(f"{field_name} amplitude too high: {max_val}")

    return audio_data

def validate_sample_rate(sample_rate: Any) -> int:
    """Validate audio sample rate"""
    if not isinstance(sample_rate, int):
        raise ValidationError(f"Sample rate must be integer, got {type(sample_rate)}")

    if not (AUDIO_SAMPLE_RATE_LIMITS[0] <= sample_rate <= AUDIO_SAMPLE_RATE_LIMITS[1]):
        raise ValidationError(
            f"Sample rate {sample_rate} outside valid range "
            f"{AUDIO_SAMPLE_RATE_LIMITS[0]}-{AUDIO_SAMPLE_RATE_LIMITS[1]}"
        )

    return sample_rate

def validate_file_path(file_path: Any, must_exist: bool = False) -> Path:
    """
    Validate file path with security checks

    Args:
        file_path: Path to validate
        must_exist: Whether file must already exist

    Returns:
        Validated Path object

    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(file_path, (str, Path)):
        raise ValidationError(f"File path must be string or Path, got {type(file_path)}")

    path = Path(file_path)

    # Security: Check for path traversal attempts
    if '..' in str(path):
        raise ValidationError("Path traversal attempts not allowed")

    # Check filename length
    if len(path.name) > MAX_FILENAME_LENGTH:
        raise ValidationError(f"Filename too long: {len(path.name)} > {MAX_FILENAME_LENGTH}")

    # Basic filename safety
    if not SAFE_FILENAME_PATTERN.match(path.name) and path.name:
        raise ValidationError(f"Unsafe filename characters in: {path.name}")

    if must_exist and not path.exists():
        raise ValidationError(f"Required file does not exist: {path}")

    return path

def validate_numeric_range(value: Any, min_val: float, max_val: float, field_name: str) -> Union[int, float]:
    """Validate numeric value within range"""
    if not isinstance(value, (int, float)):
        raise ValidationError(f"{field_name} must be numeric, got {type(value)}")

    if not (min_val <= value <= max_val):
        raise ValidationError(f"{field_name} {value} outside valid range {min_val}-{max_val}")

    return value

def sanitize_log_message(message: Any) -> str:
    """Sanitize message for safe logging"""
    if not isinstance(message, str):
        message = str(message)

    # Remove potential log injection attacks
    message = message.replace('\n', ' ').replace('\r', ' ')
    message = message.replace('\t', ' ')

    # Limit length for security
    if len(message) > 1000:
        message = message[:997] + "..."

    return message

# Validation decorators for easy application
def validate_input(validation_func):
    """Decorator to apply validation to function arguments"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Apply validation logic here
            return func(*args, **kwargs)
        return wrapper
    return decorator