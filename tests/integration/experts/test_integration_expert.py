#!/usr/bin/env python3
"""
Integration Testing Expert
Tests complete workflows without mocking to catch real integration issues.
"""

import pytest
import numpy as np
from unittest.mock import patch, MagicMock
import tempfile
import os
import soundfile as sf

from voiceflow.core.config import VoiceFlowConfig
from voiceflow.core.audio import create_audio_recorder
from voiceflow.core.transcription import create_transcription_engine
from voiceflow.ui.hotkeys import HotkeyManager
from voiceflow.ui.clipboard import ClipboardManager


class TestRealWorldIntegration:
    """Test real-world integration scenarios."""
    
    def setup_method(self):
        """Setup for each test."""
        self.config = VoiceFlowConfig()
        
    def test_complete_audio_chain_no_mocks(self):
        """Test the complete audio processing chain without mocks."""
        try:
            # Create audio recorder - this should work with correct parameter order
            audio_recorder = create_audio_recorder(self.config, self.config.audio_recorder_type)
            assert audio_recorder is not None
            
            # Create transcription engine - this should work with correct parameter order
            transcription_engine = create_transcription_engine(self.config, self.config.transcription_engine_type)
            assert transcription_engine is not None
            
            # Test with dummy audio data
            dummy_audio = np.random.random(16000).astype(np.float32)  # 1 second of noise
            
            # This should not crash
            result = transcription_engine.transcribe(dummy_audio)
            # Result might be empty due to noise, but shouldn't crash
            
        except Exception as e:
            pytest.fail(f"Complete audio chain failed: {e}")
    
    def test_hotkey_manager_integration(self):
        """Test hotkey manager integration."""
        try:
            hotkey_manager = HotkeyManager(self.config)
            assert hotkey_manager is not None
            
            # Test that we can register a callback
            callback_called = False
            def test_callback():
                nonlocal callback_called
                callback_called = True
            
            # This should not crash
            hotkey_manager.register_hotkey(test_callback)
            
            # Cleanup
            hotkey_manager.cleanup()
            
        except Exception as e:
            pytest.fail(f"Hotkey manager integration failed: {e}")
    
    def test_clipboard_manager_integration(self):
        """Test clipboard manager integration."""
        try:
            clipboard_manager = ClipboardManager()
            assert clipboard_manager is not None
            
            # Test copying text
            test_text = "Hello, World!"
            clipboard_manager.copy_text(test_text)
            
        except Exception as e:
            pytest.fail(f"Clipboard manager integration failed: {e}")


class TestErrorHandling:
    """Test error handling in integration scenarios."""
    
    def test_invalid_audio_recorder_type(self):
        """Test handling of invalid audio recorder type."""
        config = VoiceFlowConfig()
        
        with pytest.raises((ValueError, TypeError)):
            create_audio_recorder(config, "invalid_recorder_type")
    
    def test_invalid_transcription_engine_type(self):
        """Test handling of invalid transcription engine type."""
        config = VoiceFlowConfig()
        
        with pytest.raises((ValueError, TypeError)):
            create_transcription_engine(config, "invalid_engine_type")
    
    def test_parameter_order_error_detection(self):
        """Test that wrong parameter order is detected."""
        config = VoiceFlowConfig()
        
        # These should fail due to wrong parameter order/types
        with pytest.raises((TypeError, ValueError, AttributeError)):
            # This is the bug we had - passing recorder_type as first parameter
            create_audio_recorder("sounddevice", config)
        
        with pytest.raises((TypeError, ValueError, AttributeError)):
            # Same bug for transcription engine
            create_transcription_engine("faster-whisper", config)


class TestConfigurationIntegration:
    """Test configuration integration scenarios."""
    
    def test_config_to_component_flow(self):
        """Test configuration flows to components."""
        config = VoiceFlowConfig()
        
        # Test all supported recorder types
        supported_recorders = ["sounddevice"]  # Add more as implemented
        for recorder_type in supported_recorders:
            try:
                recorder = create_audio_recorder(config, recorder_type)
                assert recorder is not None
            except Exception as e:
                pytest.fail(f"Failed to create {recorder_type} recorder: {e}")
        
        # Test all supported transcription engines
        supported_engines = ["faster-whisper"]  # Add more as implemented
        for engine_type in supported_engines:
            try:
                engine = create_transcription_engine(config, engine_type)
                assert engine is not None
            except Exception as e:
                pytest.fail(f"Failed to create {engine_type} engine: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])