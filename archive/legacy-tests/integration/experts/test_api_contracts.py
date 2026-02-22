#!/usr/bin/env python3
"""
API Contract Testing Expert
Tests function signatures, parameter orders, and return types
to catch issues like the create_audio_recorder parameter bug.
"""

import pytest
import inspect
from typing import get_type_hints

from voiceflow.core.audio import create_audio_recorder
from voiceflow.core.transcription import create_transcription_engine
from voiceflow.core.config import VoiceFlowConfig


class TestAPIContracts:
    """Test API contracts to catch signature mismatches."""
    
    def test_create_audio_recorder_signature(self):
        """Test create_audio_recorder function signature."""
        sig = inspect.signature(create_audio_recorder)
        params = list(sig.parameters.keys())
        
        # Ensure correct parameter order
        assert params[0] == 'config', f"First parameter should be 'config', got '{params[0]}'"
        assert params[1] == 'recorder_type', f"Second parameter should be 'recorder_type', got '{params[1]}'"
        
        # Test parameter types
        config_param = sig.parameters['config']
        recorder_type_param = sig.parameters['recorder_type']
        
        assert config_param.annotation == VoiceFlowConfig
        assert recorder_type_param.annotation == str
    
    def test_create_transcription_engine_signature(self):
        """Test create_transcription_engine function signature."""
        sig = inspect.signature(create_transcription_engine)
        params = list(sig.parameters.keys())
        
        # Ensure correct parameter order
        assert params[0] == 'config', f"First parameter should be 'config', got '{params[0]}'"
        assert params[1] == 'engine_type', f"Second parameter should be 'engine_type', got '{params[1]}'"
    
    def test_function_call_compatibility(self):
        """Test that functions can be called with expected parameters."""
        config = VoiceFlowConfig()
        
        # This should NOT raise any TypeError about parameter order
        try:
            # Test audio recorder creation
            audio_recorder = create_audio_recorder(config, "sounddevice")
            assert audio_recorder is not None
            
            # Test transcription engine creation  
            transcription_engine = create_transcription_engine(config, "faster-whisper")
            assert transcription_engine is not None
            
        except TypeError as e:
            pytest.fail(f"Function signature mismatch: {e}")
    
    def test_parameter_validation(self):
        """Test parameter validation catches wrong types."""
        config = VoiceFlowConfig()
        
        # Test wrong parameter types
        with pytest.raises((TypeError, ValueError)):
            create_audio_recorder("sounddevice", config)  # Wrong order
            
        with pytest.raises((TypeError, ValueError)):
            create_transcription_engine("faster-whisper", config)  # Wrong order


class TestFunctionUsagePatterns:
    """Test common usage patterns to catch integration issues."""
    
    def test_simple_app_pattern(self):
        """Test the exact pattern used in voiceflow_simple.py"""
        config = VoiceFlowConfig()
        
        # This is exactly how it's called in voiceflow_simple.py
        try:
            audio_recorder = create_audio_recorder(config, config.audio_recorder_type)
            transcription_engine = create_transcription_engine(config, config.transcription_engine_type)
            
            assert audio_recorder is not None
            assert transcription_engine is not None
            
        except Exception as e:
            pytest.fail(f"Simple app pattern failed: {e}")
    
    def test_tray_app_pattern(self):
        """Test the exact pattern used in voiceflow_tray_integrated.py"""
        voiceflow_config = VoiceFlowConfig()
        
        try:
            audio_recorder = create_audio_recorder(voiceflow_config, voiceflow_config.audio_recorder_type)
            transcription_engine = create_transcription_engine(voiceflow_config, voiceflow_config.transcription_engine_type)
            
            assert audio_recorder is not None
            assert transcription_engine is not None
            
        except Exception as e:
            pytest.fail(f"Tray app pattern failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])