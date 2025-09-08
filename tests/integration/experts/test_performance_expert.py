#!/usr/bin/env python3
"""
Performance Testing Expert
Tests performance characteristics and catches performance regressions.
"""

import pytest
import time
import psutil
import os
from contextlib import contextmanager

from voiceflow.core.config import VoiceFlowConfig
from voiceflow.core.audio import create_audio_recorder
from voiceflow.core.transcription import create_transcription_engine


@contextmanager
def monitor_performance():
    """Context manager to monitor performance metrics."""
    process = psutil.Process(os.getpid())
    
    # Initial measurements
    start_time = time.time()
    start_memory = process.memory_info().rss / 1024 / 1024  # MB
    start_cpu_percent = process.cpu_percent()
    
    try:
        yield
    finally:
        # Final measurements
        end_time = time.time()
        end_memory = process.memory_info().rss / 1024 / 1024  # MB
        end_cpu_percent = process.cpu_percent()
        
        duration = end_time - start_time
        memory_delta = end_memory - start_memory
        
        print(f"\nPerformance Metrics:")
        print(f"Duration: {duration:.2f}s")
        print(f"Memory Start: {start_memory:.1f}MB")
        print(f"Memory End: {end_memory:.1f}MB")
        print(f"Memory Delta: {memory_delta:.1f}MB")


class TestPerformance:
    """Performance tests to catch performance regressions."""
    
    def test_config_creation_performance(self):
        """Test that config creation is fast."""
        with monitor_performance():
            start_time = time.time()
            
            # Should be fast
            for _ in range(100):
                config = VoiceFlowConfig()
                config.validate()
            
            duration = time.time() - start_time
            
        # Should create 100 configs in under 1 second
        assert duration < 1.0, f"Config creation too slow: {duration:.2f}s"
    
    def test_audio_recorder_creation_performance(self):
        """Test that audio recorder creation is reasonable."""
        config = VoiceFlowConfig()
        
        with monitor_performance():
            start_time = time.time()
            
            # Create audio recorder
            audio_recorder = create_audio_recorder(config, config.audio_recorder_type)
            
            duration = time.time() - start_time
            
        # Should create recorder in under 5 seconds
        assert duration < 5.0, f"Audio recorder creation too slow: {duration:.2f}s"
        assert audio_recorder is not None
    
    def test_transcription_engine_creation_performance(self):
        """Test that transcription engine creation is reasonable."""
        config = VoiceFlowConfig()
        
        with monitor_performance():
            start_time = time.time()
            
            # Create transcription engine
            transcription_engine = create_transcription_engine(config, config.transcription_engine_type)
            
            duration = time.time() - start_time
            
        # First time model loading can be slow, but subsequent should be faster
        # Allow up to 30 seconds for model download/loading
        assert duration < 30.0, f"Transcription engine creation too slow: {duration:.2f}s"
        assert transcription_engine is not None
    
    def test_memory_usage_reasonable(self):
        """Test that memory usage is reasonable."""
        config = VoiceFlowConfig()
        
        initial_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        
        # Create components
        audio_recorder = create_audio_recorder(config, config.audio_recorder_type)
        transcription_engine = create_transcription_engine(config, config.transcription_engine_type)
        
        final_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory
        
        # Should not use more than 2GB additional memory
        assert memory_increase < 2048, f"Memory usage too high: {memory_increase:.1f}MB"
    
    def test_no_memory_leaks_in_repeated_creation(self):
        """Test for memory leaks in repeated component creation."""
        config = VoiceFlowConfig()
        
        initial_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        
        # Create and destroy components multiple times
        for i in range(5):
            audio_recorder = create_audio_recorder(config, config.audio_recorder_type)
            del audio_recorder
            
            current_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
            memory_increase = current_memory - initial_memory
            
            # Memory should not grow unbounded
            assert memory_increase < 500 * (i + 1), f"Possible memory leak detected: {memory_increase:.1f}MB after {i+1} iterations"


class TestResponseTime:
    """Test response time characteristics."""
    
    def test_hotkey_response_time(self):
        """Test that hotkey registration is fast."""
        from voiceflow.ui.hotkeys import HotkeyManager
        
        config = VoiceFlowConfig()
        
        with monitor_performance():
            start_time = time.time()
            
            hotkey_manager = HotkeyManager(config)
            
            callback_called = False
            def test_callback():
                nonlocal callback_called
                callback_called = True
            
            hotkey_manager.register_hotkey(test_callback)
            hotkey_manager.cleanup()
            
            duration = time.time() - start_time
            
        # Should be very fast
        assert duration < 1.0, f"Hotkey registration too slow: {duration:.2f}s"
    
    def test_config_validation_performance(self):
        """Test that config validation is fast."""
        config = VoiceFlowConfig()
        
        with monitor_performance():
            start_time = time.time()
            
            # Validate many times
            for _ in range(1000):
                config.validate()
            
            duration = time.time() - start_time
            
        # Should validate 1000 times in under 1 second
        assert duration < 1.0, f"Config validation too slow: {duration:.2f}s for 1000 validations"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])