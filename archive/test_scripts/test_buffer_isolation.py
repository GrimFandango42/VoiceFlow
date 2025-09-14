"""
Quick test to verify buffer isolation fix
"""

import time
import numpy as np
from localflow.config import Config
from localflow.audio_enhanced import EnhancedAudioRecorder

def test_buffer_isolation():
    """Test that buffers are properly isolated between recordings"""
    print("Testing Buffer Isolation Fix...")
    print("=" * 50)
    
    cfg = Config()
    recorder = EnhancedAudioRecorder(cfg)
    
    # Start continuous recording for pre-buffer
    recorder.start_continuous()
    time.sleep(0.5)  # Let pre-buffer collect some data
    
    # Test 1: First recording
    print("\n[TEST 1] First Recording")
    recorder.start()
    
    # Check initial state
    initial_buffer_size = recorder._ring_buffer.samples_written
    print(f"  Initial buffer samples: {initial_buffer_size}")
    
    # Simulate some recording
    time.sleep(0.5)
    audio1 = recorder.stop()
    print(f"  Audio 1 length: {len(audio1)} samples")
    
    # Test 2: Second recording - should NOT contain first
    print("\n[TEST 2] Second Recording")
    time.sleep(0.2)  # Brief pause between recordings
    
    recorder.start()
    
    # Check that buffer was cleared
    buffer_after_start = recorder._ring_buffer.samples_written
    print(f"  Buffer after start (should be small): {buffer_after_start} samples")
    
    time.sleep(0.5)
    audio2 = recorder.stop()
    print(f"  Audio 2 length: {len(audio2)} samples")
    
    # Test 3: Third recording - verify no accumulation
    print("\n[TEST 3] Third Recording")
    time.sleep(0.2)
    
    recorder.start()
    buffer_after_third_start = recorder._ring_buffer.samples_written
    print(f"  Buffer after start (should be small): {buffer_after_third_start} samples")
    
    time.sleep(0.5)
    audio3 = recorder.stop()
    print(f"  Audio 3 length: {len(audio3)} samples")
    
    # Stop continuous recording
    recorder.stop_continuous()
    
    # Validation
    print("\n" + "=" * 50)
    print("VALIDATION RESULTS:")
    print("=" * 50)
    
    # Check that buffer sizes are reasonable and not accumulating
    sizes_reasonable = (
        len(audio1) < 20000 and  # ~1.25 seconds at 16kHz
        len(audio2) < 20000 and
        len(audio3) < 20000
    )
    
    # Check that buffer is cleared at start
    buffer_cleared = (
        buffer_after_start < 16000 and  # Less than 1 second of pre-buffer
        buffer_after_third_start < 16000
    )
    
    if sizes_reasonable and buffer_cleared:
        print("[PASS] Buffer isolation working correctly!")
        print("  - Each recording has independent buffer")
        print("  - No accumulation between recordings")
        print("  - Pre-buffer properly managed")
    else:
        print("[FAIL] Buffer isolation issue detected!")
        if not sizes_reasonable:
            print("  - Audio sizes indicate accumulation")
        if not buffer_cleared:
            print("  - Buffer not properly cleared at start")
    
    return sizes_reasonable and buffer_cleared

if __name__ == "__main__":
    success = test_buffer_isolation()
    exit(0 if success else 1)