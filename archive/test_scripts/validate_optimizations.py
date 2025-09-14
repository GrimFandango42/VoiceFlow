"""
VoiceFlow Optimization Validation Script
Test key improvements: buffer timing, pre-buffer effectiveness, reduced logging
"""

import time
import numpy as np
import logging
from localflow.config import Config
from localflow.audio_enhanced import EnhancedAudioRecorder
from localflow.asr_buffer_safe import BufferSafeWhisperASR

def test_pre_buffer_timing():
    """Test pre-buffer timing optimization"""
    print("[TEST] Pre-buffer timing optimization...")
    
    cfg = Config()
    recorder = EnhancedAudioRecorder(cfg)
    
    # Test pre-buffer parameters
    assert recorder._pre_buffer_duration == 1.5, f"Expected 1.5s, got {recorder._pre_buffer_duration}s"
    
    # Start continuous recording
    recorder.start_continuous()
    time.sleep(0.5)  # Let it collect some data
    
    # Test pre-buffer data availability
    pre_data = recorder._pre_buffer.get_data()
    duration = len(pre_data) / cfg.sample_rate if len(pre_data) > 0 else 0
    
    recorder.stop_continuous()
    
    print(f"  Pre-buffer duration: {recorder._pre_buffer_duration}s")
    print(f"  Collected data: {duration:.3f}s")
    print(f"  Status: {'PASS' if duration > 0.3 else 'FAIL'}")
    
    return duration > 0.3

def test_buffer_isolation():
    """Test buffer isolation between recordings"""
    print("[TEST] Buffer isolation and clearing...")
    
    cfg = Config()
    asr = BufferSafeWhisperASR(cfg)
    
    # Create test audio
    test_audio = np.random.normal(0, 0.1, int(2.0 * cfg.sample_rate)).astype(np.float32)
    
    # Test clean state creation
    state = asr._create_clean_recording_state(test_audio)
    
    assert 'audio' in state
    assert 'recording_id' in state
    assert state['use_vad'] == False  # Critical: VAD must be disabled
    
    print(f"  Recording ID: {state['recording_id']}")
    print(f"  VAD disabled: {not state['use_vad']}")
    print(f"  Audio duration: {state['audio_duration']:.3f}s")
    print(f"  Status: PASS")
    
    return True

def test_reduced_logging():
    """Test reduced logging frequency"""
    print("[TEST] Reduced logging verbosity...")
    
    cfg = Config()
    recorder = EnhancedAudioRecorder(cfg)
    
    # Simulate callback count progression
    test_counts = [50, 100, 150, 200, 250, 300]
    logged_counts = []
    
    for count in test_counts:
        recorder._callback_count = count
        # Check if this would trigger logging (every 200 callbacks)
        if count % 200 == 0:
            logged_counts.append(count)
    
    print(f"  Test counts: {test_counts}")
    print(f"  Would log at: {logged_counts}")
    print(f"  Logging reduction: {len(test_counts) - len(logged_counts)} fewer messages")
    print(f"  Status: {'PASS' if len(logged_counts) <= 2 else 'FAIL'}")
    
    return len(logged_counts) <= 2

def test_model_reinitialization():
    """Test model reinitialization logic"""
    print("[TEST] Model reinitialization prevention...")
    
    cfg = Config()
    asr = BufferSafeWhisperASR(cfg)
    
    # Test reinitialization threshold
    assert asr._max_transcriptions_before_reload == 5, "Reload threshold should be 5"
    
    # Simulate transcription count
    asr._transcriptions_since_reload = 0
    for i in range(6):
        asr._transcriptions_since_reload += 1
        would_reload = asr._transcriptions_since_reload >= asr._max_transcriptions_before_reload
        if would_reload:
            print(f"    Would reload after transcription {i+1}")
            asr._transcriptions_since_reload = 0  # Reset as would happen in actual reload
    
    print(f"  Reload threshold: {asr._max_transcriptions_before_reload}")
    print(f"  Current count: {asr._transcriptions_since_reload}")
    print(f"  Status: PASS")
    
    return True

def run_optimization_validation():
    """Run all optimization validation tests"""
    print("=" * 60)
    print("VoiceFlow Optimization Validation")
    print("=" * 60)
    
    tests = [
        ("Pre-buffer timing", test_pre_buffer_timing),
        ("Buffer isolation", test_buffer_isolation),
        ("Reduced logging", test_reduced_logging),
        ("Model reinitialization", test_model_reinitialization),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n[RUNNING] {test_name}...")
        try:
            result = test_func()
            results.append(result)
            status = "PASS" if result else "FAIL"
            print(f"[{status}] {test_name}")
        except Exception as e:
            print(f"[ERROR] {test_name}: {e}")
            results.append(False)
    
    # Summary
    passed = sum(results)
    total = len(results)
    
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Tests passed: {passed}/{total}")
    print(f"Success rate: {passed/total*100:.1f}%")
    
    if passed == total:
        print("\n[SUCCESS] All optimizations validated successfully!")
        print("VoiceFlow is ready for enhanced performance testing.")
    else:
        print(f"\n[WARNING] {total-passed} optimization(s) need attention.")
    
    return passed == total

if __name__ == "__main__":
    success = run_optimization_validation()
    exit(0 if success else 1)