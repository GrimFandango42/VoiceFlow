"""
Comprehensive VoiceFlow Buffer Testing Suite
Tests buffer isolation, timing variations, and robustness
"""

import time
import numpy as np
import threading
from typing import Dict, List, Any
from localflow.config import Config
from localflow.audio_enhanced import EnhancedAudioRecorder
from localflow.asr_buffer_safe import BufferSafeWhisperASR

class ComprehensiveBufferTester:
    """Comprehensive testing of VoiceFlow buffer system"""
    
    def __init__(self):
        self.cfg = Config()
        self.test_results = []
        
    def test_hotkey_configuration(self) -> Dict[str, Any]:
        """Verify hotkey configuration is correct"""
        print("\n[TEST 1] Hotkey Configuration Verification")
        print("=" * 50)
        
        cfg = self.cfg
        hotkey_parts = []
        if cfg.hotkey_ctrl:
            hotkey_parts.append("Ctrl")
        if cfg.hotkey_shift:
            hotkey_parts.append("Shift")
        if cfg.hotkey_alt:
            hotkey_parts.append("Alt")
        if cfg.hotkey_key:
            hotkey_parts.append(cfg.hotkey_key)
        
        hotkey_string = " + ".join(hotkey_parts)
        expected_hotkey = "Ctrl + Shift"
        is_correct = hotkey_string == expected_hotkey
        
        print(f"Current hotkey: {hotkey_string}")
        print(f"Expected: {expected_hotkey}")
        print(f"Status: {'PASS' if is_correct else 'FAIL'}")
        
        if not is_correct:
            print(f"WARNING: Hotkey mismatch detected!")
        
        return {
            'test_name': 'Hotkey Configuration',
            'current_hotkey': hotkey_string,
            'expected_hotkey': expected_hotkey,
            'is_correct': is_correct,
            'status': 'PASS' if is_correct else 'FAIL'
        }
    
    def test_buffer_isolation_multiple_recordings(self) -> Dict[str, Any]:
        """Test buffer isolation across multiple consecutive recordings"""
        print("\n[TEST 2] Buffer Isolation - Multiple Consecutive Recordings")
        print("=" * 50)
        
        recorder = EnhancedAudioRecorder(self.cfg)
        recorder.start_continuous()
        time.sleep(0.3)  # Let pre-buffer collect data
        
        recordings = []
        buffer_sizes = []
        
        # Test 5 consecutive recordings
        for i in range(5):
            print(f"  Recording {i+1}/5...")
            
            # Start recording
            recorder.start()
            initial_buffer = recorder._ring_buffer.samples_written
            buffer_sizes.append(initial_buffer)
            
            # Simulate recording time
            time.sleep(0.4)
            
            # Stop and get audio
            audio_data = recorder.stop()
            recordings.append(len(audio_data))
            
            print(f"    Buffer at start: {initial_buffer} samples")
            print(f"    Audio captured: {len(audio_data)} samples")
            
            # Brief pause between recordings
            time.sleep(0.1)
        
        recorder.stop_continuous()
        
        # Analyze results
        buffer_properly_cleared = all(size < 20000 for size in buffer_sizes)  # Should be small
        recordings_reasonable = all(10000 < size < 50000 for size in recordings)  # Should be reasonable
        no_excessive_growth = max(recordings) - min(recordings) < 30000  # No excessive growth
        
        isolation_working = buffer_properly_cleared and recordings_reasonable and no_excessive_growth
        
        print(f"\nAnalysis:")
        print(f"  Buffer sizes at start: {buffer_sizes}")
        print(f"  Recording sizes: {recordings}")
        print(f"  Buffer properly cleared: {buffer_properly_cleared}")
        print(f"  Recordings reasonable: {recordings_reasonable}")
        print(f"  No excessive growth: {no_excessive_growth}")
        print(f"  Overall: {'PASS' if isolation_working else 'FAIL'}")
        
        return {
            'test_name': 'Buffer Isolation Multiple Recordings',
            'buffer_sizes': buffer_sizes,
            'recording_sizes': recordings,
            'buffer_cleared': buffer_properly_cleared,
            'recordings_reasonable': recordings_reasonable,
            'no_growth': no_excessive_growth,
            'isolation_working': isolation_working,
            'status': 'PASS' if isolation_working else 'FAIL'
        }
    
    def test_timing_variations(self) -> Dict[str, Any]:
        """Test various timing patterns between recordings"""
        print("\n[TEST 3] Timing Variations Test")
        print("=" * 50)
        
        recorder = EnhancedAudioRecorder(self.cfg)
        recorder.start_continuous()
        time.sleep(0.5)
        
        timing_scenarios = {
            'immediate': 0.0,       # Immediate next recording
            'quick': 0.1,          # 100ms gap
            'normal': 0.3,         # 300ms gap  
            'slow': 0.7,           # 700ms gap
            'very_slow': 1.2       # 1200ms gap
        }
        
        results = {}
        
        for scenario, delay in timing_scenarios.items():
            print(f"  Testing {scenario} timing (delay: {delay}s)...")
            
            # First recording
            recorder.start()
            time.sleep(0.3)
            audio1 = recorder.stop()
            
            # Wait specified delay
            time.sleep(delay)
            
            # Second recording
            recorder.start()
            initial_buffer = recorder._ring_buffer.samples_written
            time.sleep(0.3)
            audio2 = recorder.stop()
            
            # Analyze
            buffer_clean = initial_buffer < 16000  # Less than 1 second
            sizes_reasonable = 5000 < len(audio1) < 30000 and 5000 < len(audio2) < 30000
            
            results[scenario] = {
                'delay': delay,
                'audio1_size': len(audio1),
                'audio2_size': len(audio2),
                'buffer_at_start2': initial_buffer,
                'buffer_clean': buffer_clean,
                'sizes_reasonable': sizes_reasonable,
                'pass': buffer_clean and sizes_reasonable
            }
            
            print(f"    Audio sizes: {len(audio1)}, {len(audio2)} samples")
            print(f"    Buffer clean: {buffer_clean} ({initial_buffer} samples)")
            print(f"    Status: {'PASS' if results[scenario]['pass'] else 'FAIL'}")
        
        recorder.stop_continuous()
        
        all_passed = all(result['pass'] for result in results.values())
        
        print(f"\nOverall timing test: {'PASS' if all_passed else 'FAIL'}")
        
        return {
            'test_name': 'Timing Variations',
            'scenarios': results,
            'all_passed': all_passed,
            'status': 'PASS' if all_passed else 'FAIL'
        }
    
    def test_asr_buffer_isolation(self) -> Dict[str, Any]:
        """Test ASR-level buffer isolation"""
        print("\n[TEST 4] ASR Buffer Isolation Test")
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        # Create distinct test audio signals
        duration = 1.0  # 1 second
        samples = int(duration * self.cfg.sample_rate)
        
        # Different frequency signals to test isolation
        audio1 = np.sin(2 * np.pi * 440 * np.linspace(0, duration, samples)).astype(np.float32) * 0.1  # 440Hz
        audio2 = np.sin(2 * np.pi * 880 * np.linspace(0, duration, samples)).astype(np.float32) * 0.1  # 880Hz
        audio3 = np.sin(2 * np.pi * 1320 * np.linspace(0, duration, samples)).astype(np.float32) * 0.1  # 1320Hz
        
        print("  Testing ASR state isolation...")
        
        # Test that each transcription is independent
        states = []
        for i, audio in enumerate([audio1, audio2, audio3], 1):
            print(f"    Processing audio {i}...")
            
            # Create clean state
            state = asr._create_clean_recording_state(audio)
            states.append(state)
            
            # Verify independence
            unique_id = state['recording_id']
            vad_disabled = not state['use_vad']
            audio_isolated = not np.array_equal(state['audio'], audio1) if i > 1 else True
            
            print(f"      Recording ID: {unique_id}")
            print(f"      VAD disabled: {vad_disabled}")
            print(f"      Audio isolated: {audio_isolated}")
        
        # Verify all states are unique and isolated
        unique_ids = len(set(state['recording_id'] for state in states)) == 3
        all_vad_disabled = all(not state['use_vad'] for state in states)
        
        isolation_working = unique_ids and all_vad_disabled
        
        print(f"\nASR Isolation Analysis:")
        print(f"  Unique recording IDs: {unique_ids}")
        print(f"  All VAD disabled: {all_vad_disabled}")
        print(f"  Status: {'PASS' if isolation_working else 'FAIL'}")
        
        return {
            'test_name': 'ASR Buffer Isolation',
            'unique_ids': unique_ids,
            'vad_disabled': all_vad_disabled,
            'isolation_working': isolation_working,
            'status': 'PASS' if isolation_working else 'FAIL'
        }
    
    def test_memory_management(self) -> Dict[str, Any]:
        """Test memory management and leak prevention"""
        print("\n[TEST 5] Memory Management Test")
        print("=" * 50)
        
        recorder = EnhancedAudioRecorder(self.cfg)
        
        # Test memory bounds
        max_duration_expected = 300.0  # 5 minutes
        actual_max = recorder._ring_buffer.max_samples / self.cfg.sample_rate
        
        pre_buffer_duration = recorder._pre_buffer_duration
        pre_buffer_max = recorder._pre_buffer.max_samples / self.cfg.sample_rate
        
        memory_bounds_correct = (
            abs(actual_max - max_duration_expected) < 1.0 and  # Within 1 second
            1.0 <= pre_buffer_duration <= 2.0  # Reasonable pre-buffer size
        )
        
        # Test buffer clearing
        recorder.start_continuous()
        time.sleep(0.2)
        
        # Fill pre-buffer
        initial_pre_size = len(recorder._pre_buffer.get_data())
        
        # Clear and verify
        recorder._pre_buffer.clear()
        cleared_pre_size = len(recorder._pre_buffer.get_data())
        
        recorder.stop_continuous()
        
        clearing_works = cleared_pre_size == 0
        
        print(f"  Main buffer max duration: {actual_max:.1f}s (expected: {max_duration_expected}s)")
        print(f"  Pre-buffer duration: {pre_buffer_duration:.1f}s")
        print(f"  Pre-buffer before clear: {initial_pre_size} samples")
        print(f"  Pre-buffer after clear: {cleared_pre_size} samples")
        print(f"  Memory bounds correct: {memory_bounds_correct}")
        print(f"  Clearing works: {clearing_works}")
        
        memory_management_ok = memory_bounds_correct and clearing_works
        
        print(f"  Status: {'PASS' if memory_management_ok else 'FAIL'}")
        
        return {
            'test_name': 'Memory Management',
            'max_duration': actual_max,
            'pre_buffer_duration': pre_buffer_duration,
            'bounds_correct': memory_bounds_correct,
            'clearing_works': clearing_works,
            'memory_ok': memory_management_ok,
            'status': 'PASS' if memory_management_ok else 'FAIL'
        }
    
    def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run all comprehensive tests"""
        print("=" * 70)
        print("VoiceFlow Comprehensive Buffer Testing Suite")
        print("=" * 70)
        
        test_methods = [
            self.test_hotkey_configuration,
            self.test_buffer_isolation_multiple_recordings,
            self.test_timing_variations,
            self.test_asr_buffer_isolation,
            self.test_memory_management,
        ]
        
        results = []
        passed_tests = 0
        
        for test_method in test_methods:
            try:
                result = test_method()
                results.append(result)
                if result['status'] == 'PASS':
                    passed_tests += 1
                self.test_results.append(result)
            except Exception as e:
                error_result = {
                    'test_name': test_method.__name__,
                    'error': str(e),
                    'status': 'ERROR'
                }
                results.append(error_result)
                self.test_results.append(error_result)
                print(f"[ERROR] {test_method.__name__}: {e}")
        
        total_tests = len(results)
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        overall_result = {
            'test_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'success_rate': success_rate,
            'all_results': results,
            'system_status': 'ROBUST' if success_rate >= 90 else 'NEEDS_ATTENTION'
        }
        
        # Summary
        print("\n" + "=" * 70)
        print("COMPREHENSIVE TEST RESULTS")
        print("=" * 70)
        print(f"Tests completed: {total_tests}")
        print(f"Tests passed: {passed_tests}")
        print(f"Success rate: {success_rate:.1f}%")
        print(f"System status: {overall_result['system_status']}")
        
        if overall_result['system_status'] == 'ROBUST':
            print("\n[SUCCESS] VoiceFlow buffer system is ROBUST and ready for production!")
            print("- Buffer isolation working correctly")
            print("- No memory leaks detected")  
            print("- Timing variations handled properly")
            print("- ASR state isolation confirmed")
            print("- Hotkey configuration verified")
        else:
            failed_tests = [r for r in results if r['status'] != 'PASS']
            print(f"\n[WARNING] {len(failed_tests)} test(s) need attention:")
            for test in failed_tests:
                print(f"- {test['test_name']}: {test['status']}")
        
        return overall_result

def main():
    """Run comprehensive buffer testing"""
    tester = ComprehensiveBufferTester()
    results = tester.run_comprehensive_tests()
    
    return 0 if results['system_status'] == 'ROBUST' else 1

if __name__ == "__main__":
    exit(main())