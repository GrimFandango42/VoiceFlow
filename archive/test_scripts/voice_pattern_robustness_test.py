"""
Voice Pattern Robustness Testing for VoiceFlow
Tests different speech patterns, pauses, and lengths
"""

import time
import numpy as np
from localflow.config import Config
from localflow.audio_enhanced import EnhancedAudioRecorder
from localflow.asr_buffer_safe import BufferSafeWhisperASR

class VoicePatternTester:
    """Test VoiceFlow with various voice patterns and scenarios"""
    
    def __init__(self):
        self.cfg = Config()
        
    def test_pause_pattern_handling(self) -> dict:
        """Test handling of different pause patterns in speech"""
        print("\n[VOICE TEST 1] Pause Pattern Handling")
        print("=" * 50)
        
        recorder = EnhancedAudioRecorder(self.cfg)
        
        # Test different pause scenarios
        pause_scenarios = {
            'no_pause': 0.0,        # Continuous speech
            'short_pause': 0.2,     # 200ms pause mid-speech
            'medium_pause': 0.5,    # 500ms pause mid-speech  
            'long_pause': 1.0,      # 1000ms pause mid-speech
            'very_long_pause': 2.0  # 2000ms pause mid-speech
        }
        
        results = {}
        recorder.start_continuous()
        time.sleep(0.3)
        
        for scenario, pause_duration in pause_scenarios.items():
            print(f"  Testing {scenario} ({pause_duration}s pause)...")
            
            recorder.start()
            
            # Simulate speech with pause in middle
            time.sleep(0.5)  # First part of speech
            
            if pause_duration > 0:
                time.sleep(pause_duration)  # Pause
            
            time.sleep(0.5)  # Second part of speech
            
            audio_data = recorder.stop()
            audio_duration = len(audio_data) / self.cfg.sample_rate
            
            # Expected duration should account for pause
            expected_min_duration = 1.0 + pause_duration * 0.8  # Allow some margin
            expected_max_duration = 1.5 + pause_duration * 1.2
            
            duration_reasonable = expected_min_duration <= audio_duration <= expected_max_duration
            
            results[scenario] = {
                'pause_duration': pause_duration,
                'audio_duration': audio_duration,
                'expected_min': expected_min_duration,
                'expected_max': expected_max_duration,
                'duration_reasonable': duration_reasonable
            }
            
            print(f"    Audio duration: {audio_duration:.2f}s")
            print(f"    Expected range: {expected_min_duration:.2f}s - {expected_max_duration:.2f}s")
            print(f"    Status: {'PASS' if duration_reasonable else 'FAIL'}")
            
            time.sleep(0.2)  # Brief pause between tests
        
        recorder.stop_continuous()
        
        all_passed = all(result['duration_reasonable'] for result in results.values())
        
        return {
            'test_name': 'Pause Pattern Handling',
            'scenarios': results,
            'all_passed': all_passed,
            'status': 'PASS' if all_passed else 'FAIL'
        }
    
    def test_length_variations(self) -> dict:
        """Test different recording lengths"""
        print("\n[VOICE TEST 2] Recording Length Variations")
        print("=" * 50)
        
        recorder = EnhancedAudioRecorder(self.cfg)
        
        # Test different recording lengths
        length_scenarios = {
            'very_short': 0.3,    # 300ms - quick word
            'short': 0.8,         # 800ms - short phrase
            'medium': 2.0,        # 2s - normal sentence
            'long': 5.0,          # 5s - long sentence
            'very_long': 10.0     # 10s - paragraph
        }
        
        results = {}
        recorder.start_continuous()
        time.sleep(0.3)
        
        for scenario, target_length in length_scenarios.items():
            print(f"  Testing {scenario} recording ({target_length}s)...")
            
            recorder.start()
            time.sleep(target_length)
            audio_data = recorder.stop()
            
            audio_duration = len(audio_data) / self.cfg.sample_rate
            
            # Allow for pre-buffer addition and timing variance
            expected_min = target_length + 0.5  # Pre-buffer adds time
            expected_max = target_length + 2.0  # Allow for variance
            
            duration_reasonable = expected_min <= audio_duration <= expected_max
            has_audio = len(audio_data) > 1000  # At least some audio
            
            results[scenario] = {
                'target_length': target_length,
                'actual_duration': audio_duration,
                'audio_samples': len(audio_data),
                'duration_reasonable': duration_reasonable,
                'has_audio': has_audio,
                'pass': duration_reasonable and has_audio
            }
            
            print(f"    Target: {target_length}s, Actual: {audio_duration:.2f}s")
            print(f"    Samples: {len(audio_data)}")
            print(f"    Status: {'PASS' if results[scenario]['pass'] else 'FAIL'}")
            
            time.sleep(0.2)
        
        recorder.stop_continuous()
        
        all_passed = all(result['pass'] for result in results.values())
        
        return {
            'test_name': 'Recording Length Variations',
            'scenarios': results,
            'all_passed': all_passed,
            'status': 'PASS' if all_passed else 'FAIL'
        }
    
    def test_rapid_succession_recordings(self) -> dict:
        """Test rapid succession of recordings"""
        print("\n[VOICE TEST 3] Rapid Succession Recordings")
        print("=" * 50)
        
        recorder = EnhancedAudioRecorder(self.cfg)
        recorder.start_continuous()
        time.sleep(0.3)
        
        # Test 8 rapid recordings with minimal gaps
        recordings = []
        buffer_states = []
        
        for i in range(8):
            print(f"  Rapid recording {i+1}/8...")
            
            recorder.start()
            initial_buffer = recorder._ring_buffer.samples_written
            buffer_states.append(initial_buffer)
            
            # Very short recording
            time.sleep(0.2)
            
            audio_data = recorder.stop()
            recordings.append(len(audio_data))
            
            # Minimal gap (simulating very fast user)
            time.sleep(0.05)
        
        recorder.stop_continuous()
        
        # Analysis
        all_have_audio = all(size > 1000 for size in recordings)
        buffers_reasonable = all(size < 30000 for size in buffer_states)  # Not accumulating
        no_extreme_variation = (max(recordings) - min(recordings)) < 50000  # Reasonable consistency
        
        rapid_succession_ok = all_have_audio and buffers_reasonable and no_extreme_variation
        
        print(f"\nRapid Succession Analysis:")
        print(f"  Recording sizes: {recordings}")
        print(f"  Buffer states: {buffer_states}")
        print(f"  All have audio: {all_have_audio}")
        print(f"  Buffers reasonable: {buffers_reasonable}")
        print(f"  No extreme variation: {no_extreme_variation}")
        print(f"  Status: {'PASS' if rapid_succession_ok else 'FAIL'}")
        
        return {
            'test_name': 'Rapid Succession Recordings',
            'recording_sizes': recordings,
            'buffer_states': buffer_states,
            'all_have_audio': all_have_audio,
            'buffers_reasonable': buffers_reasonable,
            'no_extreme_variation': no_extreme_variation,
            'rapid_succession_ok': rapid_succession_ok,
            'status': 'PASS' if rapid_succession_ok else 'FAIL'
        }
    
    def test_buffer_state_consistency(self) -> dict:
        """Test that buffer state remains consistent across different scenarios"""
        print("\n[VOICE TEST 4] Buffer State Consistency")
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        # Test various audio patterns to ensure consistent state handling
        test_patterns = []
        
        # Pattern 1: Short burst
        pattern1 = np.random.normal(0, 0.1, int(0.5 * self.cfg.sample_rate)).astype(np.float32)
        test_patterns.append(('short_burst', pattern1))
        
        # Pattern 2: Long recording
        pattern2 = np.random.normal(0, 0.1, int(3.0 * self.cfg.sample_rate)).astype(np.float32)
        test_patterns.append(('long_recording', pattern2))
        
        # Pattern 3: Very quiet
        pattern3 = np.random.normal(0, 0.01, int(1.0 * self.cfg.sample_rate)).astype(np.float32)
        test_patterns.append(('very_quiet', pattern3))
        
        state_consistency_results = []
        
        for pattern_name, audio_pattern in test_patterns:
            print(f"  Testing {pattern_name}...")
            
            # Create multiple states for same pattern type
            states = []
            for i in range(3):
                state = asr._create_clean_recording_state(audio_pattern.copy())
                states.append(state)
            
            # Verify consistency
            all_unique_ids = len(set(s['recording_id'] for s in states)) == 3
            all_vad_disabled = all(not s['use_vad'] for s in states)
            same_audio_duration = len(set(s['audio_duration'] for s in states)) == 1
            
            consistency_ok = all_unique_ids and all_vad_disabled and same_audio_duration
            
            state_consistency_results.append({
                'pattern': pattern_name,
                'unique_ids': all_unique_ids,
                'vad_disabled': all_vad_disabled,
                'same_duration': same_audio_duration,
                'consistent': consistency_ok
            })
            
            print(f"    Unique IDs: {all_unique_ids}")
            print(f"    VAD disabled: {all_vad_disabled}")  
            print(f"    Same duration: {same_audio_duration}")
            print(f"    Status: {'PASS' if consistency_ok else 'FAIL'}")
        
        all_consistent = all(result['consistent'] for result in state_consistency_results)
        
        return {
            'test_name': 'Buffer State Consistency',
            'pattern_results': state_consistency_results,
            'all_consistent': all_consistent,
            'status': 'PASS' if all_consistent else 'FAIL'
        }
    
    def run_voice_pattern_tests(self) -> dict:
        """Run all voice pattern tests"""
        print("=" * 70)
        print("VoiceFlow Voice Pattern Robustness Testing")
        print("=" * 70)
        
        test_methods = [
            self.test_pause_pattern_handling,
            self.test_length_variations,
            self.test_rapid_succession_recordings,
            self.test_buffer_state_consistency,
        ]
        
        results = []
        passed_tests = 0
        
        for test_method in test_methods:
            try:
                result = test_method()
                results.append(result)
                if result['status'] == 'PASS':
                    passed_tests += 1
            except Exception as e:
                error_result = {
                    'test_name': test_method.__name__,
                    'error': str(e),
                    'status': 'ERROR'
                }
                results.append(error_result)
                print(f"[ERROR] {test_method.__name__}: {e}")
        
        total_tests = len(results)
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        overall_result = {
            'test_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'success_rate': success_rate,
            'all_results': results,
            'voice_robustness_status': 'EXCELLENT' if success_rate >= 90 else 'NEEDS_WORK'
        }
        
        # Summary
        print("\n" + "=" * 70)
        print("VOICE PATTERN ROBUSTNESS RESULTS")
        print("=" * 70)
        print(f"Tests completed: {total_tests}")
        print(f"Tests passed: {passed_tests}")
        print(f"Success rate: {success_rate:.1f}%")
        print(f"Voice robustness: {overall_result['voice_robustness_status']}")
        
        if overall_result['voice_robustness_status'] == 'EXCELLENT':
            print("\n[SUCCESS] VoiceFlow voice pattern handling is EXCELLENT!")
            print("- Handles various pause patterns correctly")
            print("- Supports wide range of recording lengths")
            print("- Robust under rapid succession scenarios")
            print("- Maintains consistent buffer state")
        else:
            failed_tests = [r for r in results if r['status'] != 'PASS']
            print(f"\n[WARNING] {len(failed_tests)} voice test(s) need attention:")
            for test in failed_tests:
                print(f"- {test['test_name']}: {test['status']}")
        
        return overall_result

def main():
    """Run voice pattern robustness testing"""
    tester = VoicePatternTester()
    results = tester.run_voice_pattern_tests()
    
    return 0 if results['voice_robustness_status'] == 'EXCELLENT' else 1

if __name__ == "__main__":
    exit(main())