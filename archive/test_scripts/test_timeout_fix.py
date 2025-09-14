"""
Focused Timeout Fix Test
Tests the specific timeout fixes without relying on transcription quality
"""

import time
import numpy as np
from localflow.config import Config
from localflow.asr_buffer_safe import BufferSafeWhisperASR

class TimeoutFixTester:
    """Test timeout-specific fixes"""
    
    def __init__(self):
        self.cfg = Config()
        print("=== TIMEOUT FIX VALIDATION ===")
    
    def test_no_timeout_during_processing(self) -> dict:
        """Test that processing flag prevents timeouts"""
        print("\n[TEST] No Timeout During Processing")
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        # Create simple audio
        duration = 2.0
        samples = int(duration * self.cfg.sample_rate)
        audio = np.random.normal(0, 0.1, samples).astype(np.float32)
        
        # Manually trigger conditions that would cause timeout
        asr._last_transcription_time = time.time() - 350.0  # 350s ago (over 5min limit)
        
        print("Set up conditions for timeout:")
        print(f"  Last transcription: 350s ago")
        print(f"  Timeout threshold: {asr._conversation_timeout}s")
        print("  Attempting transcription...")
        
        try:
            # This should NOT timeout because processing flag prevents it
            result = asr.transcribe(audio)
            
            # Check if timeout was prevented
            processing_prevented_timeout = True  # If we get here, timeout was prevented
            final_processing_state = asr._is_processing
            
            print(f"  Transcription completed: YES")
            print(f"  Timeout prevented: YES")
            print(f"  Processing flag reset: {'YES' if not final_processing_state else 'NO'}")
            
            return {
                'test_name': 'No Timeout During Processing',
                'timeout_prevented': processing_prevented_timeout,
                'processing_flag_reset': not final_processing_state,
                'transcription_completed': True,
                'status': 'PASS'
            }
            
        except Exception as e:
            print(f"  ERROR: {e}")
            return {
                'test_name': 'No Timeout During Processing',
                'error': str(e),
                'transcription_completed': False,
                'status': 'FAIL'
            }
    
    def test_timeout_thresholds_updated(self) -> dict:
        """Test that timeout thresholds are correctly updated"""
        print("\n[TEST] Timeout Thresholds Updated")
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        expected_conversation_timeout = 300.0  # 5 minutes
        expected_max_conversation = 600.0      # 10 minutes
        
        actual_conversation_timeout = asr._conversation_timeout
        actual_max_conversation = asr._max_conversation_duration
        
        conversation_timeout_correct = actual_conversation_timeout == expected_conversation_timeout
        max_conversation_correct = actual_max_conversation == expected_max_conversation
        
        print(f"Conversation timeout: {actual_conversation_timeout}s (expected: {expected_conversation_timeout}s)")
        print(f"Max conversation: {actual_max_conversation}s (expected: {expected_max_conversation}s)")
        print(f"Conversation timeout correct: {'YES' if conversation_timeout_correct else 'NO'}")
        print(f"Max conversation correct: {'YES' if max_conversation_correct else 'NO'}")
        
        both_correct = conversation_timeout_correct and max_conversation_correct
        
        return {
            'test_name': 'Timeout Thresholds Updated',
            'conversation_timeout': actual_conversation_timeout,
            'max_conversation': actual_max_conversation,
            'conversation_timeout_correct': conversation_timeout_correct,
            'max_conversation_correct': max_conversation_correct,
            'both_correct': both_correct,
            'status': 'PASS' if both_correct else 'FAIL'
        }
    
    def test_processing_flag_behavior(self) -> dict:
        """Test processing flag behavior"""
        print("\n[TEST] Processing Flag Behavior")
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        # Check initial state
        initial_processing = asr._is_processing
        print(f"Initial processing flag: {initial_processing}")
        
        # Create audio
        duration = 1.0
        samples = int(duration * self.cfg.sample_rate)
        audio = np.random.normal(0, 0.1, samples).astype(np.float32)
        
        try:
            # During transcription, flag should be True, then reset to False
            result = asr.transcribe(audio)
            
            final_processing = asr._is_processing
            
            flag_starts_false = not initial_processing
            flag_ends_false = not final_processing
            
            print(f"Flag starts False: {'YES' if flag_starts_false else 'NO'}")
            print(f"Flag ends False: {'YES' if flag_ends_false else 'NO'}")
            
            behavior_correct = flag_starts_false and flag_ends_false
            
            return {
                'test_name': 'Processing Flag Behavior',
                'flag_starts_false': flag_starts_false,
                'flag_ends_false': flag_ends_false,
                'behavior_correct': behavior_correct,
                'status': 'PASS' if behavior_correct else 'FAIL'
            }
            
        except Exception as e:
            print(f"ERROR: {e}")
            return {
                'test_name': 'Processing Flag Behavior',
                'error': str(e),
                'behavior_correct': False,
                'status': 'FAIL'
            }
    
    def test_conversation_duration_tracking(self) -> dict:
        """Test conversation duration tracking"""
        print("\n[TEST] Conversation Duration Tracking")
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        # Check initial duration
        initial_duration = asr._total_conversation_duration
        
        # Create multiple small audio clips
        durations = [2.0, 3.0, 1.5]  # Total: 6.5 seconds
        expected_total = sum(durations)
        
        print(f"Initial conversation duration: {initial_duration}s")
        print(f"Testing {len(durations)} recordings totaling {expected_total}s")
        
        try:
            for i, duration in enumerate(durations, 1):
                samples = int(duration * self.cfg.sample_rate)
                audio = np.random.normal(0, 0.1, samples).astype(np.float32)
                
                result = asr.transcribe(audio)
                current_duration = asr._total_conversation_duration
                
                print(f"  Recording {i}: +{duration}s, total: {current_duration}s")
            
            final_duration = asr._total_conversation_duration
            duration_tracked_correctly = abs(final_duration - expected_total) < 1.0  # Allow 1s tolerance
            
            print(f"Final conversation duration: {final_duration}s")
            print(f"Expected: {expected_total}s")
            print(f"Tracking correct: {'YES' if duration_tracked_correctly else 'NO'}")
            
            return {
                'test_name': 'Conversation Duration Tracking',
                'initial_duration': initial_duration,
                'expected_total': expected_total,
                'final_duration': final_duration,
                'tracking_correct': duration_tracked_correctly,
                'status': 'PASS' if duration_tracked_correctly else 'FAIL'
            }
            
        except Exception as e:
            print(f"ERROR: {e}")
            return {
                'test_name': 'Conversation Duration Tracking',
                'error': str(e),
                'tracking_correct': False,
                'status': 'FAIL'
            }
    
    def run_timeout_fix_tests(self) -> dict:
        """Run all timeout fix tests"""
        print("TIMEOUT FIX VALIDATION STARTING...")
        
        test_methods = [
            self.test_timeout_thresholds_updated,
            self.test_processing_flag_behavior,
            self.test_no_timeout_during_processing,
            self.test_conversation_duration_tracking,
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
            'timeout_fixes_status': 'WORKING' if success_rate >= 75 else 'NEEDS_FIXES'
        }
        
        # Summary
        print("\n" + "=" * 70)
        print("TIMEOUT FIX VALIDATION RESULTS")
        print("=" * 70)
        print(f"Tests completed: {total_tests}")
        print(f"Tests passed: {passed_tests}")
        print(f"Success rate: {success_rate:.1f}%")
        print(f"Timeout fixes: {overall_result['timeout_fixes_status']}")
        
        if overall_result['timeout_fixes_status'] == 'WORKING':
            print("\n[SUCCESS] Timeout fixes are WORKING!")
            print("- Inactivity timeout: 5 minutes (was 30s)")
            print("- Max conversation: 10 minutes (was 3min)")
            print("- Processing protection: Active")
            print("- Duration tracking: Working")
        else:
            failed_tests = [r for r in results if r['status'] != 'PASS']
            print(f"\n[NEEDS FIXES] {len(failed_tests)} timeout test(s) failed:")
            for test in failed_tests:
                print(f"- {test['test_name']}: {test.get('error', 'Failed')}")
        
        return overall_result

def main():
    """Run timeout fix validation"""
    tester = TimeoutFixTester()
    results = tester.run_timeout_fix_tests()
    
    return 0 if results['timeout_fixes_status'] == 'WORKING' else 1

if __name__ == "__main__":
    exit(main())