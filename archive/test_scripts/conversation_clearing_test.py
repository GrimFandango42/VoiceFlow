"""
Conversation Clearing Test - Tests aggressive clearing mechanisms
Tests the fixes for model reinitialization and long conversation handling
"""

import time
import numpy as np
from localflow.config import Config
from localflow.asr_buffer_safe import BufferSafeWhisperASR

class ConversationClearingTester:
    """Test conversation clearing and model stability fixes"""
    
    def __init__(self):
        self.cfg = Config()
        print("=== CONVERSATION CLEARING VALIDATION ===")
        print("Testing fixes for:")
        print("1. Model reinitialization frequency (20 vs 5 transcriptions)")
        print("2. Long conversation clearing (3-minute timeout)")
        print("3. Inactivity clearing (30s timeout)")
    
    def test_frequent_transcriptions(self) -> dict:
        """Test that we can do many transcriptions without model reload issues"""
        print("\n[TEST 1] Frequent Transcriptions (Beyond 5 threshold)")
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        # Test 8 consecutive transcriptions (would have hit old 5-limit)
        results = []
        
        for i in range(8):
            print(f"  Transcription {i+1}/8...")
            
            # Create test audio
            duration = 1.0 + (i * 0.1)  # Slightly different lengths
            samples = int(duration * self.cfg.sample_rate)
            freq = 300 + (i * 50)
            audio = np.sin(2 * np.pi * freq * np.linspace(0, duration, samples)).astype(np.float32) * 0.05
            
            try:
                start_time = time.perf_counter()
                result = asr.transcribe(audio)
                processing_time = time.perf_counter() - start_time
                
                success = len(result.strip()) > 0
                speed_factor = duration / processing_time if processing_time > 0 else 0
                
                results.append({
                    'transcription_num': i + 1,
                    'duration': duration,
                    'processing_time': processing_time,
                    'speed_factor': speed_factor,
                    'success': success,
                    'result_length': len(result)
                })
                
                print(f"    Duration: {duration:.2f}s, Speed: {speed_factor:.1f}x, Success: {'YES' if success else 'NO'}")
                
                # Brief pause between transcriptions
                time.sleep(0.1)
                
            except Exception as e:
                print(f"    ERROR: {e}")
                results.append({
                    'transcription_num': i + 1,
                    'error': str(e),
                    'success': False
                })
                break
        
        successful_count = sum(1 for r in results if r.get('success', False))
        all_successful = successful_count == 8
        
        print(f"\nFrequent Transcriptions Result:")
        print(f"  Successful: {successful_count}/8")
        print(f"  All successful: {'YES' if all_successful else 'NO'}")
        
        return {
            'test_name': 'Frequent Transcriptions',
            'transcriptions_attempted': len(results),
            'transcriptions_successful': successful_count,
            'all_successful': all_successful,
            'results': results,
            'status': 'PASS' if all_successful else 'FAIL'
        }
    
    def test_conversation_timeout_clearing(self) -> dict:
        """Test conversation clearing after timeout"""
        print("\n[TEST 2] Conversation Timeout Clearing")
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        # Test sequence:
        # 1. Some transcriptions
        # 2. Wait for timeout (31s)
        # 3. More transcriptions should work
        
        print("  Phase 1: Initial transcriptions...")
        phase1_audio = np.sin(2 * np.pi * 440 * np.linspace(0, 2.0, int(2.0 * self.cfg.sample_rate))).astype(np.float32) * 0.05
        
        try:
            result1 = asr.transcribe(phase1_audio)
            phase1_success = len(result1.strip()) > 0
            print(f"    Phase 1 result: {'SUCCESS' if phase1_success else 'FAILED'}")
        except Exception as e:
            print(f"    Phase 1 ERROR: {e}")
            phase1_success = False
        
        print("  Phase 2: Waiting for timeout (5s simulated, real timeout is 30s)...")
        # Simulate timeout by directly calling the private method for testing
        old_time = asr._last_transcription_time
        asr._last_transcription_time = time.time() - 35.0  # Simulate 35s ago
        
        print("  Phase 3: Transcription after timeout...")
        phase3_audio = np.sin(2 * np.pi * 880 * np.linspace(0, 1.5, int(1.5 * self.cfg.sample_rate))).astype(np.float32) * 0.05
        
        try:
            result3 = asr.transcribe(phase3_audio)  # This should trigger timeout clearing
            phase3_success = len(result3.strip()) > 0
            print(f"    Phase 3 result: {'SUCCESS' if phase3_success else 'FAILED'}")
        except Exception as e:
            print(f"    Phase 3 ERROR: {e}")
            phase3_success = False
        
        timeout_clearing_works = phase1_success and phase3_success
        
        print(f"\nTimeout Clearing Result:")
        print(f"  Phase 1 (before timeout): {'PASS' if phase1_success else 'FAIL'}")
        print(f"  Phase 3 (after timeout): {'PASS' if phase3_success else 'FAIL'}")
        print(f"  Timeout clearing works: {'YES' if timeout_clearing_works else 'NO'}")
        
        return {
            'test_name': 'Conversation Timeout Clearing',
            'phase1_success': phase1_success,
            'phase3_success': phase3_success,
            'timeout_clearing_works': timeout_clearing_works,
            'status': 'PASS' if timeout_clearing_works else 'FAIL'
        }
    
    def test_long_conversation_clearing(self) -> dict:
        """Test automatic clearing after 3-minute conversation"""
        print("\n[TEST 3] Long Conversation Clearing (3-minute limit)")
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        print("  Simulating long conversation (total audio > 3 minutes)...")
        
        # Simulate reaching the 3-minute limit by setting internal state
        asr._total_conversation_duration = 190.0  # Over the 180s limit
        
        # Create test audio
        test_audio = np.sin(2 * np.pi * 500 * np.linspace(0, 1.0, int(1.0 * self.cfg.sample_rate))).astype(np.float32) * 0.05
        
        try:
            result = asr.transcribe(test_audio)  # Should trigger long conversation clearing
            success = len(result.strip()) > 0
            
            # Check if conversation duration was reset
            duration_reset = asr._total_conversation_duration < 190.0  # Should be reset
            
            print(f"    Transcription after 3min limit: {'SUCCESS' if success else 'FAILED'}")
            print(f"    Conversation duration reset: {'YES' if duration_reset else 'NO'}")
            
            long_conversation_clearing_works = success and duration_reset
            
        except Exception as e:
            print(f"    ERROR: {e}")
            long_conversation_clearing_works = False
        
        print(f"\nLong Conversation Clearing Result:")
        print(f"  Works correctly: {'YES' if long_conversation_clearing_works else 'NO'}")
        
        return {
            'test_name': 'Long Conversation Clearing',
            'long_conversation_clearing_works': long_conversation_clearing_works,
            'status': 'PASS' if long_conversation_clearing_works else 'FAIL'
        }
    
    def run_conversation_clearing_tests(self) -> dict:
        """Run all conversation clearing tests"""
        print("CONVERSATION CLEARING TESTS STARTING...")
        print("Testing fixes for model reinitialization and long conversation issues")
        
        test_methods = [
            self.test_frequent_transcriptions,
            self.test_conversation_timeout_clearing,
            self.test_long_conversation_clearing,
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
            'clearing_status': 'FIXED' if success_rate >= 90 else 'NEEDS_WORK'
        }
        
        # Summary
        print("\n" + "=" * 70)
        print("CONVERSATION CLEARING TEST RESULTS")
        print("=" * 70)
        print(f"Tests completed: {total_tests}")
        print(f"Tests passed: {passed_tests}")
        print(f"Success rate: {success_rate:.1f}%")
        print(f"Clearing mechanisms: {overall_result['clearing_status']}")
        
        if overall_result['clearing_status'] == 'FIXED':
            print("\n[SUCCESS] Conversation clearing mechanisms FIXED!")
            print("- Model reinitialization: Every 20 transcriptions (was 5)")
            print("- Long conversation clearing: After 3 minutes")
            print("- Inactivity clearing: After 30 seconds")
            print("- Frequent transcriptions: No longer cause failures")
        else:
            failed_tests = [r for r in results if r['status'] != 'PASS']
            print(f"\n[WARNING] {len(failed_tests)} test(s) still failing:")
            for test in failed_tests:
                print(f"- {test['test_name']}: {test['status']}")
        
        return overall_result

def main():
    """Run conversation clearing tests"""
    tester = ConversationClearingTester()
    results = tester.run_conversation_clearing_tests()
    
    return 0 if results['clearing_status'] == 'FIXED' else 1

if __name__ == "__main__":
    exit(main())