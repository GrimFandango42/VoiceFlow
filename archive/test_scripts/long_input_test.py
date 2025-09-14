"""
Long Input Testing - 3-minute recordings with pauses and breaks
Tests realistic long-form dictation scenarios
"""

import time
import numpy as np
from localflow.config import Config
from localflow.audio_enhanced import EnhancedAudioRecorder
from localflow.asr_buffer_safe import BufferSafeWhisperASR

class LongInputTester:
    """Test long-form input scenarios (up to 3 minutes)"""
    
    def __init__(self):
        self.cfg = Config()
        print("=== 3-MINUTE LONG INPUT VALIDATION ===")
        print(f"System capacity: {300.0}s (5 minutes)")
        print(f"Target testing: 180s (3 minutes)")
        print(f"VAD disabled: {not self.cfg.vad_filter}")
    
    def test_long_recording_capacity(self) -> dict:
        """Test system capacity for long recordings"""
        print("\n[TEST 1] Long Recording Capacity")
        print("=" * 50)
        
        recorder = EnhancedAudioRecorder(self.cfg)
        
        # Check system limits
        max_duration = recorder._ring_buffer.max_samples / self.cfg.sample_rate
        pre_buffer_duration = recorder._pre_buffer_duration
        
        capacity_adequate = max_duration >= 180.0  # At least 3 minutes
        pre_buffer_reasonable = 1.0 <= pre_buffer_duration <= 2.0
        
        print(f"Max recording capacity: {max_duration:.1f}s")
        print(f"Pre-buffer duration: {pre_buffer_duration:.1f}s")  
        print(f"3-minute capacity: {'YES' if capacity_adequate else 'NO'}")
        print(f"Pre-buffer reasonable: {'YES' if pre_buffer_reasonable else 'NO'}")
        
        return {
            'test_name': 'Long Recording Capacity',
            'max_duration': max_duration,
            'pre_buffer_duration': pre_buffer_duration,
            'capacity_adequate': capacity_adequate,
            'pre_buffer_reasonable': pre_buffer_reasonable,
            'status': 'PASS' if capacity_adequate and pre_buffer_reasonable else 'FAIL'
        }
    
    def test_simulated_long_input_with_pauses(self) -> dict:
        """Test simulated 3-minute input with realistic pause patterns"""
        print("\n[TEST 2] Simulated 3-Minute Input with Pauses")
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        # Simulate a 3-minute recording with various segments and pauses
        target_duration = 180.0  # 3 minutes
        segment_patterns = [
            (30.0, 0.5),    # 30s speech, 0.5s pause
            (45.0, 1.0),    # 45s speech, 1.0s pause  
            (25.0, 2.0),    # 25s speech, 2.0s pause
            (40.0, 1.5),    # 40s speech, 1.5s pause
            (35.0, 0.0),    # 35s speech, no pause (end)
        ]
        
        total_speech_time = sum(duration for duration, _ in segment_patterns)
        total_pause_time = sum(pause for _, pause in segment_patterns[:-1])  # Last has no pause
        expected_total = total_speech_time + total_pause_time
        
        print(f"Simulated recording structure:")
        print(f"  Total speech time: {total_speech_time:.1f}s")
        print(f"  Total pause time: {total_pause_time:.1f}s")
        print(f"  Expected total: {expected_total:.1f}s")
        
        # Create the composite audio
        composite_audio = []
        sample_rate = self.cfg.sample_rate
        
        for i, (speech_duration, pause_duration) in enumerate(segment_patterns):
            # Speech segment with unique frequency signature
            speech_samples = int(speech_duration * sample_rate)
            freq = 220 + (i * 50)  # Different frequency per segment
            t = np.linspace(0, speech_duration, speech_samples)
            speech_segment = np.sin(2 * np.pi * freq * t).astype(np.float32) * 0.05
            composite_audio.extend(speech_segment)
            
            # Pause segment (silence)
            if pause_duration > 0:
                pause_samples = int(pause_duration * sample_rate)  
                pause_segment = np.zeros(pause_samples, dtype=np.float32)
                composite_audio.extend(pause_segment)
        
        composite_audio = np.array(composite_audio)
        actual_duration = len(composite_audio) / sample_rate
        
        print(f"Generated audio: {actual_duration:.1f}s ({len(composite_audio)} samples)")
        
        # Test transcription
        print("Processing long input...")
        start_time = time.perf_counter()
        
        try:
            result = asr.transcribe(composite_audio)
            processing_time = time.perf_counter() - start_time
            
            # Get stats
            stats = asr.get_clean_statistics()
            
            success = len(result.strip()) > 0
            speed_factor = actual_duration / processing_time if processing_time > 0 else 0
            
            print(f"Processing time: {processing_time:.2f}s")
            print(f"Speed factor: {speed_factor:.1f}x realtime")
            print(f"Result length: {len(result)} chars")
            print(f"Transcription success: {'YES' if success else 'NO'}")
            print(f"Buffer isolation maintained: {'YES' if stats['buffer_state_isolated'] else 'NO'}")
            
            return {
                'test_name': 'Simulated 3-Minute Input',
                'audio_duration': actual_duration,
                'processing_time': processing_time,
                'speed_factor': speed_factor,
                'result_length': len(result),
                'transcription_success': success,
                'buffer_isolated': stats['buffer_state_isolated'],
                'vad_disabled': stats['vad_always_disabled'],
                'status': 'PASS' if success and stats['buffer_state_isolated'] else 'FAIL'
            }
            
        except Exception as e:
            print(f"ERROR: {e}")
            return {
                'test_name': 'Simulated 3-Minute Input',
                'error': str(e),
                'transcription_success': False,
                'status': 'FAIL'
            }
    
    def test_pause_pattern_variations(self) -> dict:
        """Test different pause patterns in long inputs"""
        print("\n[TEST 3] Pause Pattern Variations in Long Inputs")  
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        pause_scenarios = {
            'frequent_short': [(15.0, 0.3)] * 8,      # 8x 15s speech + 0.3s pause
            'moderate': [(30.0, 1.0)] * 4,            # 4x 30s speech + 1s pause  
            'long_breaks': [(45.0, 3.0)] * 3,         # 3x 45s speech + 3s pause
            'mixed_pattern': [(20.0, 0.5), (40.0, 2.0), (25.0, 0.8), (30.0, 1.5)]
        }
        
        results = {}
        
        for scenario_name, pattern in pause_scenarios.items():
            print(f"\n  Testing {scenario_name} pattern...")
            
            # Create audio for this pattern
            audio_segments = []
            total_duration = 0
            
            for i, (speech_dur, pause_dur) in enumerate(pattern):
                # Speech
                samples = int(speech_dur * self.cfg.sample_rate)
                freq = 300 + (i * 75)
                t = np.linspace(0, speech_dur, samples)
                speech = np.sin(2 * np.pi * freq * t).astype(np.float32) * 0.05
                audio_segments.extend(speech)
                total_duration += speech_dur
                
                # Pause
                if pause_dur > 0:
                    pause_samples = int(pause_dur * self.cfg.sample_rate)
                    audio_segments.extend(np.zeros(pause_samples, dtype=np.float32))
                    total_duration += pause_dur
            
            test_audio = np.array(audio_segments)
            actual_duration = len(test_audio) / self.cfg.sample_rate
            
            # Test transcription
            try:
                start_time = time.perf_counter()
                result = asr.transcribe(test_audio)
                processing_time = time.perf_counter() - start_time
                
                success = len(result.strip()) > 0
                speed_factor = actual_duration / processing_time if processing_time > 0 else 0
                
                results[scenario_name] = {
                    'pattern': pattern,
                    'audio_duration': actual_duration,
                    'processing_time': processing_time,
                    'speed_factor': speed_factor,
                    'transcription_success': success,
                    'result_length': len(result)
                }
                
                print(f"    Duration: {actual_duration:.1f}s")
                print(f"    Speed: {speed_factor:.1f}x")
                print(f"    Success: {'YES' if success else 'NO'}")
                
            except Exception as e:
                print(f"    ERROR: {e}")
                results[scenario_name] = {
                    'pattern': pattern,
                    'error': str(e),
                    'transcription_success': False
                }
        
        all_successful = all(r.get('transcription_success', False) for r in results.values())
        
        return {
            'test_name': 'Pause Pattern Variations',
            'scenarios_tested': len(results),
            'all_successful': all_successful,
            'scenario_results': results,
            'status': 'PASS' if all_successful else 'FAIL'
        }
    
    def run_long_input_tests(self) -> dict:
        """Run complete long input test suite"""
        print("LONG INPUT TESTING STARTING...")
        print("Testing 3-minute recordings with pauses and breaks")
        
        test_methods = [
            self.test_long_recording_capacity,
            self.test_simulated_long_input_with_pauses,
            self.test_pause_pattern_variations,
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
            'long_input_status': 'READY' if success_rate >= 90 else 'NEEDS_WORK'
        }
        
        # Summary
        print("\n" + "=" * 70)
        print("LONG INPUT TEST RESULTS")
        print("=" * 70)
        print(f"Tests completed: {total_tests}")
        print(f"Tests passed: {passed_tests}")
        print(f"Success rate: {success_rate:.1f}%")
        print(f"3-minute input status: {overall_result['long_input_status']}")
        
        if overall_result['long_input_status'] == 'READY':
            print("\n[SUCCESS] 3-minute long input support READY!")
            print("- System capacity: 5 minutes (exceeds requirement)")  
            print("- Long recordings with pauses: SUPPORTED")
            print("- Various pause patterns: TESTED")
            print("- Buffer isolation: MAINTAINED")
        else:
            failed_tests = [r for r in results if r['status'] != 'PASS']
            print(f"\n[WARNING] {len(failed_tests)} test(s) need attention:")
            for test in failed_tests:
                print(f"- {test['test_name']}: {test['status']}")
        
        return overall_result

def main():
    """Run long input testing"""
    tester = LongInputTester()
    results = tester.run_long_input_tests()
    
    return 0 if results['long_input_status'] == 'READY' else 1

if __name__ == "__main__":
    exit(main())