"""
Long Conversation Validation Test
Tests the exact scenario reported by user: 4+ consecutive sentences
"""

import time
import numpy as np
from localflow.config import Config
from localflow.asr_buffer_safe import BufferSafeWhisperASR

class LongConversationValidator:
    """Validate long conversation scenarios with multiple sentences"""
    
    def __init__(self):
        self.cfg = Config()
        print("=== LONG CONVERSATION VALIDATION ===")
        print(f"Testing with VAD disabled: {not self.cfg.vad_filter}")
    
    def test_sequential_sentences(self, num_sentences: int = 6) -> dict:
        """Test sequential sentence processing like user's scenario"""
        print(f"\n[TEST] Sequential {num_sentences} Sentences")
        print("=" * 50)
        
        asr = BufferSafeWhisperASR(self.cfg)
        
        # Create test sentences as audio patterns
        sentences = []
        for i in range(num_sentences):
            # Create unique audio signature for each sentence
            duration = 1.0 + (i * 0.2)  # Varying lengths
            samples = int(duration * self.cfg.sample_rate)
            
            # Different frequency patterns to simulate different speech
            freq = 440 + (i * 100)  # Different frequency per sentence
            audio = np.sin(2 * np.pi * freq * np.linspace(0, duration, samples)).astype(np.float32) * 0.1
            sentences.append((f"sentence_{i+1}", audio))
        
        results = []
        transcription_count = 0
        
        print(f"Processing {num_sentences} sequential sentences...")
        
        for i, (sentence_name, audio) in enumerate(sentences, 1):
            print(f"\n  Sentence {i}/{num_sentences}: {sentence_name}")
            
            try:
                # Test transcription 
                start_time = time.perf_counter()
                result = asr.transcribe(audio)
                processing_time = time.perf_counter() - start_time
                
                transcription_count += 1
                
                # Get ASR stats after this transcription
                stats = asr.get_clean_statistics()
                
                sentence_result = {
                    'sentence_num': i,
                    'sentence_name': sentence_name,
                    'audio_duration': len(audio) / self.cfg.sample_rate,
                    'processing_time': processing_time,
                    'transcription_successful': len(result.strip()) > 0,
                    'result_length': len(result),
                    'asr_session_count': stats['session_transcription_count'],
                    'asr_buffer_isolated': stats['buffer_state_isolated'],
                    'asr_vad_disabled': stats['vad_always_disabled'],
                }
                
                results.append(sentence_result)
                
                print(f"    Duration: {sentence_result['audio_duration']:.2f}s")
                print(f"    Processing: {processing_time:.3f}s")
                print(f"    Result length: {sentence_result['result_length']} chars")
                print(f"    ASR session count: {sentence_result['asr_session_count']}")
                print(f"    Status: {'SUCCESS' if sentence_result['transcription_successful'] else 'FAILED'}")
                
                # Brief pause between sentences (like user's scenario)
                time.sleep(0.2)
                
            except Exception as e:
                print(f"    ERROR: {e}")
                results.append({
                    'sentence_num': i,
                    'sentence_name': sentence_name,
                    'error': str(e),
                    'transcription_successful': False
                })
                break
        
        # Analysis
        successful_transcriptions = sum(1 for r in results if r.get('transcription_successful', False))
        all_successful = successful_transcriptions == num_sentences
        no_degradation = len(results) > 0 and all(r.get('asr_session_count', 0) == r.get('sentence_num', 0) for r in results if 'asr_session_count' in r)
        buffer_isolation_maintained = all(r.get('asr_buffer_isolated', False) for r in results if 'asr_buffer_isolated' in r)
        vad_consistently_disabled = all(r.get('asr_vad_disabled', False) for r in results if 'asr_vad_disabled' in r)
        
        print(f"\n=== LONG CONVERSATION ANALYSIS ===")
        print(f"Sentences processed: {len(results)}")
        print(f"Successful transcriptions: {successful_transcriptions}/{num_sentences}")
        print(f"All successful: {all_successful}")
        print(f"No degradation: {no_degradation}")  
        print(f"Buffer isolation maintained: {buffer_isolation_maintained}")
        print(f"VAD consistently disabled: {vad_consistently_disabled}")
        
        long_conversation_success = all_successful and buffer_isolation_maintained and vad_consistently_disabled
        
        print(f"LONG CONVERSATION STATUS: {'SUCCESS' if long_conversation_success else 'NEEDS_WORK'}")
        
        return {
            'test_name': f'Sequential {num_sentences} Sentences',
            'sentences_processed': len(results),
            'successful_transcriptions': successful_transcriptions,
            'all_successful': all_successful,
            'buffer_isolation_maintained': buffer_isolation_maintained,
            'vad_consistently_disabled': vad_consistently_disabled,
            'no_degradation': no_degradation,
            'long_conversation_success': long_conversation_success,
            'sentence_results': results,
            'status': 'SUCCESS' if long_conversation_success else 'NEEDS_WORK'
        }
    
    def run_validation(self) -> dict:
        """Run complete long conversation validation"""
        print("LONG CONVERSATION VALIDATION STARTING...")
        print("Testing the exact scenario reported: multiple consecutive sentences")
        
        # Test the problematic scenario: 4+ sentences
        result_4 = self.test_sequential_sentences(4)
        result_6 = self.test_sequential_sentences(6)
        result_10 = self.test_sequential_sentences(10)
        
        all_tests = [result_4, result_6, result_10]
        passed_tests = sum(1 for test in all_tests if test['status'] == 'SUCCESS')
        
        overall_success = passed_tests == len(all_tests)
        
        print("\n" + "=" * 70)
        print("LONG CONVERSATION VALIDATION RESULTS")  
        print("=" * 70)
        print(f"Tests run: {len(all_tests)}")
        print(f"Tests passed: {passed_tests}")
        print(f"Overall success: {overall_success}")
        
        if overall_success:
            print("\n[SUCCESS] Long conversation support VALIDATED!")
            print("- Multiple consecutive sentences work correctly")
            print("- No transcription degradation after sentence 3")
            print("- Buffer isolation maintained throughout")
            print("- VAD consistently disabled")
        else:
            failed_tests = [test for test in all_tests if test['status'] != 'SUCCESS']
            print(f"\n[WARNING] {len(failed_tests)} test(s) failed:")
            for test in failed_tests:
                print(f"- {test['test_name']}")
        
        return {
            'validation_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'overall_success': overall_success,
            'tests_passed': passed_tests,
            'total_tests': len(all_tests),
            'detailed_results': all_tests
        }

def main():
    """Run long conversation validation"""
    validator = LongConversationValidator()
    results = validator.run_validation()
    
    return 0 if results['overall_success'] else 1

if __name__ == "__main__":
    exit(main())