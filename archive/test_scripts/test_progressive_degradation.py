#!/usr/bin/env python3
"""
Comprehensive test for VoiceFlow progressive transcription degradation.

This test reproduces the exact issue reported:
- Recording 1: Full transcription
- Recording 2: Shorter transcription (fewer words despite longer/equal audio)  
- Recording 3: Even shorter transcription
- Pattern: Progressive reduction in transcribed content over time
"""

import sys
import os
import time
import numpy as np
from typing import List, Dict, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from localflow.config import Config
from localflow.asr_buffer_safe import BufferSafeWhisperASR
from localflow.audio_enhanced import BoundedRingBuffer


class ProgressiveDegradationTester:
    """Test suite to identify progressive transcription degradation patterns"""
    
    def __init__(self):
        self.config = Config()
        self.asr = BufferSafeWhisperASR(self.config)
        self.test_results: List[Dict[str, Any]] = []
    
    def generate_test_audio(self, duration_seconds: float, frequency: float = 440.0) -> np.ndarray:
        """Generate consistent test audio of specified duration"""
        sample_rate = 16000
        samples = int(duration_seconds * sample_rate)
        t = np.linspace(0, duration_seconds, samples, False)
        
        # Generate a more complex waveform that simulates speech patterns
        audio = (
            np.sin(2 * np.pi * frequency * t) * 0.3 +          # Base tone
            np.sin(2 * np.pi * frequency * 2.1 * t) * 0.2 +    # Harmonic
            np.sin(2 * np.pi * frequency * 0.5 * t) * 0.1 +    # Sub-harmonic
            np.random.normal(0, 0.05, samples)                  # Background noise
        )
        
        # Add amplitude modulation to simulate speech patterns
        envelope = 0.5 + 0.5 * np.sin(2 * np.pi * 2 * t)  # 2 Hz modulation
        audio = audio * envelope
        
        return audio.astype(np.float32)
    
    def create_speech_like_audio(self, word_count: int, base_duration: float = 1.0) -> np.ndarray:
        """Create more realistic speech-like audio patterns"""
        # Estimate duration based on average speaking rate (150 words/minute)
        duration = max(base_duration, word_count * 60.0 / 150.0)
        sample_rate = 16000
        samples = int(duration * sample_rate)
        
        audio = np.zeros(samples, dtype=np.float32)
        
        # Create word-like segments with pauses
        word_duration = 0.4  # Average word duration in seconds
        pause_duration = 0.1  # Pause between words
        
        current_pos = 0
        for word_idx in range(word_count):
            if current_pos >= samples:
                break
                
            # Generate word-like segment
            word_samples = int(word_duration * sample_rate)
            end_pos = min(current_pos + word_samples, samples)
            
            # Create formant-like frequencies for speech simulation
            t = np.linspace(0, word_duration, end_pos - current_pos, False)
            
            # Multiple formants typical of human speech
            word_audio = (
                np.sin(2 * np.pi * 200 * t) * 0.3 +   # F0 (fundamental)
                np.sin(2 * np.pi * 800 * t) * 0.2 +   # F1 (first formant)  
                np.sin(2 * np.pi * 1200 * t) * 0.1 +  # F2 (second formant)
                np.random.normal(0, 0.02, len(t))      # Noise
            )
            
            # Apply envelope to make it more speech-like
            envelope = np.exp(-3 * (t - word_duration/2)**2 / (word_duration/2)**2)
            word_audio *= envelope
            
            audio[current_pos:end_pos] = word_audio
            current_pos = end_pos + int(pause_duration * sample_rate)
        
        # Normalize
        if np.max(np.abs(audio)) > 0:
            audio = audio / np.max(np.abs(audio)) * 0.8
            
        return audio
    
    def test_consecutive_recordings(self, num_recordings: int = 10) -> List[Dict[str, Any]]:
        """Test multiple consecutive recordings to identify progressive degradation"""
        
        print(f"Testing {num_recordings} consecutive recordings...")
        print("=" * 60)
        
        results = []
        
        # Test recordings of increasing length to match user report
        base_word_counts = [10, 15, 12, 18, 14, 16, 20, 13, 17, 15]  # Variable lengths
        
        for recording_idx in range(num_recordings):
            word_count = base_word_counts[recording_idx % len(base_word_counts)]
            
            print(f"\n--- Recording {recording_idx + 1} ---")
            print(f"Target words: {word_count}")
            
            # Generate audio with expected word count
            audio = self.create_speech_like_audio(word_count, base_duration=2.0)
            audio_duration = len(audio) / 16000.0
            
            print(f"Audio duration: {audio_duration:.2f}s")
            print(f"Audio samples: {len(audio)}")
            
            # Transcribe
            start_time = time.perf_counter()
            transcription = self.asr.transcribe(audio)
            processing_time = time.perf_counter() - start_time
            
            # Analyze result
            transcribed_words = len(transcription.split()) if transcription.strip() else 0
            characters = len(transcription)
            
            result = {
                'recording_number': recording_idx + 1,
                'target_words': word_count,
                'audio_duration_seconds': audio_duration,
                'audio_samples': len(audio),
                'transcription': transcription,
                'transcribed_words': transcribed_words,
                'transcribed_characters': characters,
                'processing_time_seconds': processing_time,
                'speed_factor': audio_duration / processing_time if processing_time > 0 else 0,
                'words_per_second_audio': word_count / audio_duration,
                'words_per_second_transcription': transcribed_words / audio_duration if audio_duration > 0 else 0,
                'transcription_efficiency': transcribed_words / word_count if word_count > 0 else 0,
            }
            
            results.append(result)
            
            # Print detailed results
            print(f"Transcription: '{transcription}'")
            print(f"Words transcribed: {transcribed_words}")
            print(f"Characters: {characters}")
            print(f"Processing time: {processing_time:.2f}s")
            print(f"Speed factor: {result['speed_factor']:.1f}x realtime")
            print(f"Efficiency: {result['transcription_efficiency']:.1%} (transcribed/target words)")
            
            # Look for degradation pattern
            if recording_idx > 0:
                prev_result = results[recording_idx - 1]
                word_change = transcribed_words - prev_result['transcribed_words']
                efficiency_change = result['transcription_efficiency'] - prev_result['transcription_efficiency']
                
                print(f"Change from previous: {word_change:+d} words ({efficiency_change:+.1%} efficiency)")
                
                if transcribed_words < prev_result['transcribed_words']:
                    print("⚠️  DEGRADATION DETECTED: Fewer words transcribed than previous recording")
                elif efficiency_change < -0.1:
                    print("⚠️  EFFICIENCY DEGRADATION: Transcription efficiency decreased significantly")
        
        return results
    
    def analyze_degradation_pattern(self, results: List[Dict[str, Any]]):
        """Analyze results for progressive degradation patterns"""
        
        print("\n" + "=" * 60)
        print("DEGRADATION PATTERN ANALYSIS")
        print("=" * 60)
        
        if len(results) < 3:
            print("Insufficient data for pattern analysis")
            return
        
        # Look for progressive decline in transcribed words
        word_counts = [r['transcribed_words'] for r in results]
        efficiencies = [r['transcription_efficiency'] for r in results]
        processing_times = [r['processing_time_seconds'] for r in results]
        
        print(f"Word counts: {word_counts}")
        print(f"Efficiencies: {[f'{e:.1%}' for e in efficiencies]}")
        print(f"Processing times: {[f'{t:.2f}s' for t in processing_times]}")
        
        # Check for consistent decline
        declining_words = 0
        declining_efficiency = 0
        increasing_time = 0
        
        for i in range(1, len(results)):
            if word_counts[i] < word_counts[i-1]:
                declining_words += 1
            if efficiencies[i] < efficiencies[i-1]:
                declining_efficiency += 1
            if processing_times[i] > processing_times[i-1]:
                increasing_time += 1
        
        total_comparisons = len(results) - 1
        
        print(f"\nDegradation Metrics:")
        print(f"- Declining word counts: {declining_words}/{total_comparisons} ({declining_words/total_comparisons:.1%})")
        print(f"- Declining efficiency: {declining_efficiency}/{total_comparisons} ({declining_efficiency/total_comparisons:.1%})")
        print(f"- Increasing processing time: {increasing_time}/{total_comparisons} ({increasing_time/total_comparisons:.1%})")
        
        # Determine if progressive degradation is occurring
        degradation_threshold = 0.4  # 40% of recordings show decline
        
        is_degrading = (
            declining_words / total_comparisons > degradation_threshold or
            declining_efficiency / total_comparisons > degradation_threshold
        )
        
        if is_degrading:
            print("\n🚨 PROGRESSIVE DEGRADATION CONFIRMED")
            print("The system shows consistent decline in transcription quality over consecutive recordings.")
            
            # Identify potential causes
            if increasing_time / total_comparisons > 0.5:
                print("- CAUSE: Processing time is increasing (memory/performance degradation)")
            
            # Check ASR model state
            asr_stats = self.asr.get_clean_statistics()
            print(f"- ASR session stats: {asr_stats}")
            
        else:
            print("\n✅ NO PROGRESSIVE DEGRADATION DETECTED")
            print("Transcription quality remains consistent across recordings.")
    
    def test_model_state_isolation(self):
        """Test if Whisper model maintains internal state between calls"""
        
        print("\n" + "=" * 60)
        print("WHISPER MODEL STATE ISOLATION TEST")
        print("=" * 60)
        
        # Create identical audio
        audio = self.create_speech_like_audio(10, 2.0)
        
        results = []
        
        for i in range(5):
            print(f"\nIdentical audio test {i+1}/5")
            
            start_time = time.perf_counter()
            transcription = self.asr.transcribe(audio)
            processing_time = time.perf_counter() - start_time
            
            result = {
                'test_number': i + 1,
                'transcription': transcription,
                'word_count': len(transcription.split()),
                'character_count': len(transcription),
                'processing_time': processing_time
            }
            results.append(result)
            
            print(f"Transcription: '{transcription}'")
            print(f"Words: {result['word_count']}, Characters: {result['character_count']}")
            print(f"Processing time: {processing_time:.2f}s")
        
        # Check consistency
        base_transcription = results[0]['transcription']
        base_word_count = results[0]['word_count']
        
        identical_results = sum(1 for r in results if r['transcription'] == base_transcription)
        consistent_word_counts = sum(1 for r in results if r['word_count'] == base_word_count)
        
        print(f"\nConsistency Analysis:")
        print(f"- Identical transcriptions: {identical_results}/5")
        print(f"- Consistent word counts: {consistent_word_counts}/5")
        
        if identical_results == 5:
            print("✅ Perfect model isolation - identical audio produces identical results")
        elif consistent_word_counts >= 4:
            print("✅ Good model isolation - word counts consistent")
        else:
            print("⚠️  Model isolation issue - same audio produces different results")
            print("This suggests internal state persistence in Whisper model")


def main():
    """Run comprehensive progressive degradation tests"""
    
    print("VoiceFlow Progressive Degradation Diagnostic Test")
    print("=" * 60)
    print("This test reproduces the user-reported issue:")
    print("• First recording: Good transcription")  
    print("• Subsequent recordings: Progressively shorter transcriptions")
    print("• Audio length stays same or increases, but transcribed text decreases")
    print("=" * 60)
    
    tester = ProgressiveDegradationTester()
    
    try:
        # Load the ASR model
        print("Loading Whisper model...")
        tester.asr.load()
        print("Model loaded successfully.")
        
        # Test 1: Consecutive recordings with variable lengths
        print("\n🔍 TEST 1: Consecutive Recordings (10 recordings)")
        results = tester.test_consecutive_recordings(10)
        tester.analyze_degradation_pattern(results)
        
        # Test 2: Model state isolation
        print("\n🔍 TEST 2: Model State Isolation")
        tester.test_model_state_isolation()
        
        # Test 3: Memory and performance over time
        print("\n🔍 TEST 3: Extended Session Test (20 recordings)")
        extended_results = tester.test_consecutive_recordings(20)
        tester.analyze_degradation_pattern(extended_results)
        
        print("\n" + "=" * 60)
        print("TEST COMPLETE")
        print("=" * 60)
        print("Review the output above to identify:")
        print("1. Whether progressive degradation is occurring")
        print("2. Patterns in word count decline")
        print("3. Processing time changes")
        print("4. Model state isolation issues")
        
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())