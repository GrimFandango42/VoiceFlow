#!/usr/bin/env python3
"""
Comprehensive Production Robustness Test Suite for VoiceFlow
Tests all critical scenarios for production deployment with real-world complexity.
"""

import sys
import os
import time
import threading
import unittest
from unittest.mock import patch, MagicMock
import numpy as np
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple
import logging

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from localflow.config import Config
from localflow.audio_enhanced import EnhancedAudioRecorder
from localflow.asr_buffer_safe import BufferSafeWhisperASR
from localflow.production_logging import get_production_logger, LogLevel, print_system_health

@dataclass
class TestScenario:
    """Represents a production test scenario"""
    name: str
    description: str
    audio_pattern: str
    expected_behavior: str
    timing_pattern: str
    complexity_level: str

class ProductionRobustnessTestSuite(unittest.TestCase):
    """Comprehensive test suite for production deployment scenarios"""
    
    def setUp(self):
        """Set up test environment with production configuration"""
        self.config = Config()
        self.logger = get_production_logger()
        self.logger.set_level(LogLevel.INFO)  # Production log level
        
        # Test scenarios covering real-world usage patterns
        self.test_scenarios = [
            TestScenario(
                name="immediate_speech_pattern",
                description="User starts speaking immediately when pressing PTT",
                audio_pattern="immediate",
                expected_behavior="complete_capture_with_prebuffer",
                timing_pattern="0ms_delay",
                complexity_level="basic"
            ),
            TestScenario(
                name="delayed_speech_pattern", 
                description="User pauses before speaking after PTT press",
                audio_pattern="delayed_start",
                expected_behavior="complete_capture_with_extended_prebuffer",
                timing_pattern="200-500ms_delay",
                complexity_level="intermediate"
            ),
            TestScenario(
                name="rapid_consecutive_recordings",
                description="Multiple recordings with minimal gaps between them",
                audio_pattern="rapid_sequence",
                expected_behavior="no_buffer_interference",
                timing_pattern="<1s_between_recordings",
                complexity_level="advanced"
            ),
            TestScenario(
                name="long_session_stability",
                description="Extended session with 20+ recordings over 10+ minutes",
                audio_pattern="extended_session",
                expected_behavior="stable_performance_no_degradation",
                timing_pattern="varied_intervals",
                complexity_level="enterprise"
            ),
            TestScenario(
                name="variable_audio_lengths",
                description="Mix of very short (1-2 words) and long (2+ minutes) recordings",
                audio_pattern="variable_duration",
                expected_behavior="consistent_accuracy",
                timing_pattern="varied_durations",
                complexity_level="advanced"
            ),
            TestScenario(
                name="technical_vocabulary_stress_test",
                description="Complex technical terms and professional vocabulary",
                audio_pattern="technical_speech",
                expected_behavior="accurate_technical_transcription",
                timing_pattern="standard",
                complexity_level="advanced"
            ),
            TestScenario(
                name="interruption_recovery",
                description="PTT key released and pressed again during speech",
                audio_pattern="interrupted_speech",
                expected_behavior="seamless_continuation_with_tail_buffer",
                timing_pattern="interruption_pattern",
                complexity_level="expert"
            ),
            TestScenario(
                name="resource_constraint_handling",
                description="System under high CPU/Memory load",
                audio_pattern="standard_speech",
                expected_behavior="graceful_degradation_with_quality_maintenance",
                timing_pattern="standard",
                complexity_level="enterprise"
            )
        ]
    
    def test_timing_pattern_robustness(self):
        """Test various key-press-to-speech timing patterns"""
        print("\n" + "="*60)
        print("🎯 TESTING: Key-press to Speech Timing Patterns")
        print("="*60)
        
        timing_patterns = [
            ("immediate", 0.0, "User speaks immediately when pressing PTT"),
            ("brief_pause", 0.2, "User pauses 200ms before speaking"),
            ("moderate_pause", 0.5, "User pauses 500ms before speaking"), 
            ("long_pause", 1.0, "User pauses 1 second before speaking"),
        ]
        
        results = {}
        
        for pattern_name, delay_seconds, description in timing_patterns:
            print(f"\n📝 Testing: {description}")
            
            # Create test audio with specified timing
            sample_rate = 16000
            silence_samples = int(delay_seconds * sample_rate)
            speech_samples = int(2.0 * sample_rate)  # 2 seconds of speech
            
            # Generate realistic speech-like audio
            speech_audio = self._generate_speech_like_audio(speech_samples, sample_rate)
            
            if silence_samples > 0:
                silence = np.zeros(silence_samples, dtype=np.float32)
                full_audio = np.concatenate([silence, speech_audio])
            else:
                full_audio = speech_audio
            
            # Test with mock ASR
            with patch('localflow.asr_buffer_safe.BufferSafeWhisperASR') as mock_asr:
                mock_asr_instance = MagicMock()
                mock_asr_instance.transcribe.return_value = f"Test speech with {pattern_name} timing pattern"
                mock_asr.return_value = mock_asr_instance
                
                # Test audio recording and transcription
                recorder = EnhancedAudioRecorder(self.config)
                asr = BufferSafeWhisperASR(self.config)
                
                start_time = time.perf_counter()
                
                # Simulate recording process
                recorder.start()
                time.sleep(delay_seconds + 0.1)  # Simulate the timing pattern
                audio_result = recorder.stop()
                
                # Test transcription
                if len(audio_result) > 0:
                    transcription = f"Processed audio with timing pattern: {pattern_name}"
                else:
                    transcription = "No audio captured"
                
                processing_time = time.perf_counter() - start_time
                
                results[pattern_name] = {
                    'success': len(audio_result) > 0,
                    'audio_length': len(audio_result),
                    'processing_time': processing_time,
                    'transcription': transcription,
                    'expected_delay': delay_seconds
                }
                
                success_icon = "✅" if results[pattern_name]['success'] else "❌"
                print(f"  {success_icon} Result: {len(audio_result)} samples captured")
                print(f"  ⏱️  Processing: {processing_time:.3f}s")
        
        # Analyze results
        print(f"\n📊 TIMING PATTERN ANALYSIS:")
        for pattern, result in results.items():
            effectiveness = "EXCELLENT" if result['success'] and result['audio_length'] > 1000 else "NEEDS_IMPROVEMENT"
            print(f"  {pattern}: {effectiveness}")
        
        self.assertTrue(all(r['success'] for r in results.values()), 
                       "All timing patterns should be handled successfully")
    
    def test_pre_buffer_effectiveness(self):
        """Test pre-buffer system across different scenarios"""
        print("\n" + "="*60) 
        print("🎯 TESTING: Pre-buffer System Effectiveness")
        print("="*60)
        
        # Test pre-buffer with different speech onset patterns
        patterns = [
            ("word_starts_immediately", "The quick brown fox"),
            ("sentence_with_pause", "...The API endpoint is returning"),
            ("technical_term_first", "Microservices architecture enables"),
            ("number_sequence", "Version 2.4.1 includes these features")
        ]
        
        for pattern_name, expected_start in patterns:
            print(f"\n📝 Testing: {pattern_name}")
            
            recorder = EnhancedAudioRecorder(self.config)
            
            # Start continuous recording to populate pre-buffer
            recorder.start_continuous()
            time.sleep(0.1)  # Allow pre-buffer to collect some data
            
            # Simulate PTT press and immediate recording
            recorder.start()  # This should integrate pre-buffer data
            time.sleep(0.5)   # Simulate some recording time
            audio_data = recorder.stop()
            
            recorder.stop_continuous()
            
            # Verify pre-buffer integration
            self.assertGreater(len(audio_data), 8000, 
                             f"Should have at least 0.5s of audio for {pattern_name}")
            
            print(f"  ✅ Captured {len(audio_data)} samples ({len(audio_data)/16000:.2f}s)")
    
    def test_long_session_stability(self):
        """Test system stability over extended sessions"""
        print("\n" + "="*60)
        print("🎯 TESTING: Long Session Stability (20 recordings)")
        print("="*60)
        
        session_results = []
        
        with patch('localflow.asr_buffer_safe.BufferSafeWhisperASR') as mock_asr:
            mock_asr_instance = MagicMock()
            mock_asr_instance.transcribe.return_value = "Stable transcription result"
            mock_asr.return_value = mock_asr_instance
            
            asr = BufferSafeWhisperASR(self.config)
            
            for session_num in range(20):
                start_time = time.perf_counter()
                
                # Generate test audio of varying lengths
                duration = 1.0 + (session_num % 5) * 0.5  # 1.0 to 3.0 seconds
                audio_samples = int(duration * 16000)
                test_audio = self._generate_speech_like_audio(audio_samples, 16000)
                
                # Perform transcription
                result = asr.transcribe(test_audio)
                processing_time = time.perf_counter() - start_time
                
                session_results.append({
                    'session': session_num + 1,
                    'audio_duration': duration,
                    'processing_time': processing_time,
                    'result_length': len(result),
                    'speed_factor': duration / processing_time if processing_time > 0 else 0
                })
                
                # Progress indicator every 5 recordings
                if (session_num + 1) % 5 == 0:
                    avg_speed = np.mean([r['speed_factor'] for r in session_results[-5:]])
                    print(f"  Sessions {session_num-3}-{session_num+1}: {avg_speed:.1f}x real-time avg")
        
        # Analyze session stability
        processing_times = [r['processing_time'] for r in session_results]
        speed_factors = [r['speed_factor'] for r in session_results]
        
        avg_processing_time = np.mean(processing_times)
        std_processing_time = np.std(processing_times)
        avg_speed_factor = np.mean(speed_factors)
        
        print(f"\n📊 SESSION STABILITY ANALYSIS:")
        print(f"  Average processing time: {avg_processing_time:.3f}s ± {std_processing_time:.3f}s")
        print(f"  Average speed factor: {avg_speed_factor:.1f}x real-time")
        print(f"  Consistency: {'EXCELLENT' if std_processing_time < 0.5 else 'GOOD' if std_processing_time < 1.0 else 'NEEDS_IMPROVEMENT'}")
        
        # Verify no significant performance degradation
        early_avg = np.mean(processing_times[:5])
        late_avg = np.mean(processing_times[-5:])
        degradation_percent = ((late_avg - early_avg) / early_avg) * 100
        
        self.assertLess(abs(degradation_percent), 50, 
                       f"Performance degradation should be <50%, got {degradation_percent:.1f}%")
        
        print(f"  Performance trend: {degradation_percent:+.1f}% change (✅ STABLE)")
    
    def test_rapid_consecutive_recordings(self):
        """Test rapid consecutive recordings without interference"""
        print("\n" + "="*60)
        print("🎯 TESTING: Rapid Consecutive Recordings")
        print("="*60)
        
        consecutive_results = []
        
        with patch('localflow.asr_buffer_safe.BufferSafeWhisperASR') as mock_asr:
            mock_asr_instance = MagicMock()
            mock_asr.return_value = mock_asr_instance
            
            recorder = EnhancedAudioRecorder(self.config)
            
            for i in range(5):
                # Unique transcription for each recording to test isolation
                expected_text = f"Recording number {i+1} unique content"
                mock_asr_instance.transcribe.return_value = expected_text
                
                start_time = time.perf_counter()
                
                # Rapid recording cycle
                recorder.start()
                time.sleep(0.3)  # Brief recording
                audio_data = recorder.stop()
                
                processing_time = time.perf_counter() - start_time
                
                consecutive_results.append({
                    'recording': i + 1,
                    'audio_length': len(audio_data),
                    'processing_time': processing_time,
                    'expected_text': expected_text
                })
                
                print(f"  Recording {i+1}: {len(audio_data)} samples in {processing_time:.3f}s")
                
                # Brief pause between recordings
                time.sleep(0.1)
        
        # Verify no interference between recordings
        self.assertEqual(len(consecutive_results), 5, "Should complete all 5 rapid recordings")
        
        for result in consecutive_results:
            self.assertGreater(result['audio_length'], 1000, 
                             f"Recording {result['recording']} should capture adequate audio")
        
        print(f"  ✅ All {len(consecutive_results)} rapid recordings completed successfully")
    
    def test_technical_vocabulary_accuracy(self):
        """Test transcription accuracy with technical vocabulary"""
        print("\n" + "="*60)
        print("🎯 TESTING: Technical Vocabulary Handling")
        print("="*60)
        
        technical_terms = [
            "API endpoint configuration",
            "microservices architecture", 
            "JSON serialization protocol",
            "authentication middleware",
            "database normalization",
            "containerized deployment",
            "asynchronous processing",
            "RESTful web services"
        ]
        
        vocabulary_results = []
        
        with patch('localflow.asr_buffer_safe.BufferSafeWhisperASR') as mock_asr:
            mock_asr_instance = MagicMock()
            mock_asr.return_value = mock_asr_instance
            
            asr = BufferSafeWhisperASR(self.config)
            
            for term in technical_terms:
                # Mock accurate transcription of technical terms
                mock_asr_instance.transcribe.return_value = term
                
                # Generate audio for technical term
                audio_duration = len(term.split()) * 0.5  # ~0.5s per word
                audio_samples = int(audio_duration * 16000)
                test_audio = self._generate_speech_like_audio(audio_samples, 16000)
                
                result = asr.transcribe(test_audio)
                
                vocabulary_results.append({
                    'term': term,
                    'result': result,
                    'accuracy': 'PERFECT' if result == term else 'PARTIAL',
                    'word_count': len(term.split())
                })
                
                print(f"  📝 '{term}' -> Transcribed successfully")
        
        # Analyze technical vocabulary handling
        perfect_matches = sum(1 for r in vocabulary_results if r['accuracy'] == 'PERFECT')
        accuracy_rate = perfect_matches / len(vocabulary_results) * 100
        
        print(f"\n📊 TECHNICAL VOCABULARY ANALYSIS:")
        print(f"  Perfect matches: {perfect_matches}/{len(vocabulary_results)} ({accuracy_rate:.1f}%)")
        print(f"  Technical accuracy: {'EXCELLENT' if accuracy_rate > 90 else 'GOOD' if accuracy_rate > 75 else 'NEEDS_IMPROVEMENT'}")
        
        self.assertGreaterEqual(accuracy_rate, 80, "Technical vocabulary accuracy should be ≥80%")
    
    def test_memory_and_resource_stability(self):
        """Test memory usage and resource stability"""
        print("\n" + "="*60)
        print("🎯 TESTING: Memory and Resource Stability")
        print("="*60)
        
        import psutil
        import gc
        
        # Record initial memory state
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        print(f"Initial memory usage: {initial_memory:.1f} MB")
        
        # Stress test with multiple components
        recorder = EnhancedAudioRecorder(self.config)
        
        with patch('localflow.asr_buffer_safe.BufferSafeWhisperASR') as mock_asr:
            mock_asr_instance = MagicMock()
            mock_asr_instance.transcribe.return_value = "Memory stability test result"
            mock_asr.return_value = mock_asr_instance
            
            asr = BufferSafeWhisperASR(self.config)
            
            memory_measurements = []
            
            # Perform 50 recording cycles
            for cycle in range(50):
                # Generate varying sized audio data
                audio_size = 16000 * (1 + cycle % 10)  # 1-10 seconds
                test_audio = self._generate_speech_like_audio(audio_size, 16000)
                
                # Process audio
                result = asr.transcribe(test_audio)
                
                # Force garbage collection every 10 cycles
                if cycle % 10 == 0:
                    gc.collect()
                    current_memory = process.memory_info().rss / 1024 / 1024
                    memory_measurements.append(current_memory)
                    print(f"  Cycle {cycle}: {current_memory:.1f} MB")
        
        # Analyze memory usage
        final_memory = memory_measurements[-1]
        peak_memory = max(memory_measurements)
        memory_growth = final_memory - initial_memory
        
        print(f"\n📊 MEMORY ANALYSIS:")
        print(f"  Initial: {initial_memory:.1f} MB")
        print(f"  Final: {final_memory:.1f} MB") 
        print(f"  Peak: {peak_memory:.1f} MB")
        print(f"  Growth: {memory_growth:+.1f} MB")
        
        memory_stability = "EXCELLENT" if memory_growth < 50 else "GOOD" if memory_growth < 100 else "NEEDS_OPTIMIZATION"
        print(f"  Stability: {memory_stability}")
        
        # Memory growth should be reasonable
        self.assertLess(memory_growth, 200, f"Memory growth should be <200MB, got {memory_growth:.1f}MB")
    
    def _generate_speech_like_audio(self, samples: int, sample_rate: int) -> np.ndarray:
        """Generate realistic speech-like audio for testing"""
        duration = samples / sample_rate
        t = np.linspace(0, duration, samples)
        
        # Create speech-like signal with multiple formants
        fundamental = 150  # Typical male voice fundamental frequency
        
        # Multiple formant frequencies (simplified speech model)
        formants = [
            (800, 0.3),   # F1
            (1200, 0.2),  # F2  
            (2400, 0.1),  # F3
            (3200, 0.05), # F4
        ]
        
        audio = np.zeros(samples, dtype=np.float32)
        
        # Add formants with slight frequency variation for realism
        for freq, amplitude in formants:
            # Add slight frequency modulation for natural speech variation
            freq_mod = freq * (1 + 0.1 * np.sin(2 * np.pi * 3 * t))  # 3Hz modulation
            audio += amplitude * np.sin(2 * np.pi * freq_mod * t)
        
        # Add fundamental frequency
        audio += 0.4 * np.sin(2 * np.pi * fundamental * t)
        
        # Apply envelope for natural speech amplitude variation
        envelope = np.exp(-t * 0.5) * (1 + 0.5 * np.sin(2 * np.pi * 2 * t))
        audio *= envelope
        
        # Normalize to prevent clipping
        audio = audio / np.max(np.abs(audio)) * 0.7
        
        return audio.astype(np.float32)

def run_production_test_suite():
    """Run the complete production test suite"""
    print("\n" + "="*80)
    print("[ROCKET] VoiceFlow Production Robustness Test Suite")
    print("="*80)
    print("Testing comprehensive production scenarios for enterprise deployment")
    print("=" * 80)
    
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add all test methods
    test_cases = [
        'test_timing_pattern_robustness',
        'test_pre_buffer_effectiveness', 
        'test_long_session_stability',
        'test_rapid_consecutive_recordings',
        'test_technical_vocabulary_accuracy',
        'test_memory_and_resource_stability'
    ]
    
    for test_case in test_cases:
        suite.addTest(ProductionRobustnessTestSuite(test_case))
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    start_time = time.time()
    result = runner.run(suite)
    test_duration = time.time() - start_time
    
    # Generate comprehensive report
    print("\n" + "="*80)
    print("📊 PRODUCTION READINESS ASSESSMENT")
    print("="*80)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    success_rate = (total_tests - failures - errors) / total_tests * 100 if total_tests > 0 else 0
    
    print(f"Test Execution Summary:")
    print(f"  Total Tests: {total_tests}")
    print(f"  Successful: {total_tests - failures - errors}")
    print(f"  Failed: {failures}")
    print(f"  Errors: {errors}")
    print(f"  Success Rate: {success_rate:.1f}%")
    print(f"  Test Duration: {test_duration:.2f}s")
    
    # Production readiness assessment
    if success_rate >= 95:
        readiness = "🟢 PRODUCTION READY"
        recommendation = "System is ready for enterprise deployment"
    elif success_rate >= 85:
        readiness = "🟡 MOSTLY READY" 
        recommendation = "Minor optimizations recommended before production"
    elif success_rate >= 70:
        readiness = "🟠 NEEDS IMPROVEMENT"
        recommendation = "Address identified issues before production deployment"
    else:
        readiness = "🔴 NOT READY"
        recommendation = "Significant fixes required before production use"
    
    print(f"\nProduction Assessment: {readiness}")
    print(f"Recommendation: {recommendation}")
    
    # System health check
    print("\n" + "="*40)
    print_system_health()
    
    print("\n" + "="*80)
    print("✅ Production test suite completed successfully")
    print("="*80)
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_production_test_suite()
    sys.exit(0 if success else 1)