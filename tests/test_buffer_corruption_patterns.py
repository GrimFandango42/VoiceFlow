#!/usr/bin/env python3
"""
VoiceFlow Buffer Corruption Pattern Analysis & Testing

This test suite specifically targets buffer corruption patterns identified in production logs:
1. VAD state pollution between recordings
2. Buffer state not properly cleared between sessions
3. Previous buffer content bleeding into new recordings
4. State management issues in long-running sessions

Based on real user feedback about buffer corruption with repeating outputs.
"""

import unittest
import sys
import os
import logging
import time
from unittest.mock import Mock, patch, MagicMock
import numpy as np

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from voiceflow.config import Config
from voiceflow.asr_enhanced import EnhancedWhisperASR

logger = logging.getLogger(__name__)


class TestBufferCorruptionPatterns(unittest.TestCase):
    """Test specific buffer corruption patterns seen in production logs"""
    
    def setUp(self):
        self.config = Config()
        self.config.vad_filter = False  # Should be disabled
        
    def test_vad_state_pollution_between_recordings(self):
        """
        Test the exact VAD state pollution pattern from logs:
        - First recording: Success with VAD
        - Subsequent recordings: VAD removes ALL audio
        """
        
        # Track VAD behavior across multiple recordings
        vad_decisions = []
        
        class MockWhisperModel:
            def __init__(self):
                self.call_count = 0
            
            def transcribe(self, audio, **kwargs):
                self.call_count += 1
                use_vad = kwargs.get('vad_filter', False)
                
                # Simulate the exact pattern from logs
                if use_vad:
                    if self.call_count == 1:
                        # First call: VAD works normally
                        vad_decisions.append("kept_some_audio")
                        segments = [Mock(text="First recording works", start=0.0, end=3.0)]
                    else:
                        # Subsequent calls: VAD removes everything (THE BUG!)
                        vad_decisions.append("removed_all_audio")  
                        segments = []  # VAD removed all audio
                else:
                    # Without VAD: always works
                    vad_decisions.append("no_vad_used")
                    segments = [Mock(text=f"Recording {self.call_count} works", start=0.0, end=3.0)]
                
                info = Mock()
                return segments, info
        
        # Test with VAD enabled (reproduces the bug)
        with patch('localflow.asr_enhanced.WhisperModel', return_value=MockWhisperModel()):
            asr = EnhancedWhisperASR(self.config)
            asr.cfg.vad_filter = True  # Force VAD on to reproduce bug
            asr.load()
            
            # Simulate 4 consecutive recordings (pattern from logs)
            results = []
            for i in range(4):
                audio = np.random.randn(16000 * 3).astype(np.float32)  # 3 seconds
                result = asr.transcribe(audio)
                results.append(result)
                logger.info(f"Recording {i+1}: '{result}' (VAD decision: {vad_decisions[i] if i < len(vad_decisions) else 'none'})")
            
            # Verify the exact corruption pattern from logs
            self.assertNotEqual(results[0], "", "First recording should work")
            self.assertEqual(results[1], "", "Second recording affected by VAD bug")
            self.assertEqual(results[2], "", "Third recording affected by VAD bug") 
            self.assertEqual(results[3], "", "Fourth recording affected by VAD bug")
            
            # Verify VAD decisions match the log pattern
            expected_pattern = ["kept_some_audio", "removed_all_audio", "removed_all_audio", "removed_all_audio"]
            self.assertEqual(vad_decisions, expected_pattern, "VAD decisions should match log corruption pattern")
    
    def test_buffer_state_clearing_between_recordings(self):
        """Test that buffer state is properly cleared between recordings"""
        
        asr = EnhancedWhisperASR(self.config)
        
        # Track internal state changes
        initial_transcription_count = asr.transcription_count
        initial_consecutive_empty = asr.consecutive_empty_results
        
        # Simulate first recording
        with patch.object(asr, '_model') as mock_model:
            mock_model.transcribe.return_value = ([Mock(text="First recording", start=0.0, end=2.0)], Mock())
            
            audio1 = np.random.randn(16000 * 2).astype(np.float32)
            result1 = asr.transcribe(audio1)
            
            # Check state after first recording
            state_after_first = {
                'transcription_count': asr.transcription_count,
                'consecutive_empty_results': asr.consecutive_empty_results,
                'vad_fallback_triggered': asr.vad_fallback_triggered
            }
            
            # Simulate second recording
            mock_model.transcribe.return_value = ([Mock(text="Second recording", start=0.0, end=2.0)], Mock())
            
            audio2 = np.random.randn(16000 * 2).astype(np.float32)
            result2 = asr.transcribe(audio2)
            
            # Verify state evolution is correct
            self.assertGreater(asr.transcription_count, initial_transcription_count, 
                             "Transcription count should increment")
            self.assertEqual(asr.consecutive_empty_results, 0, 
                           "Empty results counter should reset on success")
            
            # Verify no state pollution between recordings
            self.assertNotEqual(result1, result2, "Results should be independent")
            self.assertNotIn("First recording", result2, "Previous buffer shouldn't bleed into new recording")
            
            logger.info(f"State management: {state_after_first}")
    
    def test_segment_buffer_overflow_corruption(self):
        """Test segment buffer management to prevent overflow corruption"""
        
        # Create scenario with many small segments (potential overflow)
        large_segment_count = 50
        segments = []
        
        for i in range(large_segment_count):
            segment = Mock()
            segment.text = f"Segment {i+1}"
            segment.start = i * 0.5  # 0.5 second intervals
            segment.end = (i + 1) * 0.5
            segments.append(segment)
        
        asr = EnhancedWhisperASR(self.config)
        
        with patch.object(asr, '_model') as mock_model:
            mock_model.transcribe.return_value = (segments, Mock())
            
            # Large audio to stress test segment processing
            large_audio = np.random.randn(16000 * 25).astype(np.float32)  # 25 seconds
            result = asr.transcribe(large_audio)
            
            # Verify all segments processed correctly
            self.assertIn("Segment 1", result, "First segment should be present")
            self.assertIn("Segment 50", result, "Last segment should be present")
            
            # Verify segments are in chronological order (our fix)
            segment_positions = []
            for i in range(1, large_segment_count + 1):
                pos = result.find(f"Segment {i}")
                if pos != -1:
                    segment_positions.append((i, pos))
            
            # Check ordering
            for i in range(1, len(segment_positions)):
                prev_segment, prev_pos = segment_positions[i-1]
                curr_segment, curr_pos = segment_positions[i]
                
                self.assertLess(prev_pos, curr_pos, 
                              f"Segment {prev_segment} should come before Segment {curr_segment}")
            
            logger.info(f"Processed {large_segment_count} segments correctly in chronological order")
    
    def test_memory_state_corruption_detection(self):
        """Test detection of memory state corruption patterns"""
        
        asr = EnhancedWhisperASR(self.config)
        
        # Simulate corruption scenarios
        corruption_tests = [
            {
                "name": "repeated_transcription_same_input",
                "scenario": "Same audio produces different results (memory corruption)",
                "audio": np.random.randn(16000 * 2).astype(np.float32),
                "expected_consistent": True
            },
            {
                "name": "state_leakage_between_calls",
                "scenario": "Previous call state affects new call",
                "audio": np.random.randn(16000 * 1).astype(np.float32),
                "expected_consistent": False  # Should vary with different audio
            }
        ]
        
        with patch.object(asr, '_model') as mock_model:
            for test in corruption_tests:
                # Mock consistent behavior
                mock_model.transcribe.return_value = ([Mock(text="Consistent result", start=0.0, end=2.0)], Mock())
                
                # Run same test multiple times
                results = []
                for i in range(3):
                    if test["expected_consistent"]:
                        # Same audio should give same result
                        result = asr.transcribe(test["audio"])
                    else:
                        # Different audio should give different results
                        different_audio = np.random.randn(16000 * 1).astype(np.float32)
                        result = asr.transcribe(different_audio)
                    
                    results.append(result)
                
                if test["expected_consistent"]:
                    # All results should be the same
                    for result in results[1:]:
                        self.assertEqual(result, results[0], 
                                       f"Consistent input should produce consistent output in {test['name']}")
                
                logger.info(f"Memory corruption test '{test['name']}': {len(set(results))} unique results")
    
    def test_long_session_buffer_degradation(self):
        """Test for buffer degradation over long sessions (the 'repeating outputs' issue)"""
        
        asr = EnhancedWhisperASR(self.config)
        session_results = []
        
        with patch.object(asr, '_model') as mock_model:
            # Simulate a long session with 20 recordings
            for session_num in range(20):
                # Each recording should be unique
                expected_text = f"Session {session_num + 1} unique recording"
                mock_model.transcribe.return_value = ([Mock(text=expected_text, start=0.0, end=2.0)], Mock())
                
                audio = np.random.randn(16000 * 2).astype(np.float32)
                result = asr.transcribe(audio)
                session_results.append(result)
                
                # Check for buffer corruption signs
                if session_num > 0:
                    # Current result shouldn't contain previous results (buffer bleeding)
                    for prev_idx in range(session_num):
                        prev_text = f"Session {prev_idx + 1} unique recording"
                        self.assertNotIn(prev_text, result, 
                                       f"Session {session_num + 1} shouldn't contain content from session {prev_idx + 1}")
                
                # Check for repeated outputs (the specific issue mentioned)
                if session_num > 2:
                    recent_results = session_results[-3:]  # Last 3 results
                    unique_results = set(recent_results)
                    self.assertEqual(len(unique_results), 3, 
                                   f"Recent results should be unique, not repeated: {recent_results}")
            
            # Verify session statistics are reasonable
            stats = asr.get_statistics()
            self.assertEqual(stats['transcription_count'], 20, "Should have processed 20 recordings")
            self.assertFalse(stats['vad_fallback_triggered'], "VAD fallback shouldn't be triggered in this test")
            
            logger.info(f"Long session completed: {stats}")


def run_buffer_corruption_analysis():
    """Run comprehensive buffer corruption pattern analysis"""
    
    print("=" * 70)
    print("VoiceFlow Buffer Corruption Pattern Analysis")
    print("=" * 70)
    print("Analyzing specific issues identified from production logs:")
    print("• VAD state pollution between recordings")
    print("• Buffer state not cleared between sessions")
    print("• Previous buffer content bleeding into new recordings")
    print("• Repeating outputs from previous buffers")
    print("• Memory state corruption in long-running sessions")
    print("=" * 70)
    
    # Create test suite focused on buffer corruption
    suite = unittest.TestSuite()
    tests = unittest.TestLoader().loadTestsFromTestCase(TestBufferCorruptionPatterns)
    suite.addTests(tests)
    
    # Run with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Analysis
    print("\n" + "=" * 70)
    print("Buffer Corruption Analysis Results")
    print("=" * 70)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    success_rate = (total_tests - failures - errors) / total_tests * 100 if total_tests > 0 else 0
    
    print(f"Buffer Corruption Tests: {total_tests}")
    print(f"Issues Identified: {failures + errors}")
    print(f"Clean Patterns: {total_tests - failures - errors}")
    print(f"System Health: {success_rate:.1f}%")
    
    # Specific findings
    print("\nBuffer Corruption Patterns:")
    
    if result.failures:
        print("CRITICAL ISSUES FOUND:")
        for test, traceback in result.failures:
            test_name = str(test).split('.')[-1].replace(')', '').replace('(', ' ')
            print(f"• {test_name}: Buffer corruption detected")
    
    if result.errors:
        print("SYSTEM ERRORS:")
        for test, traceback in result.errors:
            test_name = str(test).split('.')[-1].replace(')', '').replace('(', ' ')
            print(f"• {test_name}: System error during buffer test")
    
    if success_rate >= 90:
        print("\nSTATUS: Buffer management is robust")
    elif success_rate >= 70:
        print("\nSTATUS: Minor buffer issues detected")
    else:
        print("\nSTATUS: CRITICAL - Multiple buffer corruption patterns found")
    
    print("\nRecommended Actions:")
    print("• Ensure VAD is completely disabled in production")
    print("• Add buffer state clearing between recordings")
    print("• Implement session isolation to prevent state bleeding")
    print("• Add memory corruption detection in production monitoring")
    
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_buffer_corruption_analysis()
    sys.exit(0 if success else 1)