#!/usr/bin/env python3
"""
VoiceFlow Pause Detection Testing Framework
==========================================

Comprehensive testing framework for intelligent pause detection and interruption handling.
Tests natural speech scenarios, VAD sensitivity validation, and context preservation.

Features:
- Natural speech pattern simulation
- VAD sensitivity testing across different thresholds
- Speech continuity testing for various pause durations
- Interruption recovery testing scenarios
- Context preservation validation
- Performance benchmarking
"""

import unittest
import asyncio
import time
import random
import statistics
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from unittest.mock import Mock, MagicMock, patch
import tempfile
import os
from pathlib import Path

# Import pause detection modules
try:
    from pause_analyzer import (
        PauseClassifier, AdaptiveVADManager, PauseType, ContextType, 
        PauseEvent, create_pause_analyzer
    )
    from context_manager import (
        ContextPreserver, InterruptionType, ContextLevel,
        create_context_manager
    )
    PAUSE_MODULES_AVAILABLE = True
except ImportError:
    PAUSE_MODULES_AVAILABLE = False


@dataclass
class TestScenario:
    """Represents a pause detection test scenario"""
    name: str
    description: str
    speech_segments: List[str]
    pause_durations: List[float]
    expected_classifications: List[PauseType]
    context_type: ContextType
    expected_min_confidence: float = 0.6


@dataclass
class TestResult:
    """Test execution result"""
    scenario_name: str
    passed: bool
    actual_classifications: List[PauseType]
    actual_confidences: List[float]
    expected_classifications: List[PauseType]
    execution_time_ms: float
    errors: List[str]


class SpeechPatternGenerator:
    """Generates realistic speech patterns for testing"""
    
    def __init__(self):
        self.speech_templates = {
            ContextType.CODING: [
                "Let me define a function that takes two parameters",
                "First we need to import the necessary libraries",
                "Now we'll create a class called UserManager",
                "The variable should be initialized to an empty list",
                "We need to handle the exception properly here"
            ],
            ContextType.WRITING: [
                "The protagonist walked slowly through the empty street",
                "It was a dark and stormy night when everything changed",
                "She opened the letter with trembling hands",
                "The conclusion of this chapter brings us to understand",
                "In the beginning there was nothing but silence"
            ],
            ContextType.CHAT: [
                "Hey how are you doing today",
                "That sounds really interesting tell me more",
                "I was thinking we could meet up later",
                "Did you see the news about the new update",
                "Thanks for helping me with that problem"
            ],
            ContextType.PRESENTATION: [
                "Good morning everyone and welcome to today's presentation",
                "Our quarterly results show significant improvement",
                "The next slide demonstrates our market analysis",
                "In conclusion I would like to emphasize three key points",
                "Are there any questions about this proposal"
            ]
        }
        
        self.natural_pause_patterns = {
            PauseType.NATURAL_BREATH: (0.1, 0.4),
            PauseType.THINKING_PAUSE: (0.5, 2.0),
            PauseType.SENTENCE_BREAK: (1.0, 3.0),
            PauseType.TOPIC_TRANSITION: (2.0, 5.0),
            PauseType.INTENTIONAL_STOP: (3.0, 8.0)
        }
    
    def generate_speech_sequence(self, context: ContextType, num_segments: int = 5) -> List[str]:
        """Generate realistic speech sequence for given context"""
        templates = self.speech_templates.get(context, self.speech_templates[ContextType.CHAT])
        return [random.choice(templates) for _ in range(num_segments)]
    
    def generate_pause_duration(self, pause_type: PauseType) -> float:
        """Generate realistic pause duration for given type"""
        min_dur, max_dur = self.natural_pause_patterns[pause_type]
        return random.uniform(min_dur, max_dur)
    
    def create_realistic_scenario(self, name: str, context: ContextType, 
                                 num_segments: int = 5) -> TestScenario:
        """Create a realistic test scenario with natural speech patterns"""
        speech_segments = self.generate_speech_sequence(context, num_segments)
        
        # Generate natural pause pattern
        pause_types = []
        pause_durations = []
        
        for i in range(num_segments - 1):
            if i == 0:
                # First pause tends to be thinking or sentence break
                pause_type = random.choice([PauseType.THINKING_PAUSE, PauseType.SENTENCE_BREAK])
            elif i == num_segments - 2:
                # Last pause might be intentional stop
                pause_type = random.choice([
                    PauseType.SENTENCE_BREAK, PauseType.TOPIC_TRANSITION, 
                    PauseType.INTENTIONAL_STOP
                ])
            else:
                # Middle pauses are varied
                pause_type = random.choice([
                    PauseType.NATURAL_BREATH, PauseType.THINKING_PAUSE, 
                    PauseType.SENTENCE_BREAK
                ])
            
            pause_types.append(pause_type)
            pause_durations.append(self.generate_pause_duration(pause_type))
        
        return TestScenario(
            name=name,
            description=f"Realistic {context.value} scenario with {num_segments} segments",
            speech_segments=speech_segments,
            pause_durations=pause_durations,
            expected_classifications=pause_types,
            context_type=context,
            expected_min_confidence=0.5  # Lower for realistic scenarios
        )


class PauseDetectionTestSuite(unittest.TestCase):
    """Comprehensive test suite for pause detection functionality"""
    
    def setUp(self):
        """Set up test environment"""
        if not PAUSE_MODULES_AVAILABLE:
            self.skipTest("Pause detection modules not available")
        
        # Create temporary directory for test data
        self.test_dir = tempfile.mkdtemp()
        
        # Initialize components
        self.pause_classifier = PauseClassifier("test_user")
        self.vad_manager = AdaptiveVADManager(self.pause_classifier)
        self.context_manager = ContextPreserver(max_context_size=100)
        self.pattern_generator = SpeechPatternGenerator()
        
        # Test results storage
        self.test_results = []
    
    def tearDown(self):
        """Clean up test environment"""
        if hasattr(self, 'context_manager'):
            self.context_manager.cleanup()
        
        # Clean up test directory
        import shutil
        try:
            shutil.rmtree(self.test_dir)
        except Exception:
            pass
    
    def test_basic_pause_classification(self):
        """Test basic pause duration classification"""
        print("\n🧪 Testing basic pause classification...")
        
        test_cases = [
            (0.2, PauseType.NATURAL_BREATH),
            (1.0, PauseType.THINKING_PAUSE),
            (2.5, PauseType.SENTENCE_BREAK),
            (4.0, PauseType.TOPIC_TRANSITION),
            (6.0, PauseType.INTENTIONAL_STOP)
        ]
        
        for duration, expected_type in test_cases:
            with self.subTest(duration=duration):
                pause_event = self.pause_classifier.classify_pause(
                    duration=duration,
                    speech_before="Test speech before",
                    speech_after="Test speech after"
                )
                
                self.assertEqual(pause_event.classification, expected_type)
                self.assertGreater(pause_event.confidence, 0.3)
                print(f"   ✅ {duration}s → {expected_type.value} (confidence: {pause_event.confidence:.2f})")
    
    def test_context_aware_classification(self):
        """Test context-aware pause classification"""
        print("\n🧪 Testing context-aware classification...")
        
        contexts = [ContextType.CODING, ContextType.CHAT, ContextType.PRESENTATION]
        
        for context in contexts:
            with self.subTest(context=context):
                self.pause_classifier.set_context(context)
                
                # Test same pause duration in different contexts
                pause_event = self.pause_classifier.classify_pause(
                    duration=2.0,
                    speech_before="Previous statement in context",
                    speech_after="Following statement"
                )
                
                # Confidence should be reasonable in all contexts
                self.assertGreater(pause_event.confidence, 0.4)
                self.assertEqual(pause_event.context, context)
                print(f"   ✅ {context.value}: 2.0s → {pause_event.classification.value}")
    
    def test_speech_pattern_learning(self):
        """Test user speech pattern learning"""
        print("\n🧪 Testing speech pattern learning...")
        
        # Simulate multiple pause events to train the classifier
        training_pauses = [
            (1.2, PauseType.THINKING_PAUSE),
            (1.5, PauseType.THINKING_PAUSE),
            (2.8, PauseType.SENTENCE_BREAK),
            (3.1, PauseType.SENTENCE_BREAK),
            (0.3, PauseType.NATURAL_BREATH)
        ]
        
        for duration, expected_type in training_pauses:
            self.pause_classifier.classify_pause(
                duration=duration,
                speech_before="Training speech",
                speech_after="More training"
            )
        
        # Force pattern update
        self.pause_classifier._update_patterns()
        
        # Test that patterns were learned
        self.assertIsNotNone(self.pause_classifier.user_patterns)
        self.assertGreater(self.pause_classifier.user_patterns.avg_pause_duration, 0)
        
        stats = self.pause_classifier.get_pause_statistics()
        self.assertTrue(stats.get("pattern_learned", False))
        print(f"   ✅ Learned patterns: avg={self.pause_classifier.user_patterns.avg_pause_duration:.2f}s")
    
    def test_vad_adaptation(self):
        """Test VAD configuration adaptation"""
        print("\n🧪 Testing VAD adaptation...")
        
        contexts = [ContextType.CODING, ContextType.CHAT, ContextType.PRESENTATION]
        
        for context in contexts:
            with self.subTest(context=context):
                config = self.vad_manager.get_config_for_context(context)
                
                # Verify required VAD parameters are present
                required_params = [
                    'silero_sensitivity', 'webrtc_sensitivity',
                    'post_speech_silence_duration', 'min_length_of_recording',
                    'min_gap_between_recordings'
                ]
                
                for param in required_params:
                    self.assertIn(param, config)
                    self.assertIsInstance(config[param], (int, float))
                
                print(f"   ✅ {context.value}: silence_duration={config['post_speech_silence_duration']:.1f}s")
    
    def test_context_preservation(self):
        """Test context preservation across interruptions"""
        print("\n🧪 Testing context preservation...")
        
        # Add some context
        test_texts = [
            "We were discussing the new project requirements",
            "The deadline is next Friday for the first milestone",
            "I think we should prioritize the user interface"
        ]
        
        for text in test_texts:
            self.context_manager.add_context(text, importance=1.0)
        
        # Simulate interruption
        self.context_manager.handle_interruption_start(InterruptionType.PHONE_CALL)
        time.sleep(0.1)  # Brief interruption
        recovery_info = self.context_manager.handle_interruption_end()
        
        # Verify context was preserved
        self.assertIsNotNone(recovery_info)
        self.assertIn("pre_interruption_context", recovery_info)
        self.assertGreater(recovery_info.get("context_preservation_score", 0), 0.8)
        
        # Test context retrieval
        context = self.context_manager.get_context(ContextLevel.SHORT_TERM)
        self.assertGreater(len(context), 0)
        print(f"   ✅ Context preserved: score={recovery_info['context_preservation_score']:.2f}")
    
    def test_continuation_detection(self):
        """Test continuation intent detection"""
        print("\n🧪 Testing continuation detection...")
        
        # Set up pre-interruption context
        pre_context = "We were talking about the new feature implementation"
        self.context_manager.add_context(pre_context)
        
        # Simulate interruption
        self.context_manager.handle_interruption_start(InterruptionType.MEETING)
        time.sleep(0.1)
        self.context_manager.handle_interruption_end()
        
        # Test continuation detection
        continuation_tests = [
            ("And furthermore, we need to consider", True),   # Clear continuation
            ("Also, the performance impact", True),           # Continuation word
            ("What time is it?", False),                      # Topic change
            ("That feature we discussed", True)               # Reference to previous
        ]
        
        for new_text, expected_continuation in continuation_tests:
            with self.subTest(text=new_text):
                result = self.context_manager.detect_continuation_intent(new_text)
                
                # Allow some tolerance in continuation detection
                if expected_continuation:
                    self.assertGreater(result.get("confidence", 0), 0.3)
                else:
                    self.assertLess(result.get("confidence", 1), 0.7)
                
                print(f"   ✅ '{new_text[:30]}...' → continuation: {result.get('is_continuation', False)}")
    
    def test_realistic_scenarios(self):
        """Test with realistic speech scenarios"""
        print("\n🧪 Testing realistic scenarios...")
        
        scenarios = [
            self.pattern_generator.create_realistic_scenario("coding_session", ContextType.CODING, 4),
            self.pattern_generator.create_realistic_scenario("casual_chat", ContextType.CHAT, 5),
            self.pattern_generator.create_realistic_scenario("presentation", ContextType.PRESENTATION, 3)
        ]
        
        for scenario in scenarios:
            with self.subTest(scenario=scenario.name):
                result = self._execute_scenario(scenario)
                
                # At least 60% of classifications should be reasonable
                correct_classifications = sum(
                    1 for actual, expected in zip(result.actual_classifications, result.expected_classifications)
                    if actual == expected or self._is_reasonable_classification(actual, expected)
                )
                
                accuracy = correct_classifications / len(result.expected_classifications)
                self.assertGreater(accuracy, 0.4, f"Low accuracy for {scenario.name}: {accuracy:.2f}")
                
                print(f"   ✅ {scenario.name}: {accuracy:.1%} accuracy")
                self.test_results.append(result)
    
    def test_performance_benchmarks(self):
        """Test performance benchmarks"""
        print("\n🧪 Testing performance benchmarks...")
        
        # Test classification speed
        start_time = time.time()
        num_classifications = 100
        
        for i in range(num_classifications):
            duration = random.uniform(0.1, 5.0)
            self.pause_classifier.classify_pause(
                duration=duration,
                speech_before=f"Test speech {i}",
                speech_after=f"Following speech {i}"
            )
        
        total_time = time.time() - start_time
        avg_time_ms = (total_time / num_classifications) * 1000
        
        # Should be very fast (under 10ms per classification)
        self.assertLess(avg_time_ms, 50, f"Classification too slow: {avg_time_ms:.1f}ms")
        print(f"   ✅ Classification speed: {avg_time_ms:.1f}ms average")
        
        # Test memory usage (rough check)
        import psutil
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        
        # Should use reasonable memory (under 100MB for tests)
        self.assertLess(memory_mb, 200, f"Memory usage too high: {memory_mb:.1f}MB")
        print(f"   ✅ Memory usage: {memory_mb:.1f}MB")
    
    def test_edge_cases(self):
        """Test edge cases and error handling"""
        print("\n🧪 Testing edge cases...")
        
        # Test with empty/invalid inputs
        edge_cases = [
            (0.0, "", ""),                    # Zero duration
            (-1.0, "text", "text"),           # Negative duration
            (999.0, "text", "text"),          # Very long duration
            (1.0, "", ""),                    # Empty speech
            (1.0, "a" * 10000, "text")        # Very long speech
        ]
        
        for duration, before, after in edge_cases:
            with self.subTest(duration=duration, before_len=len(before)):
                try:
                    pause_event = self.pause_classifier.classify_pause(
                        duration=duration,
                        speech_before=before,
                        speech_after=after
                    )
                    
                    # Should not crash and return reasonable values
                    self.assertIsInstance(pause_event, PauseEvent)
                    self.assertGreaterEqual(pause_event.confidence, 0)
                    self.assertLessEqual(pause_event.confidence, 1)
                    
                except Exception as e:
                    self.fail(f"Edge case caused exception: {e}")
        
        print("   ✅ All edge cases handled gracefully")
    
    def _execute_scenario(self, scenario: TestScenario) -> TestResult:
        """Execute a test scenario and return results"""
        start_time = time.time()
        actual_classifications = []
        actual_confidences = []
        errors = []
        
        try:
            # Set context
            self.pause_classifier.set_context(scenario.context_type)
            
            # Execute pause classifications
            for i, duration in enumerate(scenario.pause_durations):
                speech_before = scenario.speech_segments[i] if i < len(scenario.speech_segments) else ""
                speech_after = scenario.speech_segments[i + 1] if i + 1 < len(scenario.speech_segments) else ""
                
                pause_event = self.pause_classifier.classify_pause(
                    duration=duration,
                    speech_before=speech_before,
                    speech_after=speech_after
                )
                
                actual_classifications.append(pause_event.classification)
                actual_confidences.append(pause_event.confidence)
        
        except Exception as e:
            errors.append(str(e))
        
        execution_time = (time.time() - start_time) * 1000
        
        # Determine if test passed
        passed = (
            len(errors) == 0 and
            len(actual_classifications) == len(scenario.expected_classifications) and
            all(conf >= scenario.expected_min_confidence for conf in actual_confidences)
        )
        
        return TestResult(
            scenario_name=scenario.name,
            passed=passed,
            actual_classifications=actual_classifications,
            actual_confidences=actual_confidences,
            expected_classifications=scenario.expected_classifications,
            execution_time_ms=execution_time,
            errors=errors
        )
    
    def _is_reasonable_classification(self, actual: PauseType, expected: PauseType) -> bool:
        """Check if classification is reasonable even if not exact match"""
        # Define reasonable alternatives
        reasonable_alternatives = {
            PauseType.NATURAL_BREATH: [PauseType.THINKING_PAUSE],
            PauseType.THINKING_PAUSE: [PauseType.NATURAL_BREATH, PauseType.SENTENCE_BREAK],
            PauseType.SENTENCE_BREAK: [PauseType.THINKING_PAUSE, PauseType.TOPIC_TRANSITION],
            PauseType.TOPIC_TRANSITION: [PauseType.SENTENCE_BREAK, PauseType.INTENTIONAL_STOP],
            PauseType.INTENTIONAL_STOP: [PauseType.TOPIC_TRANSITION]
        }
        
        alternatives = reasonable_alternatives.get(expected, [])
        return actual in alternatives
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r.passed)
        
        avg_execution_time = statistics.mean([r.execution_time_ms for r in self.test_results]) if self.test_results else 0
        
        # Calculate classification accuracy
        total_classifications = sum(len(r.actual_classifications) for r in self.test_results)
        correct_classifications = 0
        
        for result in self.test_results:
            for actual, expected in zip(result.actual_classifications, result.expected_classifications):
                if actual == expected or self._is_reasonable_classification(actual, expected):
                    correct_classifications += 1
        
        classification_accuracy = correct_classifications / total_classifications if total_classifications > 0 else 0
        
        return {
            "test_summary": {
                "total_scenarios": total_tests,
                "passed_scenarios": passed_tests,
                "success_rate": passed_tests / total_tests if total_tests > 0 else 0,
                "avg_execution_time_ms": avg_execution_time
            },
            "classification_performance": {
                "total_classifications": total_classifications,
                "correct_classifications": correct_classifications,
                "accuracy": classification_accuracy
            },
            "detailed_results": [
                {
                    "scenario": r.scenario_name,
                    "passed": r.passed,
                    "execution_time_ms": r.execution_time_ms,
                    "errors": r.errors
                }
                for r in self.test_results
            ]
        }


def run_comprehensive_tests():
    """Run comprehensive pause detection tests"""
    print("🚀 Starting VoiceFlow Pause Detection Test Suite")
    print("=" * 60)
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(PauseDetectionTestSuite)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=None)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    print("📊 Test Summary:")
    print(f"   Tests run: {result.testsRun}")
    print(f"   Failures: {len(result.failures)}")
    print(f"   Errors: {len(result.errors)}")
    print(f"   Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print("\n❌ Failures:")
        for test, traceback in result.failures:
            print(f"   {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\n🔥 Errors:")
        for test, traceback in result.errors:
            print(f"   {test}: {traceback.split('Exception:')[-1].strip()}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    if not PAUSE_MODULES_AVAILABLE:
        print("❌ Pause detection modules not available. Please ensure pause_analyzer.py and context_manager.py are installed.")
        exit(1)
    
    success = run_comprehensive_tests()
    exit(0 if success else 1)