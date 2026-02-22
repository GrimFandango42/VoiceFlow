#!/usr/bin/env python3
"""
Long Session Stress Test for VoiceFlow Stability Improvements

Tests system stability under extended usage scenarios:
- Multiple hours of continuous operation
- Various audio types and edge cases
- Memory usage monitoring
- Performance degradation detection
- Error recovery under stress

Author: Claude Code
Date: 2025-09-27
"""

import sys
import os
import time
import numpy as np
import psutil
import gc
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
    from voiceflow.core.config import Config
    from voiceflow.stability.hallucination_detector import HallucinationDetector
except ImportError as e:
    print(f"Failed to import VoiceFlow modules: {e}")
    sys.exit(1)

@dataclass
class StressTestMetrics:
    """Metrics collected during stress testing"""
    timestamp: str
    transcription_number: int
    processing_time: float
    memory_usage_mb: float
    cpu_usage_percent: float
    model_reloads: int
    hallucinations_detected: int
    errors_occurred: int
    transcription_length: int
    audio_type: str

class LongSessionStressTester:
    """Comprehensive stress testing framework"""

    def __init__(self, target_duration_minutes: int = 30):
        self.target_duration = target_duration_minutes * 60  # Convert to seconds
        self.config = Config()
        self.asr = None
        self.hallucination_detector = HallucinationDetector()
        self.process = psutil.Process()
        self.metrics: List[StressTestMetrics] = []
        self.start_time = None
        self.total_transcriptions = 0
        self.total_errors = 0
        self.total_model_reloads = 0
        self.total_hallucinations = 0

    def setup_stress_test(self):
        """Initialize stress test environment"""
        print(f"Setting up stress test for {self.target_duration/60:.1f} minutes...")

        try:
            self.asr = BufferSafeWhisperASR(self.config)
            print("ASR initialized successfully")
            return True
        except Exception as e:
            print(f"Failed to initialize ASR: {e}")
            return False

    def generate_varied_audio(self, iteration: int) -> tuple:
        """Generate varied audio types for comprehensive testing"""
        # Cycle through different audio types and durations
        audio_patterns = [
            ("speech_short", 0.5),
            ("speech_medium", 1.5),
            ("speech_long", 3.0),
            ("silence", 0.3),
            ("noise", 1.0),
            ("quiet_speech", 2.0),
            ("mixed", 1.8)
        ]

        pattern_index = iteration % len(audio_patterns)
        audio_type, duration = audio_patterns[pattern_index]

        sample_rate = 16000
        samples = int(duration * sample_rate)

        if audio_type == "speech_short":
            t = np.linspace(0, duration, samples)
            audio = 0.1 * np.sin(2 * np.pi * 200 * t)
        elif audio_type == "speech_medium":
            t = np.linspace(0, duration, samples)
            audio = (0.1 * np.sin(2 * np.pi * 150 * t) +
                    0.05 * np.sin(2 * np.pi * 400 * t))
        elif audio_type == "speech_long":
            t = np.linspace(0, duration, samples)
            audio = (0.1 * np.sin(2 * np.pi * 180 * t) +
                    0.05 * np.sin(2 * np.pi * 350 * t) +
                    0.02 * np.sin(2 * np.pi * 800 * t))
        elif audio_type == "silence":
            audio = np.zeros(samples)
        elif audio_type == "noise":
            audio = np.random.normal(0, 0.01, samples)
        elif audio_type == "quiet_speech":
            t = np.linspace(0, duration, samples)
            audio = 0.02 * np.sin(2 * np.pi * 200 * t)  # Very quiet
        elif audio_type == "mixed":
            t = np.linspace(0, duration, samples)
            # Mix of speech and background noise
            speech = 0.08 * np.sin(2 * np.pi * 180 * t)
            noise = np.random.normal(0, 0.005, samples)
            audio = speech + noise
        else:
            audio = np.random.normal(0, 0.1, samples)

        return audio.astype(np.float32), audio_type

    def collect_metrics(self, transcription_num: int, processing_time: float,
                       transcription_result: str, audio_type: str) -> StressTestMetrics:
        """Collect comprehensive metrics"""
        memory_info = self.process.memory_info()
        memory_mb = memory_info.rss / 1024 / 1024
        cpu_percent = self.process.cpu_percent()

        # Check for hallucinations in result
        hallucinations = 0
        if transcription_result:
            if self.hallucination_detector.detect_okay_hallucination(transcription_result):
                hallucinations += 1
                self.total_hallucinations += 1

        # Track model reloads
        current_reload_count = getattr(self.asr, '_transcriptions_since_reload', 0)
        if hasattr(self, '_last_reload_count'):
            if current_reload_count < self._last_reload_count:
                self.total_model_reloads += 1
        self._last_reload_count = current_reload_count

        metrics = StressTestMetrics(
            timestamp=datetime.now().isoformat(),
            transcription_number=transcription_num,
            processing_time=processing_time,
            memory_usage_mb=memory_mb,
            cpu_usage_percent=cpu_percent,
            model_reloads=self.total_model_reloads,
            hallucinations_detected=hallucinations,
            errors_occurred=0,  # Will be updated if errors occur
            transcription_length=len(transcription_result),
            audio_type=audio_type
        )

        return metrics

    def run_stress_test_cycle(self, iteration: int) -> bool:
        """Run a single stress test cycle"""
        try:
            # Generate test audio
            audio, audio_type = self.generate_varied_audio(iteration)

            # Perform transcription with timing
            start_time = time.time()
            result = self.asr.transcribe(audio)
            processing_time = time.time() - start_time

            # Collect metrics
            metrics = self.collect_metrics(iteration + 1, processing_time, result, audio_type)
            self.metrics.append(metrics)

            # Print progress every 10 iterations
            if (iteration + 1) % 10 == 0:
                elapsed = time.time() - self.start_time
                remaining = self.target_duration - elapsed
                print(f"  Progress: {iteration + 1} transcriptions, "
                      f"{elapsed/60:.1f}m elapsed, {remaining/60:.1f}m remaining, "
                      f"Memory: {metrics.memory_usage_mb:.1f}MB")

            return True

        except Exception as e:
            print(f"Error in stress test cycle {iteration + 1}: {e}")
            self.total_errors += 1
            # Continue testing even after errors
            return False

    def analyze_performance_trends(self) -> Dict:
        """Analyze performance trends over the stress test"""
        if not self.metrics:
            return {"error": "No metrics collected"}

        # Calculate trends
        times = [m.processing_time for m in self.metrics]
        memories = [m.memory_usage_mb for m in self.metrics]
        cpu_usage = [m.cpu_usage_percent for m in self.metrics]

        # Performance analysis
        avg_processing_time = sum(times) / len(times)
        max_processing_time = max(times)
        min_processing_time = min(times)

        initial_memory = memories[0] if memories else 0
        final_memory = memories[-1] if memories else 0
        memory_growth = final_memory - initial_memory
        max_memory = max(memories) if memories else 0

        avg_cpu = sum(cpu_usage) / len(cpu_usage) if cpu_usage else 0

        # Detect performance degradation
        first_half = times[:len(times)//2] if len(times) > 10 else times
        second_half = times[len(times)//2:] if len(times) > 10 else times

        avg_first_half = sum(first_half) / len(first_half) if first_half else 0
        avg_second_half = sum(second_half) / len(second_half) if second_half else 0
        performance_degradation = ((avg_second_half - avg_first_half) / avg_first_half * 100) if avg_first_half > 0 else 0

        return {
            "total_transcriptions": len(self.metrics),
            "total_duration_minutes": (time.time() - self.start_time) / 60,
            "performance_metrics": {
                "avg_processing_time": avg_processing_time,
                "max_processing_time": max_processing_time,
                "min_processing_time": min_processing_time,
                "performance_degradation_percent": performance_degradation
            },
            "memory_metrics": {
                "initial_memory_mb": initial_memory,
                "final_memory_mb": final_memory,
                "memory_growth_mb": memory_growth,
                "max_memory_mb": max_memory
            },
            "stability_metrics": {
                "total_errors": self.total_errors,
                "total_model_reloads": self.total_model_reloads,
                "total_hallucinations": self.total_hallucinations,
                "error_rate_percent": (self.total_errors / len(self.metrics) * 100) if self.metrics else 0,
                "avg_cpu_usage": avg_cpu
            }
        }

    def generate_stress_test_report(self) -> Dict:
        """Generate comprehensive stress test report"""
        analysis = self.analyze_performance_trends()

        # Evaluate test results
        success_criteria = {
            "completed_target_duration": (time.time() - self.start_time) >= (self.target_duration * 0.9),
            "low_error_rate": analysis.get("stability_metrics", {}).get("error_rate_percent", 100) < 5,
            "reasonable_memory_growth": analysis.get("memory_metrics", {}).get("memory_growth_mb", 1000) < 500,
            "no_severe_degradation": abs(analysis.get("performance_metrics", {}).get("performance_degradation_percent", 100)) < 50,
            "successful_model_reloads": self.total_model_reloads > 0
        }

        overall_success = all(success_criteria.values())

        report = {
            "test_summary": {
                "start_time": self.start_time,
                "end_time": time.time(),
                "target_duration_minutes": self.target_duration / 60,
                "actual_duration_minutes": (time.time() - self.start_time) / 60,
                "overall_success": overall_success,
                "success_criteria": success_criteria
            },
            "performance_analysis": analysis,
            "recommendations": self._generate_stress_recommendations(analysis, success_criteria),
            "detailed_metrics": [asdict(m) for m in self.metrics[-50:]]  # Last 50 for brevity
        }

        return report

    def _generate_stress_recommendations(self, analysis: Dict, success_criteria: Dict) -> List[str]:
        """Generate recommendations based on stress test results"""
        recommendations = []

        if not success_criteria["completed_target_duration"]:
            recommendations.append("CRITICAL: Test terminated early - investigate stability issues")

        if not success_criteria["low_error_rate"]:
            error_rate = analysis.get("stability_metrics", {}).get("error_rate_percent", 0)
            recommendations.append(f"HIGH ERROR RATE: {error_rate:.1f}% - implement additional error handling")

        if not success_criteria["reasonable_memory_growth"]:
            growth = analysis.get("memory_metrics", {}).get("memory_growth_mb", 0)
            recommendations.append(f"MEMORY LEAK: {growth:.1f}MB growth - investigate memory cleanup")

        if not success_criteria["no_severe_degradation"]:
            degradation = analysis.get("performance_metrics", {}).get("performance_degradation_percent", 0)
            recommendations.append(f"PERFORMANCE DEGRADATION: {degradation:.1f}% - optimize long-running performance")

        if success_criteria["successful_model_reloads"]:
            recommendations.append("POSITIVE: Model reloads functioning as designed")

        memory_growth = analysis.get("memory_metrics", {}).get("memory_growth_mb", 0)
        if memory_growth < 100:
            recommendations.append("EXCELLENT: Memory usage remains stable")

        error_rate = analysis.get("stability_metrics", {}).get("error_rate_percent", 0)
        if error_rate < 1:
            recommendations.append("EXCELLENT: Very low error rate achieved")

        if all(success_criteria.values()):
            recommendations.append("PRODUCTION READY: All stress test criteria passed")

        return recommendations

    def run_comprehensive_stress_test(self) -> Dict:
        """Run the complete stress test suite"""
        print(f"Starting Comprehensive Long Session Stress Test")
        print(f"Target Duration: {self.target_duration/60:.1f} minutes")
        print("=" * 60)

        if not self.setup_stress_test():
            return {"error": "Failed to setup stress test"}

        self.start_time = time.time()
        iteration = 0

        print(f"Starting stress test iterations...")

        try:
            while (time.time() - self.start_time) < self.target_duration:
                success = self.run_stress_test_cycle(iteration)

                if success:
                    self.total_transcriptions += 1

                iteration += 1

                # Periodic garbage collection
                if iteration % 20 == 0:
                    gc.collect()

                # Small delay to prevent overwhelming the system
                time.sleep(0.1)

        except KeyboardInterrupt:
            print("\nStress test interrupted by user")
        except Exception as e:
            print(f"Stress test terminated by error: {e}")
            self.total_errors += 1

        print(f"\nStress test completed after {(time.time() - self.start_time)/60:.1f} minutes")

        # Generate comprehensive report
        report = self.generate_stress_test_report()

        return report

def main():
    """Main stress test execution"""
    # Allow user to specify duration
    duration_minutes = 5  # Default to 5 minutes for testing

    if len(sys.argv) > 1:
        try:
            duration_minutes = int(sys.argv[1])
        except ValueError:
            print("Invalid duration specified, using default 5 minutes")

    print(f"VoiceFlow Long Session Stress Test - {duration_minutes} minutes")

    tester = LongSessionStressTester(target_duration_minutes=duration_minutes)
    report = tester.run_comprehensive_stress_test()

    # Display results
    print("\n" + "=" * 60)
    print("STRESS TEST RESULTS")
    print("=" * 60)

    if "error" in report:
        print(f"ERROR: {report['error']}")
        return 1

    summary = report["test_summary"]
    analysis = report["performance_analysis"]

    print(f"Duration: {summary['actual_duration_minutes']:.1f}/{summary['target_duration_minutes']:.1f} minutes")
    print(f"Transcriptions: {analysis['total_transcriptions']}")
    print(f"Errors: {analysis['stability_metrics']['total_errors']}")
    print(f"Model Reloads: {analysis['stability_metrics']['total_model_reloads']}")
    print(f"Memory Growth: {analysis['memory_metrics']['memory_growth_mb']:.1f}MB")
    print(f"Performance Degradation: {analysis['performance_metrics']['performance_degradation_percent']:.1f}%")
    print(f"Overall Success: {'YES' if summary['overall_success'] else 'NO'}")

    print(f"\nRecommendations:")
    for rec in report["recommendations"]:
        print(f"  {rec}")

    # Save detailed report
    report_file = f"stress_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\nDetailed report saved to: {report_file}")

    return 0 if summary["overall_success"] else 1

if __name__ == "__main__":
    exit(main())