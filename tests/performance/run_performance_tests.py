"""
VoiceFlow Performance Test Runner
=================================

Comprehensive test runner for executing all VoiceFlow performance tests
and generating complete analysis reports.

This script orchestrates:
1. Performance baseline testing
2. Configuration comparison testing
3. Dashboard generation
4. Report compilation
"""

import logging
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional
import argparse

# Add source path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from test_transcription_performance import PerformanceTester, Config
from performance_comparison import PerformanceComparator
from performance_dashboard import PerformanceDashboard

logger = logging.getLogger(__name__)

class PerformanceTestSuite:
    """Complete performance test suite orchestrator"""

    def __init__(self, output_dir: str = "performance_test_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Create subdirectories
        (self.output_dir / "test_results").mkdir(exist_ok=True)
        (self.output_dir / "comparison_results").mkdir(exist_ok=True)
        (self.output_dir / "dashboards").mkdir(exist_ok=True)
        (self.output_dir / "reports").mkdir(exist_ok=True)

        self.test_results = {}
        self.comparison_results = {}

    def run_baseline_performance_tests(self, config_overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run baseline performance tests with current stability configuration"""
        logger.info("Starting baseline performance tests...")

        # Create test configuration (current stability-focused setup)
        config = Config(
            # STABILITY-FIRST configuration matching current implementation
            model_name="tiny.en",
            device="cpu",
            compute_type="int8",
            vad_filter=False,
            beam_size=1,
            temperature=0.0,
            max_transcriptions_before_reload=2,  # Aggressive reloading
            enable_lockfree_model_access=False,
            enable_ultra_fast_mode_bypass=False,
            enable_memory_pooling=False,
            enable_chunked_long_audio=False,
            preload_model_on_startup=False,
            enable_optimized_audio_validation=True,
            skip_buffer_integrity_checks=False,
            minimal_segment_processing=False,
            disable_fallback_detection=False,
            ultra_fast_mode=False,
            verbose=False  # Reduce logging noise during tests
        )

        # Apply any configuration overrides
        if config_overrides:
            for key, value in config_overrides.items():
                if hasattr(config, key):
                    setattr(config, key, value)
                    logger.info(f"Config override: {key} = {value}")

        # Run comprehensive test suite
        tester = PerformanceTester(config)
        results = tester.run_comprehensive_performance_suite()

        # Save results
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        results_file = self.output_dir / "test_results" / f"baseline_performance_{timestamp}.json"
        tester.save_results(results, str(results_file.parent))

        self.test_results['baseline'] = results
        logger.info(f"Baseline performance tests completed. Results saved to {results_file}")

        return results

    def run_configuration_comparison_tests(self, test_iterations: int = 3) -> Dict[str, Any]:
        """Run performance comparison between different configurations"""
        logger.info("Starting configuration comparison tests...")

        comparator = PerformanceComparator()

        # Test key configuration profiles
        baseline_profile = 'stability_focused'  # Current implementation
        comparison_profiles = ['original_optimized', 'balanced']

        # Check if GPU is available and add GPU profile
        try:
            import torch
            if torch.cuda.is_available():
                comparison_profiles.append('gpu_optimized')
                logger.info("GPU detected - including GPU optimization tests")
        except ImportError:
            logger.info("PyTorch not available - skipping GPU tests")

        # Run comparison tests
        results = comparator.run_profile_comparison(
            baseline_profile=baseline_profile,
            comparison_profiles=comparison_profiles,
            test_iterations=test_iterations
        )

        # Save results
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        results_file = self.output_dir / "comparison_results" / f"config_comparison_{timestamp}.json"
        comparator.save_comparison_results(results, str(results_file.parent))

        self.comparison_results = results
        logger.info(f"Configuration comparison tests completed. Results saved to {results_file}")

        return results

    def run_stability_stress_tests(self, duration_minutes: int = 10) -> Dict[str, Any]:
        """Run extended stability stress tests"""
        logger.info(f"Starting {duration_minutes}-minute stability stress test...")

        # Create stress test configuration
        config = Config(
            model_name="tiny.en",
            device="cpu",
            compute_type="int8",
            vad_filter=False,
            beam_size=1,
            temperature=0.0,
            max_transcriptions_before_reload=2,
            enable_lockfree_model_access=False,
            verbose=False
        )

        tester = PerformanceTester(config)
        asr_instance = tester.create_asr_instance(enhanced=False)

        # Calculate number of transcriptions for the duration
        # Assume ~3 seconds average per transcription cycle
        target_transcriptions = max(30, (duration_minutes * 60) // 3)

        logger.info(f"Running {target_transcriptions} transcriptions over {duration_minutes} minutes")

        # Run extended stability test
        stress_results = tester.test_long_session_stability(
            asr_instance,
            num_transcriptions=target_transcriptions
        )

        # Save results
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        stress_results_data = {
            'stress_test_duration_minutes': duration_minutes,
            'target_transcriptions': target_transcriptions,
            'actual_transcriptions': stress_results.total_transcriptions,
            'stress_session_results': stress_results.__dict__,
            'test_timestamp': timestamp
        }

        results_file = self.output_dir / "test_results" / f"stability_stress_{timestamp}.json"
        with open(results_file, 'w') as f:
            import json
            json.dump(stress_results_data, f, indent=2, default=str)

        logger.info(f"Stability stress test completed. Results saved to {results_file}")
        return stress_results_data

    def generate_performance_dashboards(self) -> None:
        """Generate interactive performance dashboards"""
        logger.info("Generating performance dashboards...")

        dashboard = PerformanceDashboard()

        # Load latest test results
        results_dir = self.output_dir / "test_results"
        comparison_dir = self.output_dir / "comparison_results"

        # Find most recent results
        results_files = list(results_dir.glob("*.json"))
        comparison_files = list(comparison_dir.glob("*.json"))

        if results_files:
            latest_results = max(results_files, key=lambda x: x.stat().st_mtime)
            dashboard.load_test_results(latest_results)
            logger.info(f"Loaded test results from {latest_results}")

        if comparison_files:
            latest_comparison = max(comparison_files, key=lambda x: x.stat().st_mtime)
            dashboard.load_comparison_results(latest_comparison)
            logger.info(f"Loaded comparison results from {latest_comparison}")

        # Generate all dashboards
        dashboard_dir = self.output_dir / "dashboards"

        if dashboard.results_data:
            # Speed analysis dashboard
            dashboard.create_speed_analysis_dashboard(
                dashboard_dir / "speed_analysis.html"
            )

            # Memory analysis dashboard
            dashboard.create_memory_analysis_dashboard(
                dashboard_dir / "memory_analysis.html"
            )

            # Stability trends dashboard
            dashboard.create_stability_trends_dashboard(
                dashboard_dir / "stability_trends.html"
            )

        if dashboard.comparison_data:
            # Performance comparison dashboard
            dashboard.create_performance_comparison_dashboard(
                dashboard_dir / "performance_comparison.html"
            )

        # Generate summary report
        summary_report = dashboard.generate_summary_report(
            self.output_dir / "reports" / "performance_summary.txt"
        )

        logger.info(f"Performance dashboards generated in {dashboard_dir}")
        return summary_report

    def run_memory_leak_detection(self, num_cycles: int = 50) -> Dict[str, Any]:
        """Run focused memory leak detection tests"""
        logger.info(f"Running memory leak detection over {num_cycles} cycles...")

        config = Config(
            model_name="tiny.en",
            device="cpu",
            compute_type="int8",
            max_transcriptions_before_reload=2,
            verbose=False
        )

        tester = PerformanceTester(config)
        asr_instance = tester.create_asr_instance()

        # Track memory usage over multiple model reload cycles
        import psutil
        import gc

        process = psutil.Process()
        memory_measurements = []

        # Use short audio for rapid cycling
        test_audio = tester.audio_generator.generate_speech_like(1.0)

        logger.info("Starting memory leak detection cycles...")

        for cycle in range(num_cycles):
            # Force garbage collection before measurement
            gc.collect()

            # Measure memory before transcription
            memory_before = process.memory_info().rss / 1024 / 1024  # MB

            # Perform transcription (will trigger reload every 2 transcriptions)
            try:
                result = asr_instance.transcribe(test_audio)
                transcription_success = True
            except Exception as e:
                logger.error(f"Transcription failed in cycle {cycle}: {e}")
                transcription_success = False

            # Measure memory after transcription
            memory_after = process.memory_info().rss / 1024 / 1024  # MB

            measurement = {
                'cycle': cycle,
                'memory_before_mb': memory_before,
                'memory_after_mb': memory_after,
                'memory_growth_mb': memory_after - memory_before,
                'transcription_success': transcription_success,
                'transcription_count': cycle + 1
            }

            memory_measurements.append(measurement)

            if cycle % 10 == 0:
                logger.info(f"Memory leak test cycle {cycle}/{num_cycles}: "
                           f"Memory = {memory_after:.1f}MB "
                           f"(+{memory_after - memory_before:.1f}MB)")

            # Brief pause between cycles
            time.sleep(0.1)

        # Analyze memory leak patterns
        total_growth = memory_measurements[-1]['memory_after_mb'] - memory_measurements[0]['memory_before_mb']
        max_cycle_growth = max(m['memory_growth_mb'] for m in memory_measurements)

        # Calculate trend (linear regression slope)
        import statistics
        memory_values = [m['memory_after_mb'] for m in memory_measurements]
        x_values = list(range(len(memory_values)))

        # Simple linear regression
        n = len(memory_values)
        sum_x = sum(x_values)
        sum_y = sum(memory_values)
        sum_xy = sum(x * y for x, y in zip(x_values, memory_values))
        sum_x2 = sum(x * x for x in x_values)

        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)

        leak_results = {
            'test_cycles': num_cycles,
            'total_memory_growth_mb': total_growth,
            'memory_growth_per_cycle_mb': total_growth / num_cycles,
            'max_cycle_growth_mb': max_cycle_growth,
            'memory_trend_slope': slope,
            'leak_detected': slope > 0.5,  # >0.5MB per cycle indicates leak
            'measurements': memory_measurements,
            'analysis': {
                'severe_leak': slope > 2.0,
                'moderate_leak': 0.5 < slope <= 2.0,
                'acceptable_growth': slope <= 0.5,
                'memory_stable': abs(slope) < 0.1
            }
        }

        # Save results
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        results_file = self.output_dir / "test_results" / f"memory_leak_test_{timestamp}.json"
        with open(results_file, 'w') as f:
            import json
            json.dump(leak_results, f, indent=2, default=str)

        logger.info(f"Memory leak detection completed. Results saved to {results_file}")

        # Log analysis summary
        if leak_results['analysis']['severe_leak']:
            logger.warning(f"⚠️ SEVERE MEMORY LEAK DETECTED: {slope:.2f}MB per cycle")
        elif leak_results['analysis']['moderate_leak']:
            logger.warning(f"⚠️ Moderate memory leak detected: {slope:.2f}MB per cycle")
        elif leak_results['analysis']['acceptable_growth']:
            logger.info(f"✅ Acceptable memory growth: {slope:.2f}MB per cycle")
        else:
            logger.info(f"✅ Memory usage stable: {slope:.2f}MB per cycle")

        return leak_results

    def generate_final_report(self) -> str:
        """Generate comprehensive final performance report"""
        logger.info("Generating final comprehensive report...")

        report_lines = []
        report_lines.append("VoiceFlow Stability Improvements Performance Analysis")
        report_lines.append("=" * 60)
        report_lines.append(f"Test execution completed: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")

        # Executive Summary
        report_lines.append("EXECUTIVE SUMMARY")
        report_lines.append("-" * 20)
        report_lines.append("This report analyzes the performance impact of aggressive stability")
        report_lines.append("improvements implemented in VoiceFlow transcription system:")
        report_lines.append("• Model reinitialization every 2 transcriptions")
        report_lines.append("• CPU-only forced configuration with int8 compute")
        report_lines.append("• Comprehensive error recovery patterns")
        report_lines.append("• Memory cleanup and garbage collection")
        report_lines.append("")

        # Key Findings placeholder
        report_lines.append("KEY FINDINGS")
        report_lines.append("-" * 12)

        if self.test_results:
            # Analyze baseline results
            baseline = self.test_results.get('baseline', {})
            if 'summary' in baseline:
                summary = baseline['summary']

                speed_factor = summary.get('speed_factor', {}).get('mean', 0)
                error_rate = summary.get('error_rate', 0)

                if speed_factor >= 1.0:
                    report_lines.append(f"✅ Real-time performance maintained: {speed_factor:.2f}x")
                else:
                    report_lines.append(f"⚠️ Below real-time performance: {speed_factor:.2f}x")

                if error_rate <= 0.05:
                    report_lines.append(f"✅ Low error rate achieved: {error_rate:.1%}")
                else:
                    report_lines.append(f"⚠️ Higher error rate: {error_rate:.1%}")

        if self.comparison_results:
            # Analyze comparison results
            report_lines.append("✅ Configuration comparison completed")

            for profile, comparison in self.comparison_results.items():
                if hasattr(comparison, 'regression_detected'):
                    if comparison.regression_detected:
                        report_lines.append(f"⚠️ Regression detected in {profile}")
                    else:
                        report_lines.append(f"✅ No regression in {profile}")

        report_lines.append("")

        # Performance Metrics
        report_lines.append("PERFORMANCE METRICS")
        report_lines.append("-" * 19)

        if self.test_results and 'baseline' in self.test_results:
            baseline = self.test_results['baseline']
            if 'summary' in baseline:
                summary = baseline['summary']

                # Speed metrics
                if 'speed_factor' in summary:
                    sf = summary['speed_factor']
                    report_lines.append(f"Transcription Speed:")
                    report_lines.append(f"  Average: {sf.get('mean', 0):.2f}x realtime")
                    report_lines.append(f"  Range: {sf.get('min', 0):.2f}x - {sf.get('max', 0):.2f}x")
                    report_lines.append(f"  Std Dev: {sf.get('std', 0):.2f}x")

                # Memory metrics
                if 'memory_usage' in summary:
                    mem = summary['memory_usage']
                    report_lines.append(f"Memory Usage:")
                    report_lines.append(f"  Average Growth: {mem.get('mean_growth_mb', 0):.1f}MB")
                    report_lines.append(f"  Maximum Growth: {mem.get('max_growth_mb', 0):.1f}MB")

                # Latency metrics
                if 'latency' in summary and summary['latency']:
                    lat = summary['latency']
                    report_lines.append(f"Latency:")
                    report_lines.append(f"  Average: {lat.get('mean_ms', 0):.0f}ms")
                    report_lines.append(f"  Maximum: {lat.get('max_ms', 0):.0f}ms")

                # Error metrics
                report_lines.append(f"Reliability:")
                report_lines.append(f"  Error Rate: {summary.get('error_rate', 0):.1%}")
                report_lines.append(f"  Total Tests: {summary.get('total_tests', 0)}")

        report_lines.append("")

        # Recommendations
        report_lines.append("RECOMMENDATIONS")
        report_lines.append("-" * 15)
        report_lines.append("Based on performance analysis:")
        report_lines.append("")

        if self.test_results and 'baseline' in self.test_results:
            baseline = self.test_results['baseline']
            if 'summary' in baseline:
                summary = baseline['summary']
                speed_factor = summary.get('speed_factor', {}).get('mean', 0)

                if speed_factor < 1.0:
                    report_lines.append("• Consider reducing model reload frequency to improve speed")
                    report_lines.append("• Evaluate trade-off between stability and performance")
                else:
                    report_lines.append("• Current configuration provides good balance of speed and stability")

                error_rate = summary.get('error_rate', 0)
                if error_rate > 0.05:
                    report_lines.append("• Investigate sources of transcription errors")
                else:
                    report_lines.append("• Stability improvements successfully reduced error rates")

        report_lines.append("• Monitor long-term stability in production usage")
        report_lines.append("• Consider gradual optimization of model reload triggers")
        report_lines.append("• Implement continuous performance monitoring")
        report_lines.append("")

        # File locations
        report_lines.append("DETAILED RESULTS")
        report_lines.append("-" * 16)
        report_lines.append(f"Test results directory: {self.output_dir / 'test_results'}")
        report_lines.append(f"Comparison results: {self.output_dir / 'comparison_results'}")
        report_lines.append(f"Interactive dashboards: {self.output_dir / 'dashboards'}")
        report_lines.append(f"Detailed reports: {self.output_dir / 'reports'}")

        report_text = "\n".join(report_lines)

        # Save final report
        final_report_file = self.output_dir / "reports" / "final_performance_analysis.txt"
        with open(final_report_file, 'w') as f:
            f.write(report_text)

        logger.info(f"Final report saved to {final_report_file}")
        return report_text

def main():
    """Main test runner function"""
    parser = argparse.ArgumentParser(description="VoiceFlow Performance Test Suite")
    parser.add_argument("--quick", action="store_true", help="Run quick tests only")
    parser.add_argument("--stress-duration", type=int, default=5, help="Stress test duration in minutes")
    parser.add_argument("--memory-cycles", type=int, default=30, help="Memory leak test cycles")
    parser.add_argument("--output-dir", type=str, default="performance_test_output", help="Output directory")
    parser.add_argument("--skip-gpu", action="store_true", help="Skip GPU tests even if available")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(Path(args.output_dir) / "test_execution.log")
        ]
    )

    logger.info("Starting VoiceFlow Performance Test Suite")
    logger.info(f"Output directory: {args.output_dir}")

    # Create test suite
    test_suite = PerformanceTestSuite(args.output_dir)

    try:
        # Run baseline performance tests
        logger.info("Phase 1: Baseline Performance Tests")
        baseline_results = test_suite.run_baseline_performance_tests()

        if not args.quick:
            # Run configuration comparison tests
            logger.info("Phase 2: Configuration Comparison Tests")
            comparison_results = test_suite.run_configuration_comparison_tests(test_iterations=3)

            # Run stability stress tests
            logger.info("Phase 3: Stability Stress Tests")
            stress_results = test_suite.run_stability_stress_tests(duration_minutes=args.stress_duration)

            # Run memory leak detection
            logger.info("Phase 4: Memory Leak Detection")
            memory_results = test_suite.run_memory_leak_detection(num_cycles=args.memory_cycles)

        # Generate dashboards
        logger.info("Phase 5: Dashboard Generation")
        test_suite.generate_performance_dashboards()

        # Generate final report
        logger.info("Phase 6: Final Report Generation")
        final_report = test_suite.generate_final_report()

        print("\n" + "="*60)
        print("PERFORMANCE TEST SUITE COMPLETED")
        print("="*60)
        print(final_report)

        logger.info("Performance test suite completed successfully")

    except Exception as e:
        logger.error(f"Performance test suite failed: {e}")
        raise

if __name__ == "__main__":
    main()