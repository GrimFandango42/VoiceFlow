"""
24-Hour Operation Test

Comprehensive stability test for VoiceFlow 24/7 operation.
Tests long-running stability, memory management, and error recovery.
"""

import pytest
import time
import threading
import logging
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any
import psutil

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from voiceflow.stability import (
    initialize_stability_system, shutdown_stability_system,
    get_session_manager, get_resource_pool, get_state_cleanup_manager
)

logger = logging.getLogger(__name__)

class StabilityTestResults:
    """Results tracking for stability tests"""

    def __init__(self):
        self.start_time = datetime.now()
        self.memory_snapshots: List[Dict] = []
        self.session_events: List[Dict] = []
        self.error_events: List[Dict] = []
        self.performance_metrics: Dict = {}
        self.test_duration_hours = 0.0
        self.success = False

    def add_memory_snapshot(self, snapshot: Dict):
        """Add memory usage snapshot"""
        snapshot['timestamp'] = datetime.now()
        self.memory_snapshots.append(snapshot)

    def add_session_event(self, event_type: str, details: Dict = None):
        """Add session lifecycle event"""
        event = {
            'timestamp': datetime.now(),
            'type': event_type,
            'details': details or {}
        }
        self.session_events.append(event)

    def add_error_event(self, error_type: str, error_msg: str, context: Dict = None):
        """Add error event"""
        event = {
            'timestamp': datetime.now(),
            'error_type': error_type,
            'message': error_msg,
            'context': context or {}
        }
        self.error_events.append(event)

    def finalize(self):
        """Finalize test results"""
        end_time = datetime.now()
        self.test_duration_hours = (end_time - self.start_time).total_seconds() / 3600

        # Calculate performance metrics
        if self.memory_snapshots:
            memory_values = [s['process_memory_mb'] for s in self.memory_snapshots]
            self.performance_metrics = {
                'memory_min_mb': min(memory_values),
                'memory_max_mb': max(memory_values),
                'memory_avg_mb': sum(memory_values) / len(memory_values),
                'memory_growth_mb': memory_values[-1] - memory_values[0],
                'total_sessions': len([e for e in self.session_events if e['type'] == 'session_start']),
                'total_errors': len(self.error_events),
                'error_rate_per_hour': len(self.error_events) / max(self.test_duration_hours, 0.1)
            }

        self.success = (
            self.test_duration_hours >= 23.0 and  # At least 23 hours
            self.performance_metrics.get('memory_growth_mb', 0) < 100 and  # <100MB growth
            self.performance_metrics.get('error_rate_per_hour', 0) < 1.0  # <1 error/hour
        )

    def generate_report(self) -> str:
        """Generate human-readable test report"""
        report = f"""
24-Hour Stability Test Report
{'='*50}

Test Duration: {self.test_duration_hours:.2f} hours
Test Status: {'PASS' if self.success else 'FAIL'}

Memory Performance:
- Initial Memory: {self.performance_metrics.get('memory_min_mb', 0):.1f} MB
- Peak Memory: {self.performance_metrics.get('memory_max_mb', 0):.1f} MB
- Average Memory: {self.performance_metrics.get('memory_avg_mb', 0):.1f} MB
- Memory Growth: {self.performance_metrics.get('memory_growth_mb', 0):.1f} MB

Session Management:
- Total Sessions: {self.performance_metrics.get('total_sessions', 0)}
- Average Session Duration: {self.test_duration_hours / max(self.performance_metrics.get('total_sessions', 1), 1):.2f} hours

Error Analysis:
- Total Errors: {self.performance_metrics.get('total_errors', 0)}
- Error Rate: {self.performance_metrics.get('error_rate_per_hour', 0):.2f} errors/hour

Success Criteria:
✓ Duration ≥ 23 hours: {self.test_duration_hours >= 23.0}
✓ Memory growth < 100MB: {self.performance_metrics.get('memory_growth_mb', 0) < 100}
✓ Error rate < 1/hour: {self.performance_metrics.get('error_rate_per_hour', 0) < 1.0}

Overall Result: {'PASS' if self.success else 'FAIL'}
"""
        return report

@pytest.fixture
def stability_system():
    """Initialize and cleanup stability system for testing"""
    components = initialize_stability_system()
    yield components
    shutdown_stability_system()

class Test24HourOperation:
    """24-hour stability test suite"""

    def test_basic_system_initialization(self, stability_system):
        """Test that all stability components initialize correctly"""
        assert 'session_manager' in stability_system
        assert 'resource_pool' in stability_system
        assert 'state_cleanup' in stability_system

        session_manager = stability_system['session_manager']
        resource_pool = stability_system['resource_pool']
        state_cleanup = stability_system['state_cleanup']

        # Test session manager
        session_id = session_manager.start_session()
        assert session_id is not None
        assert session_manager.get_session_state(session_id).name == 'ACTIVE'

        # Test resource pool status
        status = resource_pool.get_resource_status()
        assert 'timestamp' in status
        assert 'memory_usage' in status

        # Test cleanup manager
        cleanup_status = state_cleanup.get_cleanup_status()
        assert 'cleanup_state' in cleanup_status
        assert 'memory_usage_mb' in cleanup_status

        # Clean up
        session_manager.end_session(session_id, force=True)

    def test_memory_stability_30_minutes(self, stability_system):
        """Test memory stability over 30 minutes"""
        results = StabilityTestResults()
        session_manager = stability_system['session_manager']
        resource_pool = stability_system['resource_pool']

        logger.info("Starting 30-minute memory stability test")

        try:
            # Start initial session
            session_id = session_manager.start_session()
            results.add_session_event('session_start', {'session_id': str(session_id)})

            # Run for 30 minutes with periodic memory checks
            test_duration = 30 * 60  # 30 minutes in seconds
            check_interval = 60  # Check every minute
            start_time = time.time()

            while (time.time() - start_time) < test_duration:
                try:
                    # Record memory snapshot
                    memory_usage = resource_pool.get_memory_usage()
                    results.add_memory_snapshot(memory_usage)

                    # Record activity to prevent idle timeout
                    session_manager.record_activity(session_id)

                    # Check health
                    health_score = session_manager.check_health(session_id)
                    if health_score < 0.7:
                        results.add_error_event('low_health', f'Health score: {health_score}')

                    # Wait for next check
                    time.sleep(check_interval)

                except Exception as e:
                    results.add_error_event('test_exception', str(e))
                    logger.error(f"Test error: {e}")

            # End session
            session_manager.end_session(session_id, force=True)
            results.add_session_event('session_end', {'session_id': str(session_id)})

        except Exception as e:
            results.add_error_event('test_failure', str(e))
            logger.error(f"Test failed: {e}")

        finally:
            results.finalize()

        # Validate results
        assert results.test_duration_hours >= 0.45  # At least 27 minutes
        assert results.performance_metrics['memory_growth_mb'] < 200  # <200MB growth for 30min test
        assert results.performance_metrics['error_rate_per_hour'] < 5  # <5 errors/hour for short test

        logger.info(f"30-minute test completed: {results.generate_report()}")

    @pytest.mark.slow
    def test_full_24_hour_operation(self, stability_system):
        """Full 24-hour stability test - requires pytest -m slow"""
        results = StabilityTestResults()
        session_manager = stability_system['session_manager']
        resource_pool = stability_system['resource_pool']
        state_cleanup = stability_system['state_cleanup']

        logger.info("Starting full 24-hour stability test")

        try:
            # Test parameters
            test_duration = 24 * 60 * 60  # 24 hours in seconds
            session_cycle_time = 30 * 60  # New session every 30 minutes
            memory_check_interval = 5 * 60  # Memory check every 5 minutes
            cleanup_trigger_interval = 2 * 60 * 60  # Force cleanup every 2 hours

            start_time = time.time()
            next_session_cycle = start_time + session_cycle_time
            next_memory_check = start_time + memory_check_interval
            next_cleanup = start_time + cleanup_trigger_interval

            current_session_id = None

            while (time.time() - start_time) < test_duration:
                current_time = time.time()

                try:
                    # Session lifecycle management
                    if current_time >= next_session_cycle:
                        # End current session
                        if current_session_id:
                            session_manager.end_session(current_session_id, force=True)
                            results.add_session_event('session_end', {'session_id': str(current_session_id)})

                        # Start new session
                        current_session_id = session_manager.start_session()
                        results.add_session_event('session_start', {'session_id': str(current_session_id)})
                        next_session_cycle = current_time + session_cycle_time

                    # Memory monitoring
                    if current_time >= next_memory_check:
                        memory_usage = resource_pool.get_memory_usage()
                        results.add_memory_snapshot(memory_usage)

                        # Check for memory pressure
                        if memory_usage['process_memory_mb'] > 1500:  # >1.5GB
                            results.add_error_event('high_memory', f"Memory: {memory_usage['process_memory_mb']:.1f}MB")

                        next_memory_check = current_time + memory_check_interval

                    # Periodic cleanup
                    if current_time >= next_cleanup:
                        cleanup_result = state_cleanup.cleanup_all_components()
                        results.add_session_event('cleanup_triggered', {'result': cleanup_result})
                        next_cleanup = current_time + cleanup_trigger_interval

                    # Record activity if session active
                    if current_session_id:
                        session_manager.record_activity(current_session_id)

                        # Health monitoring
                        health_score = session_manager.check_health(current_session_id)
                        if health_score < 0.5:
                            results.add_error_event('critical_health', f'Health: {health_score:.2f}')

                    # Sleep until next check
                    time.sleep(30)  # Check every 30 seconds

                except Exception as e:
                    results.add_error_event('test_exception', str(e))
                    logger.error(f"Test iteration error: {e}")
                    time.sleep(60)  # Longer sleep on error

            # Final cleanup
            if current_session_id:
                session_manager.end_session(current_session_id, force=True)
                results.add_session_event('session_end', {'session_id': str(current_session_id)})

        except Exception as e:
            results.add_error_event('test_failure', str(e))
            logger.error(f"24-hour test failed: {e}")

        finally:
            results.finalize()

        # Save detailed results
        report = results.generate_report()
        with open(f'stability_test_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json', 'w') as f:
            import json
            json.dump({
                'results': results.__dict__,
                'report': report
            }, f, indent=2, default=str)

        # Validate 24-hour success criteria
        assert results.success, f"24-hour test failed:\n{report}"

        logger.info(f"24-hour test completed successfully: {report}")

    def test_error_recovery_scenarios(self, stability_system):
        """Test error recovery under various failure conditions"""
        session_manager = stability_system['session_manager']
        resource_pool = stability_system['resource_pool']
        state_cleanup = stability_system['state_cleanup']

        # Test 1: Memory pressure recovery
        logger.info("Testing memory pressure recovery")
        initial_memory = resource_pool.get_memory_usage()

        # Force memory cleanup
        cleanup_result = resource_pool.force_memory_cleanup()
        assert cleanup_result['success']

        # Verify memory was freed
        post_cleanup_memory = resource_pool.get_memory_usage()
        assert post_cleanup_memory['process_memory_mb'] <= initial_memory['process_memory_mb']

        # Test 2: Session recovery
        logger.info("Testing session recovery")
        session_id = session_manager.start_session()

        # Simulate session degradation
        for _ in range(5):
            session_manager.record_transcription(1.0, 0.5, success=False, error_info="test error")

        # Check that recovery was triggered
        health_score = session_manager.check_health(session_id)
        assert health_score < 1.0  # Health should be degraded

        # Wait for potential recovery
        time.sleep(2)

        # Verify system is still functional
        new_session_id = session_manager.start_session()
        assert new_session_id != session_id

        session_manager.end_session(new_session_id, force=True)

        # Test 3: State cleanup recovery
        logger.info("Testing state cleanup recovery")
        cleanup_status_before = state_cleanup.get_cleanup_status()

        # Force comprehensive cleanup
        cleanup_result = state_cleanup.force_memory_cleanup()
        assert cleanup_result['success']

        cleanup_status_after = state_cleanup.get_cleanup_status()
        assert cleanup_status_after['memory_usage_mb'] <= cleanup_status_before['memory_usage_mb']

if __name__ == "__main__":
    """Run stability tests directly"""
    import argparse

    parser = argparse.ArgumentParser(description='VoiceFlow Stability Tests')
    parser.add_argument('--test', choices=['basic', '30min', '24hour', 'recovery'],
                       default='basic', help='Test to run')
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize stability system
    components = initialize_stability_system()

    try:
        test_instance = Test24HourOperation()

        if args.test == 'basic':
            test_instance.test_basic_system_initialization(components)
            print("✓ Basic initialization test passed")

        elif args.test == '30min':
            test_instance.test_memory_stability_30_minutes(components)
            print("✓ 30-minute stability test passed")

        elif args.test == '24hour':
            test_instance.test_full_24_hour_operation(components)
            print("✓ 24-hour stability test passed")

        elif args.test == 'recovery':
            test_instance.test_error_recovery_scenarios(components)
            print("✓ Error recovery test passed")

    finally:
        shutdown_stability_system()