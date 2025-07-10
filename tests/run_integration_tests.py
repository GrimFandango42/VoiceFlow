#!/usr/bin/env python3
"""
Comprehensive Integration Test Runner for VoiceFlow

This script runs all integration tests and provides detailed reporting
on the health and integration status of the VoiceFlow system.
"""

import sys
import subprocess
import argparse
import time
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class IntegrationTestRunner:
    """Comprehensive integration test runner for VoiceFlow system."""
    
    def __init__(self, verbose: bool = False, parallel: bool = False):
        self.verbose = verbose
        self.parallel = parallel
        self.results = {}
        self.start_time = None
        self.end_time = None
        
        # Test categories and their priorities
        self.test_categories = {
            'component_integration': {
                'priority': 1,
                'description': 'Core component integration tests',
                'tests': [
                    'test_comprehensive_integration.py::TestComponentIntegration',
                ],
                'timeout': 300
            },
            'end_to_end_workflows': {
                'priority': 2,
                'description': 'End-to-end workflow tests',
                'tests': [
                    'test_comprehensive_integration.py::TestEndToEndWorkflows',
                ],
                'timeout': 300
            },
            'implementation_integration': {
                'priority': 3,
                'description': 'Implementation integration tests',
                'tests': [
                    'test_comprehensive_integration.py::TestImplementationIntegration',
                ],
                'timeout': 180
            },
            'server_integration': {
                'priority': 4,
                'description': 'Server integration tests',
                'tests': [
                    'test_server_integration.py::TestMCPServerIntegration',
                    'test_server_integration.py::TestWebSocketIntegration',
                    'test_server_integration.py::TestServerCommunication',
                ],
                'timeout': 240
            },
            'system_integration': {
                'priority': 5,
                'description': 'System-level integration tests',
                'tests': [
                    'test_comprehensive_integration.py::TestSystemIntegration',
                ],
                'timeout': 180
            },
            'failure_modes': {
                'priority': 6,
                'description': 'Failure mode and resilience tests',
                'tests': [
                    'test_comprehensive_integration.py::TestFailureModes',
                    'test_server_integration.py::TestServerFailureModes',
                ],
                'timeout': 300
            },
            'existing_integration': {
                'priority': 7,
                'description': 'Existing integration tests',
                'tests': [
                    'test_integration.py',
                ],
                'timeout': 240
            }
        }
    
    def run_all_tests(self, categories: Optional[List[str]] = None) -> Dict[str, any]:
        """Run all integration tests or specific categories."""
        self.start_time = datetime.now()
        
        print("=" * 80)
        print("VoiceFlow Integration Test Suite")
        print("=" * 80)
        print(f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Determine which categories to run
        if categories is None:
            categories = list(self.test_categories.keys())
        
        # Sort categories by priority
        sorted_categories = sorted(
            [cat for cat in categories if cat in self.test_categories],
            key=lambda x: self.test_categories[x]['priority']
        )
        
        # Run test categories
        for category in sorted_categories:
            self._run_category(category)
        
        self.end_time = datetime.now()
        return self._generate_report()
    
    def _run_category(self, category: str) -> None:
        """Run tests for a specific category."""
        category_info = self.test_categories[category]
        
        print(f"Running {category.replace('_', ' ').title()}")
        print(f"Description: {category_info['description']}")
        print("-" * 60)
        
        category_results = {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'skipped': 0,
            'errors': 0,
            'duration': 0,
            'test_results': []
        }
        
        for test_path in category_info['tests']:
            result = self._run_single_test(test_path, category_info['timeout'])
            category_results['test_results'].append(result)
            
            # Update counters
            category_results['total_tests'] += result['total']
            category_results['passed'] += result['passed']
            category_results['failed'] += result['failed']
            category_results['skipped'] += result['skipped']
            category_results['errors'] += result['errors']
            category_results['duration'] += result['duration']
        
        self.results[category] = category_results
        
        # Print category summary
        print(f"\nCategory Summary:")
        print(f"  Total: {category_results['total_tests']}")
        print(f"  Passed: {category_results['passed']}")
        print(f"  Failed: {category_results['failed']}")
        print(f"  Skipped: {category_results['skipped']}")
        print(f"  Errors: {category_results['errors']}")
        print(f"  Duration: {category_results['duration']:.2f}s")
        print()
    
    def _run_single_test(self, test_path: str, timeout: int) -> Dict[str, any]:
        """Run a single test and return results."""
        print(f"  Running: {test_path}")
        
        # Build pytest command
        cmd = [
            sys.executable, '-m', 'pytest',
            test_path,
            '-v',
            '--tb=short',
            '--disable-warnings',
            '-m', 'integration',
            '--json-report',
            '--json-report-file=test_report.json'
        ]
        
        if self.verbose:
            cmd.append('-s')
        
        # Run test
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=Path(__file__).parent
            )
            duration = time.time() - start_time
            
            # Parse JSON report if available
            report_file = Path(__file__).parent / 'test_report.json'
            if report_file.exists():
                try:
                    with open(report_file, 'r') as f:
                        json_report = json.load(f)
                    
                    test_result = {
                        'test_path': test_path,
                        'total': json_report['summary']['total'],
                        'passed': json_report['summary']['passed'],
                        'failed': json_report['summary']['failed'],
                        'skipped': json_report['summary']['skipped'],
                        'errors': json_report['summary']['error'],
                        'duration': duration,
                        'return_code': result.returncode,
                        'stdout': result.stdout if self.verbose else '',
                        'stderr': result.stderr if result.stderr else ''
                    }
                    
                    # Clean up report file
                    report_file.unlink()
                    
                except Exception as e:
                    print(f"    Warning: Could not parse JSON report: {e}")
                    test_result = self._parse_text_output(test_path, result, duration)
            else:
                test_result = self._parse_text_output(test_path, result, duration)
            
            # Print result
            if test_result['return_code'] == 0:
                print(f"    ✅ PASSED ({test_result['passed']}/{test_result['total']}) in {duration:.2f}s")
            else:
                print(f"    ❌ FAILED ({test_result['failed']}/{test_result['total']}) in {duration:.2f}s")
                if test_result['stderr']:
                    print(f"    Error: {test_result['stderr'][:200]}...")
            
            return test_result
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            print(f"    ⏰ TIMEOUT after {duration:.2f}s")
            return {
                'test_path': test_path,
                'total': 0,
                'passed': 0,
                'failed': 1,
                'skipped': 0,
                'errors': 0,
                'duration': duration,
                'return_code': -1,
                'stdout': '',
                'stderr': 'Test timed out'
            }
        
        except Exception as e:
            duration = time.time() - start_time
            print(f"    💥 ERROR: {e}")
            return {
                'test_path': test_path,
                'total': 0,
                'passed': 0,
                'failed': 0,
                'skipped': 0,
                'errors': 1,
                'duration': duration,
                'return_code': -1,
                'stdout': '',
                'stderr': str(e)
            }
    
    def _parse_text_output(self, test_path: str, result: subprocess.CompletedProcess, duration: float) -> Dict[str, any]:
        """Parse pytest text output when JSON report is not available."""
        output = result.stdout
        
        # Simple parsing of pytest output
        passed = output.count(' PASSED')
        failed = output.count(' FAILED')
        skipped = output.count(' SKIPPED')
        errors = output.count(' ERROR')
        total = passed + failed + skipped + errors
        
        return {
            'test_path': test_path,
            'total': total,
            'passed': passed,
            'failed': failed,
            'skipped': skipped,
            'errors': errors,
            'duration': duration,
            'return_code': result.returncode,
            'stdout': output if self.verbose else '',
            'stderr': result.stderr if result.stderr else ''
        }
    
    def _generate_report(self) -> Dict[str, any]:
        """Generate comprehensive test report."""
        total_duration = (self.end_time - self.start_time).total_seconds()
        
        # Calculate overall statistics
        overall_stats = {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'skipped': 0,
            'errors': 0,
            'duration': total_duration,
            'success_rate': 0
        }
        
        for category_results in self.results.values():
            overall_stats['total_tests'] += category_results['total_tests']
            overall_stats['passed'] += category_results['passed']
            overall_stats['failed'] += category_results['failed']
            overall_stats['skipped'] += category_results['skipped']
            overall_stats['errors'] += category_results['errors']
        
        if overall_stats['total_tests'] > 0:
            overall_stats['success_rate'] = (overall_stats['passed'] / overall_stats['total_tests']) * 100
        
        # Generate report
        report = {
            'timestamp': self.end_time.isoformat(),
            'duration': total_duration,
            'overall_stats': overall_stats,
            'categories': self.results,
            'summary': self._generate_summary()
        }
        
        # Print report
        self._print_report(report)
        
        return report
    
    def _generate_summary(self) -> str:
        """Generate human-readable summary."""
        summary_lines = []
        
        # Overall status
        total_tests = sum(cat['total_tests'] for cat in self.results.values())
        total_passed = sum(cat['passed'] for cat in self.results.values())
        total_failed = sum(cat['failed'] for cat in self.results.values())
        total_errors = sum(cat['errors'] for cat in self.results.values())
        
        if total_failed + total_errors == 0:
            summary_lines.append("🎉 ALL TESTS PASSED - VoiceFlow integration is healthy!")
        elif total_failed + total_errors < total_tests * 0.1:  # Less than 10% failure
            summary_lines.append("✅ MOSTLY PASSING - Minor issues detected")
        elif total_failed + total_errors < total_tests * 0.3:  # Less than 30% failure
            summary_lines.append("⚠️  SOME FAILURES - Attention required")
        else:
            summary_lines.append("❌ SIGNIFICANT FAILURES - Integration issues detected")
        
        # Category breakdown
        summary_lines.append("\nCategory Status:")
        for category, results in self.results.items():
            category_name = category.replace('_', ' ').title()
            if results['failed'] + results['errors'] == 0:
                status = "✅ PASS"
            else:
                status = "❌ FAIL"
            
            summary_lines.append(f"  {status} {category_name}: {results['passed']}/{results['total_tests']}")
        
        return "\n".join(summary_lines)
    
    def _print_report(self, report: Dict[str, any]) -> None:
        """Print comprehensive test report."""
        print("=" * 80)
        print("INTEGRATION TEST REPORT")
        print("=" * 80)
        print(f"Completed: {self.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Duration: {report['duration']:.2f}s")
        print()
        
        # Overall statistics
        stats = report['overall_stats']
        print("Overall Statistics:")
        print(f"  Total Tests: {stats['total_tests']}")
        print(f"  Passed: {stats['passed']}")
        print(f"  Failed: {stats['failed']}")
        print(f"  Skipped: {stats['skipped']}")
        print(f"  Errors: {stats['errors']}")
        print(f"  Success Rate: {stats['success_rate']:.1f}%")
        print()
        
        # Summary
        print(report['summary'])
        print()
        
        # Failed tests details
        failed_tests = []
        for category, results in self.results.items():
            for test_result in results['test_results']:
                if test_result['failed'] > 0 or test_result['errors'] > 0:
                    failed_tests.append((category, test_result))
        
        if failed_tests:
            print("Failed Tests:")
            for category, test_result in failed_tests:
                print(f"  ❌ {test_result['test_path']}")
                if test_result['stderr']:
                    print(f"     Error: {test_result['stderr'][:100]}...")
            print()
        
        # Integration health assessment
        print("Integration Health Assessment:")
        self._assess_integration_health(report)
    
    def _assess_integration_health(self, report: Dict[str, any]) -> None:
        """Assess overall integration health and provide recommendations."""
        stats = report['overall_stats']
        
        health_score = stats['success_rate']
        
        if health_score >= 95:
            print("  🟢 EXCELLENT - Integration is very healthy")
            print("     All core components are working together properly")
        elif health_score >= 80:
            print("  🟡 GOOD - Integration is mostly healthy")
            print("     Minor issues may exist but system is functional")
        elif health_score >= 60:
            print("  🟠 FAIR - Integration has some issues")
            print("     Some components may not be working together properly")
        else:
            print("  🔴 POOR - Integration has significant issues")
            print("     Major problems detected in component interactions")
        
        # Specific recommendations
        print("\nRecommendations:")
        
        # Check critical categories
        critical_categories = ['component_integration', 'end_to_end_workflows']
        for category in critical_categories:
            if category in self.results:
                results = self.results[category]
                if results['failed'] + results['errors'] > 0:
                    print(f"  - Fix {category.replace('_', ' ')} issues (critical)")
        
        # Check for specific failure patterns
        if 'failure_modes' in self.results:
            failure_results = self.results['failure_modes']
            if failure_results['failed'] > failure_results['passed']:
                print("  - Review error handling and resilience mechanisms")
        
        if 'server_integration' in self.results:
            server_results = self.results['server_integration']
            if server_results['failed'] + server_results['errors'] > 0:
                print("  - Check server communication and MCP integration")
        
        if stats['skipped'] > stats['total_tests'] * 0.2:
            print("  - Review skipped tests - some may indicate missing dependencies")
        
        print()
    
    def save_report(self, filename: str) -> None:
        """Save test report to file."""
        if not self.results:
            print("No test results to save")
            return
        
        report = {
            'timestamp': self.end_time.isoformat(),
            'duration': (self.end_time - self.start_time).total_seconds(),
            'results': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Report saved to: {filename}")


def main():
    """Main entry point for integration test runner."""
    parser = argparse.ArgumentParser(description='Run VoiceFlow integration tests')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--parallel', '-p', action='store_true', help='Run tests in parallel')
    parser.add_argument('--categories', '-c', nargs='+', help='Specific test categories to run')
    parser.add_argument('--report', '-r', help='Save report to file')
    parser.add_argument('--list-categories', action='store_true', help='List available test categories')
    
    args = parser.parse_args()
    
    runner = IntegrationTestRunner(verbose=args.verbose, parallel=args.parallel)
    
    if args.list_categories:
        print("Available test categories:")
        for category, info in runner.test_categories.items():
            print(f"  {category}: {info['description']}")
        return
    
    # Run tests
    try:
        report = runner.run_all_tests(args.categories)
        
        if args.report:
            runner.save_report(args.report)
        
        # Exit with appropriate code
        overall_stats = report['overall_stats']
        if overall_stats['failed'] + overall_stats['errors'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\nTest run interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error running tests: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()