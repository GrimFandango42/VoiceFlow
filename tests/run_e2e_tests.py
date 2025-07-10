#!/usr/bin/env python3
"""
VoiceFlow End-to-End Test Runner
===============================

Comprehensive test runner for end-to-end system testing.
Provides detailed reporting and validation of complete user workflows.

Usage:
    python run_e2e_tests.py [options]
    
Options:
    --workflows      Run complete user workflow tests
    --system         Run system-level tests  
    --implementations Run implementation path tests
    --scenarios      Run real-world scenario tests
    --validation     Run validation tests
    --all            Run all E2E tests (default)
    --fast           Skip slow tests
    --verbose        Verbose output
    --report         Generate detailed HTML report
    --parallel       Run tests in parallel (where safe)
    --health-check   Run system health validation first
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import tempfile
import shutil

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Test categories and their corresponding test classes
TEST_CATEGORIES = {
    'workflows': 'TestCompleteUserWorkflows',
    'system': 'TestSystemLevelTesting', 
    'implementations': 'TestImplementationPaths',
    'scenarios': 'TestRealWorldScenarios',
    'validation': 'TestValidationTesting'
}

# Test markers for filtering
TEST_MARKERS = {
    'fast': 'not slow',
    'integration': 'integration',
    'e2e': 'e2e',
    'requires_audio': 'requires_audio',
    'requires_ollama': 'requires_ollama'
}


class E2ETestRunner:
    """End-to-End Test Runner with comprehensive reporting."""
    
    def __init__(self, args):
        self.args = args
        self.start_time = datetime.now()
        self.results = {}
        self.temp_dir = None
        self.report_dir = Path.cwd() / "e2e_test_reports"
        self.report_dir.mkdir(exist_ok=True)
        
    def run_health_check(self) -> bool:
        """Run system health check before main tests."""
        print("🏥 Running system health check...")
        
        health_checks = [
            self._check_python_version,
            self._check_dependencies,
            self._check_project_structure,
            self._check_permissions,
            self._check_test_environment
        ]
        
        failed_checks = []
        for check in health_checks:
            try:
                check_name = check.__name__.replace('_check_', '').replace('_', ' ').title()
                print(f"  📋 {check_name}...", end=' ')
                
                result = check()
                if result:
                    print("✅")
                else:
                    print("❌")
                    failed_checks.append(check_name)
                    
            except Exception as e:
                print(f"❌ ({e})")
                failed_checks.append(check_name)
        
        if failed_checks:
            print(f"\n❌ Health check failed: {', '.join(failed_checks)}")
            print("Please resolve these issues before running E2E tests.")
            return False
        
        print("✅ System health check passed!")
        return True
    
    def _check_python_version(self) -> bool:
        """Check Python version compatibility."""
        return sys.version_info >= (3, 7)
    
    def _check_dependencies(self) -> bool:
        """Check that required dependencies are available."""
        required_packages = [
            'pytest', 'sqlite3', 'pathlib', 'threading', 'json', 'tempfile'
        ]
        
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                return False
        return True
    
    def _check_project_structure(self) -> bool:
        """Check that project structure is correct."""
        project_root = Path(__file__).parent.parent
        required_paths = [
            project_root / "core",
            project_root / "utils",
            project_root / "implementations",
            project_root / "tests",
            project_root / "tests" / "test_end_to_end.py"
        ]
        
        return all(path.exists() for path in required_paths)
    
    def _check_permissions(self) -> bool:
        """Check that we have necessary permissions."""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                test_file = Path(temp_dir) / "test.txt"
                test_file.write_text("test")
                return test_file.read_text() == "test"
        except Exception:
            return False
    
    def _check_test_environment(self) -> bool:
        """Check that test environment can be set up."""
        try:
            # Try to import test modules
            from tests.test_end_to_end import E2ETestEnvironment
            
            # Try to create test environment
            with tempfile.TemporaryDirectory() as temp_dir:
                env = E2ETestEnvironment(Path(temp_dir))
                env.setup_configuration({"test": True})
                return True
        except Exception:
            return False
    
    def run_tests(self) -> Dict[str, Any]:
        """Run the specified test categories."""
        print(f"🚀 Starting VoiceFlow E2E Tests - {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Determine which tests to run
        test_categories = self._get_test_categories()
        
        if not test_categories:
            print("❌ No test categories selected!")
            return {'success': False, 'error': 'No test categories selected'}
        
        print(f"📋 Running test categories: {', '.join(test_categories)}")
        
        # Run health check if requested
        if self.args.health_check:
            if not self.run_health_check():
                return {'success': False, 'error': 'Health check failed'}
        
        # Build pytest command
        pytest_cmd = self._build_pytest_command(test_categories)
        
        # Run tests
        print(f"\n🔧 Running command: {' '.join(pytest_cmd)}")
        print("-" * 60)
        
        try:
            result = subprocess.run(
                pytest_cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            # Parse results
            self.results = self._parse_pytest_results(result)
            
            # Generate report
            if self.args.report:
                self._generate_report()
            
            return self.results
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Tests timed out after 1 hour'}
        except Exception as e:
            return {'success': False, 'error': f'Test execution failed: {e}'}
    
    def _get_test_categories(self) -> List[str]:
        """Determine which test categories to run."""
        if self.args.all:
            return list(TEST_CATEGORIES.keys())
        
        categories = []
        for category in TEST_CATEGORIES.keys():
            if getattr(self.args, category, False):
                categories.append(category)
        
        return categories if categories else ['workflows']  # Default to workflows
    
    def _build_pytest_command(self, test_categories: List[str]) -> List[str]:
        """Build pytest command with appropriate options."""
        cmd = [
            sys.executable, '-m', 'pytest',
            'tests/test_end_to_end.py',
            '-v',
            '--tb=short',
            '--strict-markers',
            '--color=yes'
        ]
        
        # Add test class filters
        if len(test_categories) < len(TEST_CATEGORIES):
            class_filters = [TEST_CATEGORIES[cat] for cat in test_categories]
            for class_filter in class_filters:
                cmd.extend(['-k', class_filter])
        
        # Add marker filters
        markers = []
        if self.args.fast:
            markers.append(TEST_MARKERS['fast'])
        
        if markers:
            cmd.extend(['-m', ' and '.join(markers)])
        
        # Add reporting options
        if self.args.report:
            report_file = self.report_dir / f"e2e_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            cmd.extend([
                '--html', str(report_file),
                '--self-contained-html'
            ])
        
        # Add parallel execution
        if self.args.parallel:
            cmd.extend(['-n', 'auto'])
        
        # Add verbosity
        if self.args.verbose:
            cmd.append('-s')
        
        # Add coverage if requested
        if self.args.report:
            cmd.extend([
                '--cov=core',
                '--cov=utils',
                '--cov=implementations',
                '--cov-report=html:' + str(self.report_dir / 'coverage')
            ])
        
        return cmd
    
    def _parse_pytest_results(self, result: subprocess.CompletedProcess) -> Dict[str, Any]:
        """Parse pytest results and extract metrics."""
        output = result.stdout + result.stderr
        
        # Basic result parsing
        success = result.returncode == 0
        
        # Extract test counts (simple parsing)
        passed = output.count(' PASSED')
        failed = output.count(' FAILED')
        errors = output.count(' ERROR')
        skipped = output.count(' SKIPPED')
        
        # Extract timing information
        lines = output.split('\n')
        duration = 0
        for line in lines:
            if 'seconds' in line and '====' in line:
                try:
                    # Extract duration from pytest summary
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if 'seconds' in part and i > 0:
                            duration = float(parts[i-1])
                            break
                except (ValueError, IndexError):
                    pass
        
        return {
            'success': success,
            'passed': passed,
            'failed': failed,
            'errors': errors,
            'skipped': skipped,
            'total': passed + failed + errors + skipped,
            'duration': duration,
            'output': output,
            'command': result.args if hasattr(result, 'args') else [],
            'timestamp': datetime.now().isoformat()
        }
    
    def _generate_report(self):
        """Generate comprehensive test report."""
        print(f"\n📊 Generating comprehensive test report...")
        
        # Create report data
        report_data = {
            'metadata': {
                'timestamp': self.start_time.isoformat(),
                'duration': (datetime.now() - self.start_time).total_seconds(),
                'arguments': vars(self.args),
                'system_info': {
                    'python_version': sys.version,
                    'platform': sys.platform,
                    'cwd': str(Path.cwd())
                }
            },
            'results': self.results
        }
        
        # Save JSON report
        json_report = self.report_dir / f"e2e_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_report, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"📄 Report saved to: {json_report}")
        
        # Generate summary
        self._print_summary()
    
    def _print_summary(self):
        """Print test execution summary."""
        print("\n" + "=" * 60)
        print("🎯 VoiceFlow E2E Test Summary")
        print("=" * 60)
        
        if not self.results:
            print("❌ No results to display")
            return
        
        # Overall status
        status = "✅ PASSED" if self.results['success'] else "❌ FAILED"
        print(f"Status: {status}")
        
        # Test counts
        print(f"Tests Run: {self.results['total']}")
        print(f"  ✅ Passed: {self.results['passed']}")
        print(f"  ❌ Failed: {self.results['failed']}")
        print(f"  ⚠️  Errors: {self.results['errors']}")
        print(f"  ⏭️  Skipped: {self.results['skipped']}")
        
        # Duration
        duration = self.results.get('duration', 0)
        print(f"Duration: {duration:.2f} seconds")
        
        # Success rate
        if self.results['total'] > 0:
            success_rate = (self.results['passed'] / self.results['total']) * 100
            print(f"Success Rate: {success_rate:.1f}%")
        
        # Health assessment
        self._print_health_assessment()
        
        print("=" * 60)
    
    def _print_health_assessment(self):
        """Print system health assessment based on test results."""
        if not self.results['total']:
            return
        
        success_rate = (self.results['passed'] / self.results['total']) * 100
        
        if success_rate >= 95:
            health = "🟢 EXCELLENT"
            message = "All systems working optimally"
        elif success_rate >= 80:
            health = "🟡 GOOD"
            message = "Minor issues detected but system is functional"
        elif success_rate >= 60:
            health = "🟠 FAIR"
            message = "Some components may not be working properly"
        else:
            health = "🔴 POOR"
            message = "Major issues detected in system integration"
        
        print(f"\nSystem Health: {health}")
        print(f"Assessment: {message}")
        
        # Recommendations
        if self.results['failed'] > 0:
            print("\nRecommendations:")
            print("• Review failed tests for component integration issues")
            print("• Check system dependencies and configuration")
            print("• Verify external service connectivity")
            print("• Run individual test categories to isolate issues")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='VoiceFlow End-to-End Test Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Test category options
    parser.add_argument('--workflows', action='store_true',
                       help='Run complete user workflow tests')
    parser.add_argument('--system', action='store_true',
                       help='Run system-level tests')
    parser.add_argument('--implementations', action='store_true',
                       help='Run implementation path tests')
    parser.add_argument('--scenarios', action='store_true',
                       help='Run real-world scenario tests')
    parser.add_argument('--validation', action='store_true',
                       help='Run validation tests')
    parser.add_argument('--all', action='store_true', default=True,
                       help='Run all E2E tests (default)')
    
    # Execution options
    parser.add_argument('--fast', action='store_true',
                       help='Skip slow tests')
    parser.add_argument('--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--report', action='store_true',
                       help='Generate detailed HTML report')
    parser.add_argument('--parallel', action='store_true',
                       help='Run tests in parallel (where safe)')
    parser.add_argument('--health-check', action='store_true',
                       help='Run system health validation first')
    
    args = parser.parse_args()
    
    # If any specific category is selected, disable --all
    if any([args.workflows, args.system, args.implementations, 
            args.scenarios, args.validation]):
        args.all = False
    
    # Run tests
    runner = E2ETestRunner(args)
    results = runner.run_tests()
    
    # Exit with appropriate code
    sys.exit(0 if results.get('success', False) else 1)


if __name__ == '__main__':
    main()