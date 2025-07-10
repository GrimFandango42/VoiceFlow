#!/usr/bin/env python3
"""
Test runner for VoiceFlow unit tests.

This script provides a convenient way to run all tests with various options.
"""

import sys
import subprocess
from pathlib import Path

# Test categories
TEST_SUITES = {
    'core': 'tests/test_voiceflow_core.py',
    'ai': 'tests/test_ai_enhancement.py',
    'config': 'tests/test_config.py',
    'integration': 'tests/test_integration.py',
    'e2e': 'tests/test_end_to_end.py',
    'all': 'tests/'
}

# Common pytest options
PYTEST_BASE_ARGS = [
    '-v',  # Verbose output
    '--tb=short',  # Shorter traceback format
    '--strict-markers',  # Enforce marker declarations
    '--color=yes'  # Colored output
]


def print_usage():
    """Print usage information."""
    print("""
VoiceFlow Test Runner

Usage: python run_tests.py [suite] [options]

Test Suites:
  core         - Test core VoiceFlow engine functionality
  ai           - Test AI enhancement module
  config       - Test configuration management
  integration  - Test component integration
  e2e          - Test end-to-end user workflows
  all          - Run all tests (default)

Options:
  --coverage   - Generate coverage report
  --fast       - Skip slow tests
  --unit       - Run only unit tests (skip integration)
  --markers    - Show available test markers
  --failed     - Run only previously failed tests
  --pdb        - Drop into debugger on failures

Examples:
  python run_tests.py                    # Run all tests
  python run_tests.py core              # Run only core tests
  python run_tests.py e2e               # Run end-to-end tests
  python run_tests.py --coverage        # Run all tests with coverage
  python run_tests.py core --fast       # Run core tests, skip slow ones
  python run_tests.py --unit            # Run only unit tests
  
For comprehensive E2E testing, use the dedicated E2E test runner:
  python tests/run_e2e_tests.py         # Run all E2E tests with reporting
""")


def run_tests(suite='all', extra_args=None):
    """Run the specified test suite."""
    if extra_args is None:
        extra_args = []
    
    # Build pytest command
    cmd = [sys.executable, '-m', 'pytest'] + PYTEST_BASE_ARGS
    
    # Add test path
    test_path = TEST_SUITES.get(suite, TEST_SUITES['all'])
    cmd.append(test_path)
    
    # Add extra arguments
    cmd.extend(extra_args)
    
    # Print command
    print(f"\nRunning: {' '.join(cmd)}\n")
    
    # Run tests
    try:
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        return result.returncode
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        return 1
    except Exception as e:
        print(f"\nError running tests: {e}")
        return 1


def main():
    """Main entry point."""
    args = sys.argv[1:]
    
    if not args or '--help' in args or '-h' in args:
        print_usage()
        return 0
    
    # Parse arguments
    suite = 'all'
    extra_args = []
    
    # Check for test suite
    if args and args[0] in TEST_SUITES:
        suite = args[0]
        args = args[1:]
    
    # Process options
    for arg in args:
        if arg == '--coverage':
            extra_args.extend([
                '--cov=core',
                '--cov=utils',
                '--cov-report=html',
                '--cov-report=term-missing'
            ])
        elif arg == '--fast':
            extra_args.extend(['-m', 'not slow'])
        elif arg == '--unit':
            extra_args.extend(['-m', 'not integration'])
        elif arg == '--markers':
            extra_args.append('--markers')
        elif arg == '--failed':
            extra_args.append('--lf')
        elif arg == '--pdb':
            extra_args.append('--pdb')
        else:
            extra_args.append(arg)
    
    # Run tests
    return run_tests(suite, extra_args)


if __name__ == '__main__':
    sys.exit(main())