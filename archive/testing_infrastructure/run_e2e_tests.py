#!/usr/bin/env python3
"""
VoiceFlow Complete E2E Testing Suite
====================================

Master script for running the complete End-to-End testing suite.
Provides a unified interface for all E2E testing capabilities.

Usage:
    python run_e2e_tests.py [options]

This script integrates all E2E testing components:
- Environment validation
- Test execution
- Comprehensive reporting
- Health assessment
- Performance analysis
"""

import argparse
import sys
import subprocess
from pathlib import Path
from datetime import datetime

# Add tests directory to path
sys.path.insert(0, str(Path(__file__).parent / "tests"))

def main():
    """Main entry point for E2E testing."""
    parser = argparse.ArgumentParser(
        description='VoiceFlow Complete E2E Testing Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_e2e_tests.py                     # Run all E2E tests
    python run_e2e_tests.py --validate-only     # Only validate environment
    python run_e2e_tests.py --workflows         # Run workflow tests only
    python run_e2e_tests.py --report            # Generate comprehensive report
    python run_e2e_tests.py --health-check      # Run health check first
    python run_e2e_tests.py --fast              # Skip slow tests
    python run_e2e_tests.py --help              # Show detailed help

For more detailed options, use the dedicated test runner:
    python tests/run_e2e_tests.py --help
        """
    )
    
    # Main options
    parser.add_argument('--validate-only', action='store_true',
                       help='Only run environment validation')
    parser.add_argument('--workflows', action='store_true',
                       help='Run user workflow tests')
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
                       help='Generate comprehensive report')
    parser.add_argument('--health-check', action='store_true',
                       help='Run health check first')
    parser.add_argument('--parallel', action='store_true',
                       help='Run tests in parallel')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # If any specific category is selected, disable --all
    if any([args.workflows, args.system, args.implementations, 
            args.scenarios, args.validation]):
        args.all = False
    
    # Run validation only if requested
    if args.validate_only:
        return run_validation_only()
    
    # Run complete E2E testing
    return run_complete_e2e_testing(args)

def print_banner():
    """Print the testing banner."""
    print("=" * 80)
    print("🎯 VoiceFlow End-to-End Testing Suite")
    print("=" * 80)
    print(f"🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("🔍 Comprehensive system validation for real-world usage")
    print("=" * 80)

def run_validation_only():
    """Run only environment validation."""
    print("\n🔍 Running Environment Validation Only")
    print("-" * 50)
    
    try:
        result = subprocess.run([
            sys.executable, 
            'tests/test_e2e_validation.py'
        ], cwd=Path(__file__).parent)
        
        return result.returncode
        
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        return 1

def run_complete_e2e_testing(args):
    """Run complete E2E testing suite."""
    print("\n🚀 Running Complete E2E Testing Suite")
    print("-" * 50)
    
    # Build command for dedicated test runner
    cmd = [sys.executable, 'tests/run_e2e_tests.py']
    
    # Add category flags
    if args.workflows:
        cmd.append('--workflows')
    if args.system:
        cmd.append('--system')
    if args.implementations:
        cmd.append('--implementations')
    if args.scenarios:
        cmd.append('--scenarios')
    if args.validation:
        cmd.append('--validation')
    if args.all:
        cmd.append('--all')
    
    # Add execution options
    if args.fast:
        cmd.append('--fast')
    if args.verbose:
        cmd.append('--verbose')
    if args.report:
        cmd.append('--report')
    if args.health_check:
        cmd.append('--health-check')
    if args.parallel:
        cmd.append('--parallel')
    
    try:
        print(f"🔧 Running: {' '.join(cmd)}")
        print("-" * 50)
        
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        
        # Print completion message
        print("\n" + "=" * 80)
        if result.returncode == 0:
            print("✅ VoiceFlow E2E Testing Suite COMPLETED SUCCESSFULLY")
            print("🎉 All tests passed! Your VoiceFlow system is ready for production.")
        else:
            print("❌ VoiceFlow E2E Testing Suite COMPLETED WITH ISSUES")
            print("🔧 Please review the test results and address any failures.")
        
        print(f"🕐 Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        return result.returncode
        
    except Exception as e:
        print(f"❌ E2E testing failed: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())