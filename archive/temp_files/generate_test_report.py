#!/usr/bin/env python3
"""
Generate a comprehensive test report for VoiceFlow unit tests.
"""

import subprocess
import sys
import json
import os
from pathlib import Path
from datetime import datetime


def run_command(cmd):
    """Run a command and return output."""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent
        )
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return "", str(e), 1


def generate_test_report():
    """Generate comprehensive test report."""
    print("=" * 80)
    print("VoiceFlow Unit Test Report")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    print()
    
    # Count test files
    test_files = list(Path("tests").glob("test_*.py"))
    print(f"Test Files Found: {len(test_files)}")
    for f in sorted(test_files):
        print(f"  - {f.name}")
    print()
    
    # Run tests with different configurations
    test_configs = [
        ("All Tests", "python -m pytest tests/ -v --tb=short -q"),
        ("Unit Tests Only", "python -m pytest tests/ -m 'not integration' -v --tb=short -q"),
        ("Integration Tests", "python -m pytest tests/ -m integration -v --tb=short -q"),
        ("Fast Tests", "python -m pytest tests/ -m 'not slow' -v --tb=short -q"),
    ]
    
    for name, cmd in test_configs:
        print(f"\n{name}:")
        print("-" * len(name))
        stdout, stderr, code = run_command(cmd)
        
        # Extract summary
        for line in stdout.split('\n'):
            if 'passed' in line or 'failed' in line or 'error' in line:
                print(f"  {line.strip()}")
    
    print("\n" + "=" * 80)
    print("Test Coverage Summary")
    print("=" * 80)
    
    # Generate coverage report
    coverage_cmd = "python -m pytest tests/ --cov=core --cov=utils --cov-report=term-missing --cov-report=json -q"
    stdout, stderr, code = run_command(coverage_cmd)
    
    # Parse coverage JSON if available
    coverage_file = Path("coverage.json")
    if coverage_file.exists():
        try:
            with open(coverage_file) as f:
                coverage_data = json.load(f)
            
            print(f"\nTotal Coverage: {coverage_data['totals']['percent_covered']:.1f}%")
            print("\nFile Coverage:")
            
            for file_path, file_data in coverage_data['files'].items():
                if '/tests/' not in file_path:
                    percent = file_data['summary']['percent_covered']
                    missing = file_data['summary']['missing_lines']
                    print(f"  {Path(file_path).name:<30} {percent:>6.1f}%  Missing: {missing}")
        except Exception as e:
            print(f"Could not parse coverage data: {e}")
    else:
        # Fallback to parsing text output
        in_coverage = False
        for line in stdout.split('\n'):
            if 'TOTAL' in line or in_coverage:
                print(f"  {line}")
                in_coverage = True
    
    print("\n" + "=" * 80)
    print("Test Statistics")
    print("=" * 80)
    
    # Count tests by marker
    markers = ['slow', 'integration', 'requires_audio', 'requires_ollama']
    for marker in markers:
        cmd = f"python -m pytest tests/ -m {marker} --collect-only -q"
        stdout, stderr, code = run_command(cmd)
        count = stdout.count('test_')
        print(f"  Tests marked '{marker}': {count}")
    
    # Total test count
    cmd = "python -m pytest tests/ --collect-only -q"
    stdout, stderr, code = run_command(cmd)
    total_count = stdout.count('test_')
    print(f"\n  Total Tests: {total_count}")
    
    print("\n" + "=" * 80)
    print("Module Test Breakdown")
    print("=" * 80)
    
    # Test count per module
    for test_file in sorted(test_files):
        if test_file.name == "test_sanity.py":
            continue
        cmd = f"python -m pytest {test_file} --collect-only -q"
        stdout, stderr, code = run_command(cmd)
        count = stdout.count('test_')
        module = test_file.stem.replace('test_', '')
        print(f"  {module:<20} {count:>3} tests")
    
    print("\n" + "=" * 80)
    print("Recommendations")
    print("=" * 80)
    
    print("""
1. Run full test suite before committing:
   python run_tests.py --coverage

2. Run fast tests during development:
   python run_tests.py --fast

3. Generate HTML coverage report:
   pytest --cov=core --cov=utils --cov-report=html
   Open htmlcov/index.html in browser

4. Run specific module tests:
   python run_tests.py core
   python run_tests.py ai
   python run_tests.py config

5. Debug failing tests:
   pytest --pdb --lf
""")
    
    # Clean up
    for f in ['coverage.json', '.coverage']:
        if Path(f).exists():
            Path(f).unlink()


if __name__ == "__main__":
    generate_test_report()