#!/usr/bin/env python3
"""
Run Security Module Unit Tests

This script runs comprehensive unit tests for VoiceFlow security modules
and generates a detailed test report.
"""

import sys
import os
import subprocess
import json
from pathlib import Path
from datetime import datetime

def check_dependencies():
    """Check if required dependencies are installed."""
    missing = []
    
    # Check Python modules
    required_modules = [
        'pytest',
        'cryptography',
        'requests',
        'websockets'
    ]
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"❌ Missing dependencies: {', '.join(missing)}")
        print("\nTo install missing dependencies:")
        print(f"pip install {' '.join(missing)}")
        return False
    
    print("✅ All dependencies installed")
    return True

def run_security_tests():
    """Run security-specific unit tests."""
    test_files = [
        "tests/test_secure_db.py",
        "tests/test_auth.py", 
        "tests/test_input_validation.py"
    ]
    
    results = {}
    
    for test_file in test_files:
        if not Path(test_file).exists():
            print(f"⚠️  Test file not found: {test_file}")
            continue
        
        print(f"\n{'='*60}")
        print(f"Running {test_file}...")
        print(f"{'='*60}")
        
        try:
            # Run pytest with JSON output
            cmd = [
                sys.executable, "-m", "pytest", 
                test_file, 
                "-v",
                "--tb=short",
                "--json-report",
                "--json-report-file=test_report.json"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse results
            if Path("test_report.json").exists():
                with open("test_report.json", "r") as f:
                    report = json.load(f)
                    
                results[test_file] = {
                    "passed": report.get("summary", {}).get("passed", 0),
                    "failed": report.get("summary", {}).get("failed", 0),
                    "errors": report.get("summary", {}).get("error", 0),
                    "total": report.get("summary", {}).get("total", 0),
                    "duration": report.get("duration", 0)
                }
                
                # Clean up report file
                os.remove("test_report.json")
            else:
                # Fallback to parsing output
                output = result.stdout
                if "passed" in output:
                    # Extract test counts from output
                    import re
                    match = re.search(r'(\d+) passed', output)
                    passed = int(match.group(1)) if match else 0
                    match = re.search(r'(\d+) failed', output)
                    failed = int(match.group(1)) if match else 0
                    
                    results[test_file] = {
                        "passed": passed,
                        "failed": failed,
                        "errors": 0,
                        "total": passed + failed
                    }
                else:
                    results[test_file] = {
                        "passed": 0,
                        "failed": 0,
                        "errors": 1,
                        "total": 0,
                        "error_message": result.stderr
                    }
            
            # Print immediate results
            if result.returncode == 0:
                print(f"✅ All tests passed!")
            else:
                print(f"❌ Some tests failed")
                if result.stderr:
                    print(f"Error output:\n{result.stderr}")
                    
        except Exception as e:
            print(f"❌ Error running tests: {e}")
            results[test_file] = {
                "passed": 0,
                "failed": 0,
                "errors": 1,
                "total": 0,
                "error_message": str(e)
            }
    
    return results

def generate_summary_report(results):
    """Generate a summary report of test results."""
    print(f"\n{'='*60}")
    print("SECURITY TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    total_passed = 0
    total_failed = 0
    total_errors = 0
    total_tests = 0
    
    for test_file, result in results.items():
        passed = result.get("passed", 0)
        failed = result.get("failed", 0) 
        errors = result.get("errors", 0)
        total = result.get("total", 0)
        
        total_passed += passed
        total_failed += failed
        total_errors += errors
        total_tests += total
        
        status = "✅" if failed == 0 and errors == 0 else "❌"
        print(f"{status} {test_file}")
        print(f"   Passed: {passed}/{total}")
        
        if failed > 0:
            print(f"   Failed: {failed}")
        if errors > 0:
            print(f"   Errors: {errors}")
            if "error_message" in result:
                print(f"   Error: {result['error_message'][:100]}...")
        
        if "duration" in result:
            print(f"   Duration: {result['duration']:.2f}s")
        print()
    
    # Overall summary
    print(f"{'='*60}")
    print(f"TOTAL: {total_tests} tests")
    print(f"✅ Passed: {total_passed}")
    if total_failed > 0:
        print(f"❌ Failed: {total_failed}")
    if total_errors > 0:
        print(f"⚠️  Errors: {total_errors}")
    
    success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
    print(f"\nSuccess Rate: {success_rate:.1f}%")
    
    # Recommendations
    print(f"\n{'='*60}")
    print("RECOMMENDATIONS:")
    
    if total_errors > 0:
        print("1. Fix import/dependency errors before running tests")
        print("   - Install cryptography: pip install cryptography")
        print("   - Ensure all test files are in the correct location")
    
    if total_failed > 0:
        print("2. Review failed tests and fix implementation issues")
        print("   - Check error messages in test output")
        print("   - Verify security implementations match test expectations")
    
    if success_rate == 100:
        print("✅ All security tests passing! The security modules are well-tested.")
        print("\nNext steps:")
        print("- Run integration tests")
        print("- Perform security audit")
        print("- Set up continuous integration")

def main():
    """Main entry point."""
    print("VoiceFlow Security Test Runner")
    print("==============================\n")
    
    # Check dependencies
    if not check_dependencies():
        print("\n❌ Please install missing dependencies before running tests.")
        sys.exit(1)
    
    # Run tests
    print("\n🧪 Running security unit tests...")
    results = run_security_tests()
    
    # Generate report
    generate_summary_report(results)
    
    # Save detailed results
    report_file = Path("security_test_results.json")
    with open(report_file, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "results": results
        }, f, indent=2)
    
    print(f"\n📄 Detailed results saved to: {report_file}")

if __name__ == "__main__":
    main()