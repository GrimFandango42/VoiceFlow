#!/usr/bin/env python3
"""
Comprehensive Testing Fleet Launcher for VoiceFlow Personal
Executes all testing phases with detailed reporting
"""

import os
import sys
import subprocess
import time
import json
from datetime import datetime
from pathlib import Path


class TestingFleet:
    """Comprehensive testing fleet controller"""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "total_duration": 0,
            "phases": {}
        }
        self.start_time = time.time()
    
    def run_phase(self, phase_name: str, script: str, description: str) -> dict:
        """Run a testing phase"""
        print(f"\n{'='*60}")
        print(f"🚀 PHASE: {phase_name}")
        print(f"📋 {description}")
        print('='*60)
        
        if not os.path.exists(script):
            print(f"❌ Script not found: {script}")
            return {
                "phase": phase_name,
                "script": script,
                "description": description,
                "duration": 0,
                "success": False,
                "output": f"Script {script} not found",
                "error": ""
            }
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                [sys.executable, script],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout per phase
            )
            
            duration = time.time() - start_time
            success = result.returncode == 0
            
            print(f"\n{'✅' if success else '❌'} Phase completed in {duration:.1f}s")
            
            return {
                "phase": phase_name,
                "script": script,
                "description": description,
                "duration": duration,
                "success": success,
                "output": result.stdout,
                "error": result.stderr,
                "return_code": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            print(f"⏱️ Phase timed out after {duration:.1f}s")
            
            return {
                "phase": phase_name,
                "script": script,
                "description": description,
                "duration": duration,
                "success": False,
                "output": "",
                "error": "Test phase timed out",
                "return_code": -1
            }
        
        except Exception as e:
            duration = time.time() - start_time
            print(f"💥 Phase failed with exception: {e}")
            
            return {
                "phase": phase_name,
                "script": script,
                "description": description,
                "duration": duration,
                "success": False,
                "output": "",
                "error": str(e),
                "return_code": -2
            }
    
    def run_all_phases(self):
        """Run all testing phases"""
        phases = [
            {
                "name": "Unit Testing",
                "script": "test_voiceflow_personal.py",
                "description": "Core component testing (MemoryCache, AsyncAIEnhancer, SecurityLimiter)"
            },
            {
                "name": "Security Validation",
                "script": "security_validation.py",
                "description": "Comprehensive security testing for all implemented fixes"
            },
            {
                "name": "Performance Benchmarking",
                "script": "benchmark_voiceflow.py",
                "description": "Performance comparison with enterprise implementations"
            },
            {
                "name": "Integration Testing",
                "script": "test_comprehensive_integration.py",
                "description": "End-to-end component interaction testing"
            }
        ]
        
        print("🎯 VoiceFlow Personal - Comprehensive Testing Fleet")
        print("=" * 60)
        print("📋 Testing Focus Areas:")
        print("  • Unit Testing - Core components")
        print("  • Security Testing - Injection prevention, rate limiting")
        print("  • Performance Testing - Speed vs enterprise versions")
        print("  • Integration Testing - Component interactions")
        print("  • Privacy Testing - Ephemeral storage validation")
        print("  • End-to-End Testing - Complete workflows")
        
        for phase_config in phases:
            result = self.run_phase(
                phase_config["name"],
                phase_config["script"],
                phase_config["description"]
            )
            self.results["phases"][phase_config["name"]] = result
        
        # Calculate total duration
        self.results["total_duration"] = time.time() - self.start_time
    
    def generate_executive_summary(self):
        """Generate executive summary report"""
        print("\n" + "="*60)
        print("🏆 EXECUTIVE TESTING SUMMARY")
        print("="*60)
        
        total_phases = len(self.results["phases"])
        successful_phases = sum(1 for p in self.results["phases"].values() if p["success"])
        
        print(f"\n📊 Overall Results:")
        print(f"  Total Testing Phases: {total_phases}")
        print(f"  ✅ Successful: {successful_phases}")
        print(f"  ❌ Failed: {total_phases - successful_phases}")
        print(f"  ⏱️ Total Duration: {self.results['total_duration']:.1f}s")
        
        success_rate = (successful_phases / total_phases) * 100 if total_phases > 0 else 0
        print(f"  📈 Success Rate: {success_rate:.1f}%")
        
        # Overall assessment
        if success_rate == 100:
            print("\n🏆 EXCELLENT: All testing phases passed!")
            print("✅ VoiceFlow Personal is ready for production")
        elif success_rate >= 80:
            print("\n✅ GOOD: Most testing phases passed")
            print("⚠️ Review failed phases before deployment")
        elif success_rate >= 60:
            print("\n⚠️ FAIR: Some critical issues detected")
            print("🔧 Address failing tests before deployment")
        else:
            print("\n❌ POOR: Significant issues detected")
            print("🚫 NOT READY for deployment - fix critical issues")
        
        print("\n📋 Phase-by-Phase Results:")
        for phase_name, result in self.results["phases"].items():
            status = "✅ PASSED" if result["success"] else "❌ FAILED"
            print(f"  {phase_name}: {status} ({result['duration']:.1f}s)")
            
            if not result["success"] and result["error"]:
                print(f"    💥 Error: {result['error']}")
    
    def generate_detailed_report(self, output_file: str = "comprehensive_testing_report.json"):
        """Generate detailed JSON report"""
        # Add metadata
        self.results["metadata"] = {
            "voiceflow_version": "VoiceFlow Personal 2.0",
            "python_version": sys.version,
            "platform": sys.platform,
            "working_directory": os.getcwd()
        }
        
        # Add test file analysis
        self.results["test_files"] = {}
        test_files = [
            "voiceflow_personal.py",
            "run_personal.py",
            "requirements_personal.txt"
        ]
        
        for file_path in test_files:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                self.results["test_files"][file_path] = {
                    "exists": True,
                    "size_bytes": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                }
            else:
                self.results["test_files"][file_path] = {
                    "exists": False,
                    "size_bytes": 0,
                    "modified": None
                }
        
        # Save report
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n📄 Detailed report saved: {output_file}")
    
    def generate_recommendations(self):
        """Generate actionable recommendations"""
        print("\n" + "="*60)
        print("📋 RECOMMENDATIONS & NEXT STEPS")
        print("="*60)
        
        failed_phases = [name for name, result in self.results["phases"].items() 
                        if not result["success"]]
        
        if not failed_phases:
            print("\n✅ DEPLOYMENT RECOMMENDATIONS:")
            print("  • All tests passed - VoiceFlow Personal is production-ready")
            print("  • Continue regular testing during maintenance")
            print("  • Monitor performance in production environment")
            print("  • Set up automated testing for future updates")
            
        else:
            print("\n🔧 CRITICAL FIXES NEEDED:")
            for phase in failed_phases:
                result = self.results["phases"][phase]
                print(f"  • {phase}: {result['error'] or 'See detailed logs'}")
            
            print("\n📋 ACTION ITEMS:")
            if "Security Validation" in failed_phases:
                print("  ❗ CRITICAL: Fix security issues immediately")
                print("    - Review prompt injection prevention")
                print("    - Validate command injection blocks")
                print("    - Check rate limiting implementation")
            
            if "Unit Testing" in failed_phases:
                print("  🔧 HIGH: Fix core component issues")
                print("    - Debug failing unit tests")
                print("    - Ensure all components work independently")
            
            if "Performance Benchmarking" in failed_phases:
                print("  ⚡ MEDIUM: Optimize performance issues")
                print("    - Profile slow components")
                print("    - Optimize memory usage")
                print("    - Improve startup time")
            
            print("\n🔄 RE-TESTING:")
            print("  • Fix all identified issues")
            print("  • Re-run comprehensive testing")
            print("  • Validate fixes don't introduce new problems")
        
        print("\n📊 PERFORMANCE INSIGHTS:")
        if self.results["total_duration"] < 60:
            print("  ✅ Fast testing suite - good for CI/CD integration")
        elif self.results["total_duration"] < 300:
            print("  ⚠️ Moderate testing time - consider optimization for CI/CD")
        else:
            print("  🐌 Slow testing suite - optimize for faster feedback")
        
        print("\n🔐 SECURITY POSTURE:")
        security_result = self.results["phases"].get("Security Validation", {})
        if security_result.get("success"):
            print("  ✅ Strong security implementation")
            print("  ✅ Injection prevention validated")
            print("  ✅ Rate limiting functional")
        else:
            print("  ❌ Security vulnerabilities detected")
            print("  🚨 DO NOT DEPLOY until security issues are fixed")
    
    def run_final_validation(self):
        """Run final validation checks"""
        print("\n" + "="*60)
        print("🔍 FINAL VALIDATION CHECKS")
        print("="*60)
        
        # Check required files exist
        required_files = [
            "voiceflow_personal.py",
            "run_personal.py",
            "requirements_personal.txt"
        ]
        
        missing_files = []
        for file_path in required_files:
            if not os.path.exists(file_path):
                missing_files.append(file_path)
        
        if missing_files:
            print(f"❌ Missing required files: {missing_files}")
            return False
        else:
            print("✅ All required files present")
        
        # Check if any critical phases failed
        critical_phases = ["Unit Testing", "Security Validation"]
        failed_critical = [name for name in critical_phases 
                          if not self.results["phases"].get(name, {}).get("success", False)]
        
        if failed_critical:
            print(f"❌ Critical phases failed: {failed_critical}")
            return False
        else:
            print("✅ All critical phases passed")
        
        # Overall validation
        total_phases = len(self.results["phases"])
        successful_phases = sum(1 for p in self.results["phases"].values() if p["success"])
        success_rate = (successful_phases / total_phases) * 100 if total_phases > 0 else 0
        
        if success_rate >= 80:
            print(f"✅ VALIDATION PASSED: {success_rate:.1f}% success rate")
            return True
        else:
            print(f"❌ VALIDATION FAILED: {success_rate:.1f}% success rate")
            return False


def main():
    """Main testing fleet execution"""
    fleet = TestingFleet()
    
    try:
        # Run all testing phases
        fleet.run_all_phases()
        
        # Generate reports
        fleet.generate_executive_summary()
        fleet.generate_detailed_report()
        fleet.generate_recommendations()
        
        # Final validation
        validation_passed = fleet.run_final_validation()
        
        print("\n" + "="*60)
        print("🎯 TESTING FLEET COMPLETE")
        print("="*60)
        
        if validation_passed:
            print("🏆 SUCCESS: VoiceFlow Personal has passed comprehensive testing!")
            print("✅ Ready for deployment with security fixes validated")
            return 0
        else:
            print("❌ FAILURE: Critical issues detected in testing")
            print("🚫 NOT READY for deployment - address issues first")
            return 1
        
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
        return 2
    except Exception as e:
        print(f"\n💥 Testing fleet failed: {e}")
        return 3


if __name__ == "__main__":
    sys.exit(main())