#!/usr/bin/env python3
"""
VoiceFlow Comprehensive Performance Analysis Orchestrator
=========================================================

This script orchestrates the complete performance testing suite for VoiceFlow,
running all performance test categories and generating a consolidated analysis
report with actionable recommendations.

Test Categories Executed:
1. Core Performance Testing (Speech recognition, AI enhancement, Database)
2. Security Performance Impact Analysis
3. Memory Profiling and Leak Detection
4. Real-World Usage Pattern Simulation
5. Scalability and Stress Testing

Usage:
    python run_comprehensive_performance_analysis.py [--quick] [--save-raw] [--output-dir OUTPUT]

Options:
    --quick        Run abbreviated tests for faster execution
    --save-raw     Save all raw test data files
    --output-dir   Specify output directory for results

Author: Senior Performance Testing Expert
Version: 1.0.0
"""

import argparse
import json
import os
import statistics
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Import test modules
try:
    from tests.test_comprehensive_performance import VoiceFlowPerformanceTester
    from tests.test_security_performance_impact import SecurityPerformanceAnalyzer
    from tests.test_memory_profiling import VoiceFlowMemoryTester
    from tests.test_real_world_scenarios import RealWorldScenarioTester
    TESTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some test modules not available: {e}")
    TESTS_AVAILABLE = False


class PerformanceAnalysisOrchestrator:
    """Orchestrates comprehensive performance analysis of VoiceFlow."""
    
    def __init__(self, output_dir: Path, save_raw_data: bool = False, quick_mode: bool = False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.save_raw_data = save_raw_data
        self.quick_mode = quick_mode
        self.analysis_start_time = datetime.now()
        
        # Results storage
        self.test_results = {}
        self.consolidated_analysis = {}
        
        print(f"[ORCHESTRATOR] Performance analysis starting...")
        print(f"[ORCHESTRATOR] Output directory: {self.output_dir}")
        print(f"[ORCHESTRATOR] Quick mode: {quick_mode}")
        print(f"[ORCHESTRATOR] Save raw data: {save_raw_data}")
    
    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """Run complete performance analysis suite."""
        if not TESTS_AVAILABLE:
            return {"error": "Test modules not available"}
        
        print("\n" + "="*80)
        print("VOICEFLOW COMPREHENSIVE PERFORMANCE ANALYSIS")
        print("="*80)
        print(f"Analysis started: {self.analysis_start_time}")
        print("="*80)
        
        # Define test suite
        test_suite = [
            {
                'name': 'core_performance',
                'description': 'Core Performance Testing',
                'runner': self._run_core_performance_tests,
                'duration_estimate': '5-10 minutes',
                'critical': True
            },
            {
                'name': 'security_performance',
                'description': 'Security Performance Impact Analysis',
                'runner': self._run_security_performance_tests,
                'duration_estimate': '3-5 minutes',
                'critical': True
            },
            {
                'name': 'memory_analysis',
                'description': 'Memory Profiling and Leak Detection',
                'runner': self._run_memory_analysis_tests,
                'duration_estimate': '8-12 minutes',
                'critical': True
            },
            {
                'name': 'real_world_scenarios',
                'description': 'Real-World Usage Pattern Simulation',
                'runner': self._run_real_world_scenario_tests,
                'duration_estimate': '10-15 minutes',
                'critical': False  # Can be skipped in quick mode
            }
        ]
        
        # Execute test suite
        for test_config in test_suite:
            if self.quick_mode and not test_config['critical']:
                print(f"\n[SKIP] Skipping {test_config['description']} (quick mode)")
                continue
            
            print(f"\n[EXECUTING] {test_config['description']}")
            print(f"[ESTIMATE] {test_config['duration_estimate']}")
            
            start_time = time.time()
            
            try:
                result = test_config['runner']()
                execution_time = time.time() - start_time
                
                self.test_results[test_config['name']] = {
                    'result': result,
                    'execution_time_seconds': execution_time,
                    'status': 'completed',
                    'timestamp': datetime.now().isoformat()
                }
                
                print(f"[COMPLETED] {test_config['description']} in {execution_time:.1f}s")
                
            except Exception as e:
                execution_time = time.time() - start_time
                error_msg = f"Test failed: {str(e)}"
                
                self.test_results[test_config['name']] = {
                    'error': error_msg,
                    'execution_time_seconds': execution_time,
                    'status': 'failed',
                    'timestamp': datetime.now().isoformat()
                }
                
                print(f"[ERROR] {test_config['description']} failed after {execution_time:.1f}s: {error_msg}")
        
        # Generate consolidated analysis
        print("\n[ANALYSIS] Generating consolidated performance analysis...")
        self.consolidated_analysis = self._generate_consolidated_analysis()
        
        # Save results
        self._save_results()
        
        # Generate summary report
        self._print_executive_summary()
        
        total_time = (datetime.now() - self.analysis_start_time).total_seconds()
        print(f"\n[COMPLETED] Comprehensive analysis completed in {total_time:.1f} seconds")
        
        return {
            'test_results': self.test_results,
            'consolidated_analysis': self.consolidated_analysis,
            'analysis_metadata': {
                'start_time': self.analysis_start_time.isoformat(),
                'total_duration_seconds': total_time,
                'quick_mode': self.quick_mode,
                'tests_executed': len([r for r in self.test_results.values() if r.get('status') == 'completed']),
                'tests_failed': len([r for r in self.test_results.values() if r.get('status') == 'failed'])
            }
        }
    
    def _run_core_performance_tests(self) -> Dict[str, Any]:
        """Run core performance testing suite."""
        tester = VoiceFlowPerformanceTester()
        return tester.run_comprehensive_performance_tests()
    
    def _run_security_performance_tests(self) -> Dict[str, Any]:
        """Run security performance impact analysis."""
        analyzer = SecurityPerformanceAnalyzer()
        return analyzer.run_comprehensive_security_performance_analysis()
    
    def _run_memory_analysis_tests(self) -> Dict[str, Any]:
        """Run memory profiling and leak detection tests."""
        tester = VoiceFlowMemoryTester()
        return tester.run_comprehensive_memory_tests()
    
    def _run_real_world_scenario_tests(self) -> Dict[str, Any]:
        """Run real-world usage pattern simulation."""
        tester = RealWorldScenarioTester()
        return tester.run_comprehensive_real_world_tests()
    
    def _generate_consolidated_analysis(self) -> Dict[str, Any]:
        """Generate consolidated analysis from all test results."""
        analysis = {
            'overall_performance_grade': 'UNKNOWN',
            'production_readiness_score': 0,
            'key_findings': [],
            'critical_issues': [],
            'optimization_priorities': [],
            'performance_summary': {},
            'recommendations': {
                'immediate': [],
                'short_term': [],
                'long_term': []
            }
        }
        
        try:
            # Aggregate performance grades from different test categories
            performance_grades = {}
            readiness_scores = []
            
            # Core performance analysis
            if 'core_performance' in self.test_results:
                core_result = self.test_results['core_performance'].get('result', {})
                if 'test_summary' in core_result:
                    core_summary = core_result['test_summary']
                    core_grades = core_summary.get('performance_grades', {})
                    performance_grades.update(core_grades)
                    
                    # Extract key findings
                    for finding in core_summary.get('key_findings', []):
                        analysis['key_findings'].append(f"Core: {finding}")
            
            # Security performance analysis
            if 'security_performance' in self.test_results:
                security_result = self.test_results['security_performance'].get('result', {})
                if 'analysis_summary' in security_result:
                    security_summary = security_result['analysis_summary']
                    security_grades = security_summary.get('performance_impact_grades', {})
                    
                    # Convert security grades to standard format
                    for component, grade in security_grades.items():
                        performance_grades[f'security_{component}'] = grade
                    
                    # Add security findings
                    for finding in security_summary.get('key_findings', []):
                        analysis['key_findings'].append(f"Security: {finding}")
            
            # Memory analysis
            if 'memory_analysis' in self.test_results:
                memory_result = self.test_results['memory_analysis'].get('result', {})
                if 'memory_analysis_summary' in memory_result:
                    memory_summary = memory_result['memory_analysis_summary']
                    memory_health = memory_summary.get('overall_memory_health', 'UNKNOWN')
                    
                    # Convert memory health to grade
                    health_to_grade = {
                        'EXCELLENT': 'A',
                        'GOOD': 'B',
                        'FAIR': 'C',
                        'POOR': 'D'
                    }
                    performance_grades['memory_management'] = health_to_grade.get(memory_health, 'F')
                    
                    # Add memory findings
                    for finding in memory_summary.get('key_findings', []):
                        analysis['key_findings'].append(f"Memory: {finding}")
                    
                    # Check for memory issues
                    if len(memory_summary.get('memory_leak_indicators', [])) > 0:
                        analysis['critical_issues'].append("Memory leak indicators detected")
            
            # Real-world scenarios
            if 'real_world_scenarios' in self.test_results:
                rw_result = self.test_results['real_world_scenarios'].get('result', {})
                if 'real_world_analysis' in rw_result:
                    rw_analysis = rw_result['real_world_analysis']
                    
                    # Get production readiness score
                    readiness_score = rw_analysis.get('production_readiness_score', 0)
                    readiness_scores.append(readiness_score)
                    
                    # Add real-world grades
                    rw_grades = rw_analysis.get('performance_grades', {})
                    for component, grade in rw_grades.items():
                        performance_grades[f'realworld_{component}'] = grade
                    
                    # Add critical issues
                    analysis['critical_issues'].extend(rw_analysis.get('critical_issues', []))
            
            # Calculate overall performance grade
            grade_values = {'A': 4, 'B': 3, 'C': 2, 'D': 1, 'F': 0}
            if performance_grades:
                grade_scores = [grade_values.get(grade, 0) for grade in performance_grades.values()]
                avg_score = statistics.mean(grade_scores)
                overall_grade_map = {4: 'A', 3: 'B', 2: 'C', 1: 'D', 0: 'F'}
                analysis['overall_performance_grade'] = overall_grade_map.get(int(round(avg_score)), 'F')
            
            # Calculate production readiness score
            if readiness_scores:
                analysis['production_readiness_score'] = statistics.mean(readiness_scores)
            else:
                # Estimate from performance grades
                if analysis['overall_performance_grade'] in ['A']:
                    analysis['production_readiness_score'] = 90
                elif analysis['overall_performance_grade'] in ['B']:
                    analysis['production_readiness_score'] = 75
                elif analysis['overall_performance_grade'] in ['C']:
                    analysis['production_readiness_score'] = 60
                else:
                    analysis['production_readiness_score'] = 40
            
            # Store performance summary
            analysis['performance_summary'] = performance_grades
            
            # Generate optimization priorities
            analysis['optimization_priorities'] = self._identify_optimization_priorities(performance_grades)
            
            # Generate recommendations
            analysis['recommendations'] = self._generate_optimization_recommendations(
                analysis['production_readiness_score'],
                analysis['critical_issues'],
                performance_grades
            )
            
        except Exception as e:
            analysis['consolidation_error'] = str(e)
        
        return analysis
    
    def _identify_optimization_priorities(self, performance_grades: Dict[str, str]) -> List[Dict[str, Any]]:
        """Identify optimization priorities based on performance grades."""
        priorities = []
        
        grade_values = {'A': 4, 'B': 3, 'C': 2, 'D': 1, 'F': 0}
        
        for component, grade in performance_grades.items():
            grade_value = grade_values.get(grade, 0)
            
            if grade_value <= 2:  # C grade or below
                priority = {
                    'component': component,
                    'current_grade': grade,
                    'priority_level': 'HIGH' if grade_value <= 1 else 'MEDIUM',
                    'improvement_potential': 'HIGH'
                }
                priorities.append(priority)
            elif grade_value == 3:  # B grade
                priority = {
                    'component': component,
                    'current_grade': grade,
                    'priority_level': 'MEDIUM',
                    'improvement_potential': 'MEDIUM'
                }
                priorities.append(priority)
        
        # Sort by priority level and grade
        priorities.sort(key=lambda x: (
            0 if x['priority_level'] == 'HIGH' else 1,
            grade_values.get(x['current_grade'], 0)
        ))
        
        return priorities
    
    def _generate_optimization_recommendations(self, readiness_score: float, critical_issues: List[str], 
                                           performance_grades: Dict[str, str]) -> Dict[str, List[str]]:
        """Generate optimization recommendations based on analysis results."""
        recommendations = {
            'immediate': [],
            'short_term': [],
            'long_term': []
        }
        
        # Immediate recommendations (critical issues)
        if readiness_score < 70:
            recommendations['immediate'].append("System not ready for production - address critical performance issues")
        
        if len(critical_issues) > 0:
            recommendations['immediate'].extend([
                "Address all critical issues before production deployment",
                "Implement comprehensive performance monitoring",
                "Create incident response procedures"
            ])
        
        # Analyze specific component grades
        poor_components = [comp for comp, grade in performance_grades.items() if grade in ['D', 'F']]
        if poor_components:
            recommendations['immediate'].append(f"Urgent optimization needed for: {', '.join(poor_components)}")
        
        # Short-term recommendations (optimization opportunities)
        fair_components = [comp for comp, grade in performance_grades.items() if grade == 'C']
        if fair_components:
            recommendations['short_term'].append(f"Optimize performance for: {', '.join(fair_components)}")
        
        recommendations['short_term'].extend([
            "Implement response caching where appropriate",
            "Add database connection pooling",
            "Optimize memory usage patterns",
            "Implement async processing for non-critical operations"
        ])
        
        # Long-term recommendations (future enhancements)
        recommendations['long_term'].extend([
            "Consider GPU acceleration for production",
            "Implement predictive auto-scaling",
            "Advanced load balancing and distribution",
            "Machine learning-based performance optimization",
            "Comprehensive performance regression testing"
        ])
        
        # Conditional recommendations based on readiness score
        if readiness_score >= 85:
            recommendations['immediate'].append("System ready for production with proper monitoring")
        elif readiness_score >= 70:
            recommendations['immediate'].append("System ready for production with optimizations")
        
        return recommendations
    
    def _save_results(self):
        """Save all test results and analysis to files."""
        timestamp = self.analysis_start_time.strftime("%Y%m%d_%H%M%S")
        
        # Save consolidated analysis
        consolidated_file = self.output_dir / f"voiceflow_performance_analysis_{timestamp}.json"
        with open(consolidated_file, 'w') as f:
            json.dump({
                'test_results': self.test_results,
                'consolidated_analysis': self.consolidated_analysis,
                'metadata': {
                    'analysis_timestamp': self.analysis_start_time.isoformat(),
                    'quick_mode': self.quick_mode,
                    'output_directory': str(self.output_dir)
                }
            }, f, indent=2, default=str)
        
        print(f"[SAVED] Consolidated analysis: {consolidated_file}")
        
        # Save individual test results if requested
        if self.save_raw_data:
            for test_name, test_data in self.test_results.items():
                if test_data.get('status') == 'completed':
                    raw_file = self.output_dir / f"{test_name}_raw_data_{timestamp}.json"
                    with open(raw_file, 'w') as f:
                        json.dump(test_data['result'], f, indent=2, default=str)
                    print(f"[SAVED] Raw data for {test_name}: {raw_file}")
        
        # Generate markdown summary
        self._generate_markdown_summary(timestamp)
    
    def _generate_markdown_summary(self, timestamp: str):
        """Generate a markdown summary report."""
        summary_file = self.output_dir / f"performance_summary_{timestamp}.md"
        
        with open(summary_file, 'w') as f:
            f.write(f"# VoiceFlow Performance Analysis Summary\n\n")
            f.write(f"**Analysis Date:** {self.analysis_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Analysis Mode:** {'Quick' if self.quick_mode else 'Comprehensive'}\n\n")
            
            # Overall results
            analysis = self.consolidated_analysis
            f.write(f"## Overall Assessment\n\n")
            f.write(f"- **Performance Grade:** {analysis.get('overall_performance_grade', 'UNKNOWN')}\n")
            f.write(f"- **Production Readiness Score:** {analysis.get('production_readiness_score', 0):.1f}%\n")
            
            readiness_score = analysis.get('production_readiness_score', 0)
            if readiness_score >= 85:
                f.write(f"- **Status:** ✅ **PRODUCTION READY**\n\n")
            elif readiness_score >= 70:
                f.write(f"- **Status:** ⚠️ **PRODUCTION READY WITH OPTIMIZATIONS**\n\n")
            else:
                f.write(f"- **Status:** ❌ **NOT READY FOR PRODUCTION**\n\n")
            
            # Performance breakdown
            f.write(f"## Performance Breakdown\n\n")
            performance_summary = analysis.get('performance_summary', {})
            for component, grade in performance_summary.items():
                status_icon = "✅" if grade in ['A', 'B'] else "⚠️" if grade == 'C' else "❌"
                f.write(f"- **{component}:** {grade} {status_icon}\n")
            f.write("\n")
            
            # Key findings
            f.write(f"## Key Findings\n\n")
            for finding in analysis.get('key_findings', []):
                f.write(f"- {finding}\n")
            f.write("\n")
            
            # Critical issues
            if analysis.get('critical_issues'):
                f.write(f"## Critical Issues\n\n")
                for issue in analysis.get('critical_issues', []):
                    f.write(f"- ❌ {issue}\n")
                f.write("\n")
            
            # Recommendations
            f.write(f"## Recommendations\n\n")
            recommendations = analysis.get('recommendations', {})
            
            if recommendations.get('immediate'):
                f.write(f"### Immediate Actions\n")
                for rec in recommendations['immediate']:
                    f.write(f"- 🔴 {rec}\n")
                f.write("\n")
            
            if recommendations.get('short_term'):
                f.write(f"### Short-term Optimizations\n")
                for rec in recommendations['short_term']:
                    f.write(f"- 🟡 {rec}\n")
                f.write("\n")
            
            if recommendations.get('long_term'):
                f.write(f"### Long-term Enhancements\n")
                for rec in recommendations['long_term']:
                    f.write(f"- 🔵 {rec}\n")
                f.write("\n")
            
            # Test execution summary
            f.write(f"## Test Execution Summary\n\n")
            completed_tests = [name for name, data in self.test_results.items() if data.get('status') == 'completed']
            failed_tests = [name for name, data in self.test_results.items() if data.get('status') == 'failed']
            
            f.write(f"- **Tests Executed:** {len(completed_tests)}\n")
            f.write(f"- **Tests Failed:** {len(failed_tests)}\n")
            
            total_time = sum(data.get('execution_time_seconds', 0) for data in self.test_results.values())
            f.write(f"- **Total Execution Time:** {total_time:.1f} seconds\n\n")
            
            if failed_tests:
                f.write(f"### Failed Tests\n")
                for test_name in failed_tests:
                    error = self.test_results[test_name].get('error', 'Unknown error')
                    f.write(f"- **{test_name}:** {error}\n")
                f.write("\n")
        
        print(f"[SAVED] Summary report: {summary_file}")
    
    def _print_executive_summary(self):
        """Print executive summary to console."""
        print("\n" + "="*80)
        print("EXECUTIVE SUMMARY")
        print("="*80)
        
        analysis = self.consolidated_analysis
        
        print(f"Overall Performance Grade: {analysis.get('overall_performance_grade', 'UNKNOWN')}")
        print(f"Production Readiness Score: {analysis.get('production_readiness_score', 0):.1f}%")
        
        readiness_score = analysis.get('production_readiness_score', 0)
        if readiness_score >= 85:
            print("Status: ✅ PRODUCTION READY")
        elif readiness_score >= 70:
            print("Status: ⚠️ PRODUCTION READY WITH OPTIMIZATIONS")
        else:
            print("Status: ❌ NOT READY FOR PRODUCTION")
        
        print(f"\nTests Executed: {len([r for r in self.test_results.values() if r.get('status') == 'completed'])}")
        print(f"Tests Failed: {len([r for r in self.test_results.values() if r.get('status') == 'failed'])}")
        
        # Critical issues
        critical_issues = analysis.get('critical_issues', [])
        if critical_issues:
            print(f"\nCritical Issues ({len(critical_issues)}):")
            for issue in critical_issues[:3]:  # Show top 3
                print(f"  • {issue}")
            if len(critical_issues) > 3:
                print(f"  • ... and {len(critical_issues) - 3} more")
        
        # Top recommendations
        immediate_recs = analysis.get('recommendations', {}).get('immediate', [])
        if immediate_recs:
            print(f"\nImmediate Actions Required:")
            for rec in immediate_recs[:3]:  # Show top 3
                print(f"  • {rec}")
        
        print(f"\nDetailed results saved to: {self.output_dir}")
        print("="*80)


def main():
    """Main entry point for performance analysis orchestrator."""
    parser = argparse.ArgumentParser(
        description="VoiceFlow Comprehensive Performance Analysis Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_comprehensive_performance_analysis.py
    python run_comprehensive_performance_analysis.py --quick
    python run_comprehensive_performance_analysis.py --save-raw --output-dir ./results
        """
    )
    
    parser.add_argument(
        '--quick', 
        action='store_true', 
        help='Run abbreviated tests for faster execution'
    )
    
    parser.add_argument(
        '--save-raw', 
        action='store_true', 
        help='Save all raw test data files'
    )
    
    parser.add_argument(
        '--output-dir', 
        type=str, 
        default='./performance_results',
        help='Specify output directory for results (default: ./performance_results)'
    )
    
    args = parser.parse_args()
    
    # Create orchestrator and run analysis
    orchestrator = PerformanceAnalysisOrchestrator(
        output_dir=args.output_dir,
        save_raw_data=args.save_raw,
        quick_mode=args.quick
    )
    
    try:
        results = orchestrator.run_comprehensive_analysis()
        
        # Exit with appropriate code
        readiness_score = results.get('consolidated_analysis', {}).get('production_readiness_score', 0)
        if readiness_score >= 70:
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Performance issues detected
            
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Performance analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] Performance analysis failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()