#!/usr/bin/env python3
"""
VoiceFlow Comprehensive Load Testing Execution Framework
=======================================================

Master execution script for comprehensive load testing of VoiceFlow system.
Coordinates and executes all load testing scenarios with integrated reporting.

This framework executes:
1. Progressive Load Testing - Gradual user increase validation
2. Sustained Load Testing - Extended operation stability 
3. Spike Load Testing - Sudden load increase handling
4. Stress Load Testing - System breaking point identification
5. WebSocket Load Testing - Real-time communication limits
6. AI Enhancement Load Testing - AI pipeline scalability
7. Database Load Testing - High-volume data operations
8. Resource Monitoring - Memory leaks and system efficiency

The framework generates comprehensive reports with production deployment
guidelines, capacity planning recommendations, and performance optimization strategies.

Author: Senior Load Testing Expert
Version: 1.0.0
Focus: Production Readiness Validation
"""

import asyncio
import json
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import load testing modules
try:
    from tests.test_comprehensive_load_testing import VoiceFlowLoadTester
    from tests.test_websocket_load_testing import WebSocketLoadTester
    from tests.test_ai_enhancement_load_testing import AIEnhancementLoadTester
    LOAD_TESTING_AVAILABLE = True
except ImportError as e:
    print(f"Load testing modules not available: {e}")
    LOAD_TESTING_AVAILABLE = False


class LoadTestingOrchestrator:
    """Orchestrates comprehensive load testing across all VoiceFlow components."""
    
    def __init__(self):
        self.results_dir = Path("load_test_results")
        self.results_dir.mkdir(exist_ok=True)
        
        self.test_start_time = None
        self.test_results = {}
        
        # Initialize component testers
        if LOAD_TESTING_AVAILABLE:
            self.main_load_tester = VoiceFlowLoadTester()
            self.websocket_tester = WebSocketLoadTester()
            self.ai_tester = AIEnhancementLoadTester()
        else:
            print("[WARNING] Load testing components not available - running in simulation mode")
    
    async def run_comprehensive_load_testing(self) -> Dict[str, Any]:
        """Execute comprehensive load testing across all components."""
        print("\n" + "="*100)
        print("VOICEFLOW COMPREHENSIVE LOAD TESTING SUITE")
        print("Production Readiness Validation & Capacity Planning")
        print("="*100)
        
        self.test_start_time = time.time()
        
        comprehensive_results = {
            "test_metadata": {
                "start_time": datetime.now().isoformat(),
                "test_type": "comprehensive_load_testing",
                "framework_version": "1.0.0",
                "environment": {
                    "platform": sys.platform,
                    "python_version": sys.version,
                    "working_directory": str(Path.cwd())
                }
            },
            "test_results": {},
            "analysis_summary": {},
            "production_readiness": {},
            "capacity_planning": {},
            "recommendations": []
        }
        
        if not LOAD_TESTING_AVAILABLE:
            comprehensive_results["test_results"]["error"] = "Load testing components not available"
            comprehensive_results["production_readiness"]["overall_ready"] = False
            comprehensive_results["production_readiness"]["reason"] = "Components not available for testing"
            return comprehensive_results
        
        # Phase 1: Core VoiceFlow Load Testing
        print("\n" + "="*80)
        print("PHASE 1: CORE VOICEFLOW SYSTEM LOAD TESTING")
        print("="*80)
        
        try:
            print("[PHASE 1] Running progressive, sustained, spike, and stress load tests...")
            voiceflow_results = await self.main_load_tester.run_comprehensive_load_tests()
            comprehensive_results["test_results"]["voiceflow_core"] = voiceflow_results
            
            # Save intermediate results
            self._save_intermediate_results("voiceflow_core_load_results.json", voiceflow_results)
            
        except Exception as e:
            print(f"[ERROR] VoiceFlow core load testing failed: {e}")
            comprehensive_results["test_results"]["voiceflow_core"] = {
                "error": str(e),
                "traceback": traceback.format_exc()
            }
        
        # Phase 2: WebSocket Load Testing
        print("\n" + "="*80)
        print("PHASE 2: WEBSOCKET COMMUNICATION LOAD TESTING")
        print("="*80)
        
        try:
            print("[PHASE 2] Running WebSocket connection and message throughput tests...")
            websocket_results = await self.websocket_tester.test_load_scenarios()
            comprehensive_results["test_results"]["websocket"] = websocket_results
            
            self._save_intermediate_results("websocket_load_results.json", websocket_results)
            
        except Exception as e:
            print(f"[ERROR] WebSocket load testing failed: {e}")
            comprehensive_results["test_results"]["websocket"] = {
                "error": str(e),
                "traceback": traceback.format_exc()
            }
        
        # Phase 3: AI Enhancement Load Testing
        print("\n" + "="*80)
        print("PHASE 3: AI ENHANCEMENT PIPELINE LOAD TESTING")
        print("="*80)
        
        try:
            print("[PHASE 3] Running AI enhancement concurrency and scaling tests...")
            ai_results = await self.ai_tester.run_comprehensive_ai_load_tests()
            comprehensive_results["test_results"]["ai_enhancement"] = ai_results
            
            self._save_intermediate_results("ai_enhancement_load_results.json", ai_results)
            
        except Exception as e:
            print(f"[ERROR] AI enhancement load testing failed: {e}")
            comprehensive_results["test_results"]["ai_enhancement"] = {
                "error": str(e),
                "traceback": traceback.format_exc()
            }
        
        # Phase 4: Analysis and Reporting
        print("\n" + "="*80)
        print("PHASE 4: COMPREHENSIVE ANALYSIS AND REPORTING")
        print("="*80)
        
        print("[PHASE 4] Analyzing results and generating production readiness assessment...")
        
        # Generate comprehensive analysis
        comprehensive_results["analysis_summary"] = self._generate_comprehensive_analysis(
            comprehensive_results["test_results"]
        )
        
        # Assess production readiness
        comprehensive_results["production_readiness"] = self._assess_overall_production_readiness(
            comprehensive_results["test_results"]
        )
        
        # Generate capacity planning
        comprehensive_results["capacity_planning"] = self._generate_capacity_planning(
            comprehensive_results["test_results"]
        )
        
        # Generate recommendations
        comprehensive_results["recommendations"] = self._generate_optimization_recommendations(
            comprehensive_results["test_results"],
            comprehensive_results["production_readiness"]
        )
        
        # Complete test metadata
        comprehensive_results["test_metadata"]["end_time"] = datetime.now().isoformat()
        comprehensive_results["test_metadata"]["total_duration_seconds"] = time.time() - self.test_start_time
        
        return comprehensive_results
    
    def _save_intermediate_results(self, filename: str, results: Dict[str, Any]):
        """Save intermediate test results for debugging and analysis."""
        filepath = self.results_dir / filename
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"    Intermediate results saved: {filepath}")
        except Exception as e:
            print(f"    Failed to save intermediate results: {e}")
    
    def _generate_comprehensive_analysis(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive analysis across all load testing results."""
        analysis = {
            "overall_performance": {},
            "scalability_assessment": {},
            "reliability_metrics": {},
            "component_analysis": {},
            "bottleneck_identification": {},
            "system_limits": {}
        }
        
        # Analyze VoiceFlow core results
        if "voiceflow_core" in test_results and "error" not in test_results["voiceflow_core"]:
            core_results = test_results["voiceflow_core"]
            
            # Extract key performance metrics
            if "production_readiness_assessment" in core_results:
                core_readiness = core_results["production_readiness_assessment"]
                analysis["component_analysis"]["voiceflow_core"] = {
                    "overall_score": core_readiness.get("overall_score", 0),
                    "production_ready": core_readiness.get("production_ready", False),
                    "capacity_planning": core_readiness.get("capacity_planning", {})
                }
            
            # Extract system limits from stress testing
            if "stress_load" in core_results:
                stress_results = core_results["stress_load"]
                breaking_point = stress_results.get("breaking_point", {})
                analysis["system_limits"]["max_concurrent_users"] = breaking_point.get("user_count", "Not reached")
                analysis["system_limits"]["max_stable_throughput"] = stress_results.get("capacity_analysis", {}).get("max_stable_throughput", 0)
        
        # Analyze WebSocket results
        if "websocket" in test_results and "error" not in test_results["websocket"]:
            ws_results = test_results["websocket"]
            
            if "websocket_analysis" in ws_results:
                ws_analysis = ws_results["websocket_analysis"]
                analysis["component_analysis"]["websocket"] = {
                    "capacity_assessment": ws_analysis.get("capacity_assessment", {}),
                    "performance_characteristics": ws_analysis.get("performance_characteristics", {}),
                    "production_ready": ws_analysis.get("production_readiness", {}).get("overall_ready", False)
                }
                
                # Extract WebSocket limits
                capacity = ws_analysis.get("capacity_assessment", {})
                analysis["system_limits"]["max_websocket_connections"] = capacity.get("max_tested_connections", 0)
                analysis["system_limits"]["websocket_message_throughput"] = ws_analysis.get("performance_characteristics", {}).get("max_throughput_msgs_per_sec", 0)
        
        # Analyze AI Enhancement results
        if "ai_enhancement" in test_results and "error" not in test_results["ai_enhancement"]:
            ai_results = test_results["ai_enhancement"]
            
            if "production_readiness" in ai_results:
                ai_readiness = ai_results["production_readiness"]
                analysis["component_analysis"]["ai_enhancement"] = {
                    "overall_score": ai_readiness.get("overall_score", 0),
                    "production_ready": ai_readiness.get("production_ready", False),
                    "capacity_planning": ai_readiness.get("capacity_planning", {})
                }
            
            # Extract AI processing limits
            if "ai_load_analysis" in ai_results:
                ai_analysis = ai_results["ai_load_analysis"]
                perf_chars = ai_analysis.get("performance_characteristics", {})
                analysis["system_limits"]["max_ai_concurrent_requests"] = perf_chars.get("max_tested_concurrency", 0)
                analysis["system_limits"]["ai_processing_throughput"] = perf_chars.get("throughput_rps", 0)
        
        # Overall performance assessment
        component_scores = [
            analysis["component_analysis"].get("voiceflow_core", {}).get("overall_score", 0),
            analysis["component_analysis"].get("websocket", {}).get("capacity_assessment", {}).get("successful_connection_rate", 0),
            analysis["component_analysis"].get("ai_enhancement", {}).get("overall_score", 0)
        ]
        
        valid_scores = [score for score in component_scores if score > 0]
        analysis["overall_performance"]["composite_score"] = sum(valid_scores) / len(valid_scores) if valid_scores else 0
        
        # Scalability assessment
        all_ready = all([
            analysis["component_analysis"].get("voiceflow_core", {}).get("production_ready", False),
            analysis["component_analysis"].get("websocket", {}).get("production_ready", False),
            analysis["component_analysis"].get("ai_enhancement", {}).get("production_ready", False)
        ])
        
        analysis["scalability_assessment"]["overall_scalable"] = all_ready
        analysis["scalability_assessment"]["limiting_factors"] = self._identify_limiting_factors(analysis)
        
        return analysis
    
    def _identify_limiting_factors(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify performance limiting factors across components."""
        limiting_factors = []
        
        # Check VoiceFlow core limits
        core_analysis = analysis.get("component_analysis", {}).get("voiceflow_core", {})
        if not core_analysis.get("production_ready", False):
            limiting_factors.append("VoiceFlow core system needs optimization")
        
        # Check WebSocket limits
        ws_analysis = analysis.get("component_analysis", {}).get("websocket", {})
        if not ws_analysis.get("production_ready", False):
            limiting_factors.append("WebSocket communication layer needs scaling")
        
        # Check AI Enhancement limits
        ai_analysis = analysis.get("component_analysis", {}).get("ai_enhancement", {})
        if not ai_analysis.get("production_ready", False):
            limiting_factors.append("AI enhancement pipeline requires optimization")
        
        # Check system limits
        system_limits = analysis.get("system_limits", {})
        max_users = system_limits.get("max_concurrent_users", 0)
        if isinstance(max_users, int) and max_users < 50:
            limiting_factors.append(f"Low concurrent user capacity: {max_users}")
        
        return limiting_factors if limiting_factors else ["No critical limiting factors identified"]
    
    def _assess_overall_production_readiness(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall production readiness across all components."""
        readiness_assessment = {
            "overall_ready": False,
            "readiness_score": 0,
            "grade": "F",
            "critical_issues": [],
            "component_readiness": {},
            "deployment_recommendation": "",
            "required_actions": []
        }
        
        component_readiness = {}
        component_scores = []
        
        # Assess VoiceFlow core readiness
        if "voiceflow_core" in test_results and "error" not in test_results["voiceflow_core"]:
            core_results = test_results["voiceflow_core"]
            if "production_readiness_assessment" in core_results:
                core_readiness = core_results["production_readiness_assessment"]
                component_readiness["voiceflow_core"] = {
                    "ready": core_readiness.get("production_ready", False),
                    "score": core_readiness.get("overall_score", 0),
                    "grade": core_readiness.get("grade", "F")
                }
                component_scores.append(core_readiness.get("overall_score", 0))
                
                if not core_readiness.get("production_ready", False):
                    readiness_assessment["critical_issues"].extend(
                        core_readiness.get("critical_issues", ["VoiceFlow core not production ready"])
                    )
        else:
            component_readiness["voiceflow_core"] = {"ready": False, "score": 0, "grade": "F"}
            readiness_assessment["critical_issues"].append("VoiceFlow core load testing failed")
        
        # Assess WebSocket readiness
        if "websocket" in test_results and "error" not in test_results["websocket"]:
            ws_results = test_results["websocket"]
            if "websocket_analysis" in ws_results:
                ws_analysis = ws_results["websocket_analysis"]
                ws_readiness = ws_analysis.get("production_readiness", {})
                component_readiness["websocket"] = {
                    "ready": ws_readiness.get("overall_ready", False),
                    "score": ws_readiness.get("readiness_score", 0),
                    "grade": "A" if ws_readiness.get("readiness_score", 0) > 90 else "B"
                }
                component_scores.append(ws_readiness.get("readiness_score", 0))
                
                if not ws_readiness.get("overall_ready", False):
                    readiness_assessment["critical_issues"].append("WebSocket layer needs optimization")
        else:
            component_readiness["websocket"] = {"ready": False, "score": 0, "grade": "F"}
            readiness_assessment["critical_issues"].append("WebSocket load testing failed")
        
        # Assess AI Enhancement readiness
        if "ai_enhancement" in test_results and "error" not in test_results["ai_enhancement"]:
            ai_results = test_results["ai_enhancement"]
            if "production_readiness" in ai_results:
                ai_readiness = ai_results["production_readiness"]
                component_readiness["ai_enhancement"] = {
                    "ready": ai_readiness.get("production_ready", False),
                    "score": ai_readiness.get("overall_score", 0),
                    "grade": ai_readiness.get("grade", "F")
                }
                component_scores.append(ai_readiness.get("overall_score", 0))
                
                if not ai_readiness.get("production_ready", False):
                    readiness_assessment["critical_issues"].append("AI enhancement pipeline needs optimization")
        else:
            component_readiness["ai_enhancement"] = {"ready": False, "score": 0, "grade": "F"}
            readiness_assessment["critical_issues"].append("AI enhancement load testing failed")
        
        readiness_assessment["component_readiness"] = component_readiness
        
        # Calculate overall readiness
        if component_scores:
            overall_score = sum(component_scores) / len(component_scores)
            readiness_assessment["readiness_score"] = overall_score
            
            # Assign grade
            if overall_score >= 90:
                readiness_assessment["grade"] = "A"
                readiness_assessment["overall_ready"] = True
                readiness_assessment["deployment_recommendation"] = "Ready for production deployment"
            elif overall_score >= 80:
                readiness_assessment["grade"] = "B"
                readiness_assessment["overall_ready"] = True
                readiness_assessment["deployment_recommendation"] = "Ready for production with monitoring"
            elif overall_score >= 70:
                readiness_assessment["grade"] = "C"
                readiness_assessment["overall_ready"] = True
                readiness_assessment["deployment_recommendation"] = "Ready for production with optimizations"
            elif overall_score >= 60:
                readiness_assessment["grade"] = "D"
                readiness_assessment["overall_ready"] = False
                readiness_assessment["deployment_recommendation"] = "Requires optimization before production"
            else:
                readiness_assessment["grade"] = "F"
                readiness_assessment["overall_ready"] = False
                readiness_assessment["deployment_recommendation"] = "Not ready for production deployment"
        
        # Check if all components are ready
        all_components_ready = all([
            comp.get("ready", False) for comp in component_readiness.values()
        ])
        
        if not all_components_ready:
            readiness_assessment["overall_ready"] = False
            if readiness_assessment["deployment_recommendation"] == "Ready for production deployment":
                readiness_assessment["deployment_recommendation"] = "Ready for production with component optimizations"
        
        # Generate required actions
        if readiness_assessment["critical_issues"]:
            readiness_assessment["required_actions"].extend([
                "Address all critical issues before production deployment",
                "Implement comprehensive monitoring and alerting",
                "Conduct additional targeted testing for failed components"
            ])
        
        if readiness_assessment["overall_ready"]:
            readiness_assessment["required_actions"].extend([
                "Set up production monitoring and alerting",
                "Implement auto-scaling policies based on load test results",
                "Create incident response procedures"
            ])
        
        return readiness_assessment
    
    def _generate_capacity_planning(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive capacity planning guidelines."""
        capacity_planning = {
            "recommended_deployment_config": {},
            "scaling_thresholds": {},
            "monitoring_requirements": {},
            "resource_requirements": {},
            "auto_scaling_policies": {}
        }
        
        # Extract capacity recommendations from each component
        
        # VoiceFlow Core Capacity
        if "voiceflow_core" in test_results and "error" not in test_results["voiceflow_core"]:
            core_results = test_results["voiceflow_core"]
            if "production_readiness_assessment" in core_results:
                core_capacity = core_results["production_readiness_assessment"].get("capacity_planning", {})
                capacity_planning["recommended_deployment_config"]["voiceflow_core"] = {
                    "max_concurrent_users": core_capacity.get("recommended_max_concurrent_users", 25),
                    "scale_out_threshold": core_capacity.get("scale_out_threshold", 20),
                    "monitoring_threshold": core_capacity.get("monitoring_alert_threshold", 22)
                }
        
        # WebSocket Capacity
        if "websocket" in test_results and "error" not in test_results["websocket"]:
            ws_results = test_results["websocket"]
            if "websocket_analysis" in ws_results:
                ws_capacity = ws_results["websocket_analysis"].get("capacity_assessment", {})
                capacity_planning["recommended_deployment_config"]["websocket"] = {
                    "max_connections": int(ws_capacity.get("max_tested_connections", 50) * 0.7),
                    "message_rate_limit": int(ws_capacity.get("max_throughput_msgs_per_sec", 100) * 0.8),
                    "connection_timeout": 30
                }
        
        # AI Enhancement Capacity
        if "ai_enhancement" in test_results and "error" not in test_results["ai_enhancement"]:
            ai_results = test_results["ai_enhancement"]
            if "production_readiness" in ai_results:
                ai_capacity = ai_results["production_readiness"].get("capacity_planning", {})
                capacity_planning["recommended_deployment_config"]["ai_enhancement"] = {
                    "max_concurrent_requests": ai_capacity.get("recommended_max_concurrent", 10),
                    "processing_rate_limit": ai_capacity.get("optimal_processing_rate", 5),
                    "queue_size_limit": ai_capacity.get("queue_size_limit", 50)
                }
        
        # Scaling thresholds
        capacity_planning["scaling_thresholds"] = {
            "cpu_utilization": {
                "scale_out": 70,
                "scale_in": 30
            },
            "memory_utilization": {
                "scale_out": 80,
                "scale_in": 40
            },
            "response_time_ms": {
                "warning": 500,
                "critical": 1000
            },
            "error_rate_percent": {
                "warning": 2,
                "critical": 5
            }
        }
        
        # Monitoring requirements
        capacity_planning["monitoring_requirements"] = {
            "essential_metrics": [
                "Response time percentiles (P50, P95, P99)",
                "Request throughput and error rates", 
                "System resource utilization (CPU, Memory, Disk)",
                "WebSocket connection count and message rates",
                "AI enhancement queue size and processing times",
                "Database operation latency and throughput"
            ],
            "alerting_rules": [
                "Response time P95 > 1000ms",
                "Error rate > 5%",
                "CPU utilization > 85%",
                "Memory utilization > 90%",
                "WebSocket connection failures > 5%",
                "AI enhancement queue size > 100"
            ],
            "dashboard_requirements": [
                "Real-time system overview",
                "Component-specific performance metrics",
                "User experience monitoring",
                "Resource utilization trends",
                "Error tracking and analysis"
            ]
        }
        
        # Resource requirements
        capacity_planning["resource_requirements"] = {
            "minimum_production": {
                "cpu_cores": 4,
                "memory_gb": 8,
                "storage_gb": 100,
                "network_bandwidth_mbps": 1000
            },
            "recommended_production": {
                "cpu_cores": 8,
                "memory_gb": 16,
                "storage_gb": 500,
                "network_bandwidth_mbps": 10000
            },
            "high_availability": {
                "cpu_cores": 16,
                "memory_gb": 32,
                "storage_gb": 1000,
                "network_bandwidth_mbps": 10000,
                "additional_requirements": [
                    "Load balancer with health checks",
                    "Database read replicas",
                    "Redis caching layer",
                    "CDN for static assets"
                ]
            }
        }
        
        return capacity_planning
    
    def _generate_optimization_recommendations(self, test_results: Dict[str, Any], 
                                             production_readiness: Dict[str, Any]) -> List[str]:
        """Generate comprehensive optimization recommendations."""
        recommendations = []
        
        # High priority recommendations based on readiness
        if not production_readiness.get("overall_ready", False):
            recommendations.extend([
                "🚨 CRITICAL: Address all identified issues before production deployment",
                "🚨 CRITICAL: Implement comprehensive monitoring and alerting",
                "🚨 CRITICAL: Conduct additional load testing after optimizations"
            ])
        
        # Component-specific recommendations
        component_readiness = production_readiness.get("component_readiness", {})
        
        # VoiceFlow Core recommendations
        if not component_readiness.get("voiceflow_core", {}).get("ready", False):
            recommendations.extend([
                "⚠️ VoiceFlow Core: Optimize speech recognition processing pipeline",
                "⚠️ VoiceFlow Core: Implement connection pooling for database operations", 
                "⚠️ VoiceFlow Core: Add async processing for non-blocking operations"
            ])
        
        # WebSocket recommendations
        if not component_readiness.get("websocket", {}).get("ready", False):
            recommendations.extend([
                "⚠️ WebSocket: Optimize connection handling for higher concurrency",
                "⚠️ WebSocket: Implement connection pooling and reuse",
                "⚠️ WebSocket: Add message queuing for burst handling"
            ])
        
        # AI Enhancement recommendations
        if not component_readiness.get("ai_enhancement", {}).get("ready", False):
            recommendations.extend([
                "⚠️ AI Enhancement: Implement async processing for concurrent requests",
                "⚠️ AI Enhancement: Add response caching for frequently enhanced text",
                "⚠️ AI Enhancement: Implement circuit breaker for Ollama integration"
            ])
        
        # General production recommendations
        if production_readiness.get("overall_ready", False):
            recommendations.extend([
                "✅ Production Ready: Implement the recommended capacity planning",
                "✅ Production Ready: Set up comprehensive monitoring dashboards",
                "✅ Production Ready: Configure auto-scaling based on load thresholds",
                "✅ Production Ready: Establish incident response procedures",
                "✅ Production Ready: Schedule regular performance reviews"
            ])
        
        # Performance optimization recommendations
        recommendations.extend([
            "🔧 Performance: Implement response caching where appropriate",
            "🔧 Performance: Optimize database queries and add indexing",
            "🔧 Performance: Use CDN for static asset delivery",
            "🔧 Performance: Implement request rate limiting",
            "🔧 Performance: Add health checks for all services"
        ])
        
        # Security and reliability recommendations
        recommendations.extend([
            "🔒 Security: Enable all security features for production",
            "🔒 Security: Implement proper authentication and authorization",
            "🔒 Security: Use HTTPS for all communications",
            "🔧 Reliability: Implement retry mechanisms with exponential backoff",
            "🔧 Reliability: Add graceful degradation for service failures"
        ])
        
        return recommendations
    
    def generate_final_report(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive final load testing report."""
        report_lines = []
        
        # Header
        report_lines.extend([
            "="*100,
            "VOICEFLOW COMPREHENSIVE LOAD TESTING REPORT",
            "="*100,
            "",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Test Duration: {results.get('test_metadata', {}).get('total_duration_seconds', 0):.1f} seconds",
            f"Framework Version: {results.get('test_metadata', {}).get('framework_version', 'Unknown')}",
            ""
        ])
        
        # Executive Summary
        production_readiness = results.get("production_readiness", {})
        
        report_lines.extend([
            "EXECUTIVE SUMMARY",
            "-" * 50,
            f"Overall Readiness Score: {production_readiness.get('readiness_score', 0):.1f}/100",
            f"Production Readiness: {'✅ READY' if production_readiness.get('overall_ready', False) else '❌ NOT READY'}",
            f"Grade: {production_readiness.get('grade', 'Unknown')}",
            f"Deployment Recommendation: {production_readiness.get('deployment_recommendation', 'Unknown')}",
            ""
        ])
        
        # Component Readiness Summary
        component_readiness = production_readiness.get("component_readiness", {})
        
        report_lines.extend([
            "COMPONENT READINESS SUMMARY",
            "-" * 50
        ])
        
        for component, readiness in component_readiness.items():
            status = "✅ READY" if readiness.get("ready", False) else "❌ NOT READY"
            score = readiness.get("score", 0)
            grade = readiness.get("grade", "Unknown")
            report_lines.append(f"{component.upper()}: {status} (Score: {score:.1f}, Grade: {grade})")
        
        report_lines.append("")
        
        # Critical Issues
        critical_issues = production_readiness.get("critical_issues", [])
        if critical_issues:
            report_lines.extend([
                "CRITICAL ISSUES",
                "-" * 50
            ])
            for issue in critical_issues:
                report_lines.append(f"❌ {issue}")
            report_lines.append("")
        
        # Capacity Planning
        capacity_planning = results.get("capacity_planning", {})
        if capacity_planning:
            report_lines.extend([
                "CAPACITY PLANNING GUIDELINES",
                "-" * 50
            ])
            
            deployment_config = capacity_planning.get("recommended_deployment_config", {})
            for component, config in deployment_config.items():
                report_lines.append(f"{component.upper()}:")
                for key, value in config.items():
                    report_lines.append(f"  {key}: {value}")
                report_lines.append("")
        
        # Recommendations
        recommendations = results.get("recommendations", [])
        if recommendations:
            report_lines.extend([
                "OPTIMIZATION RECOMMENDATIONS",
                "-" * 50
            ])
            for rec in recommendations:
                report_lines.append(f"• {rec}")
            report_lines.append("")
        
        # System Limits Identified
        analysis_summary = results.get("analysis_summary", {})
        system_limits = analysis_summary.get("system_limits", {})
        
        if system_limits:
            report_lines.extend([
                "IDENTIFIED SYSTEM LIMITS",
                "-" * 50
            ])
            for limit_type, limit_value in system_limits.items():
                report_lines.append(f"{limit_type}: {limit_value}")
            report_lines.append("")
        
        # Footer
        report_lines.extend([
            "="*100,
            "END OF REPORT",
            "="*100
        ])
        
        return "\n".join(report_lines)
    
    async def execute_and_report(self) -> Tuple[Dict[str, Any], str]:
        """Execute comprehensive load testing and generate final report."""
        print("Starting VoiceFlow Comprehensive Load Testing...")
        
        # Execute comprehensive load testing
        results = await self.run_comprehensive_load_testing()
        
        # Generate final report
        report = self.generate_final_report(results)
        
        # Save comprehensive results
        results_file = self.results_dir / "comprehensive_load_test_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Save final report
        report_file = self.results_dir / "COMPREHENSIVE_LOAD_TESTING_REPORT.md"
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(f"\nComprehensive results saved to: {results_file}")
        print(f"Final report saved to: {report_file}")
        
        return results, report


async def main():
    """Main execution function."""
    orchestrator = LoadTestingOrchestrator()
    
    try:
        results, report = await orchestrator.execute_and_report()
        
        # Print final report to console
        print("\n" + report)
        
        # Print final summary
        production_readiness = results.get("production_readiness", {})
        print(f"\n{'='*60}")
        print("FINAL SUMMARY")
        print(f"{'='*60}")
        print(f"Overall Score: {production_readiness.get('readiness_score', 0):.1f}/100")
        print(f"Grade: {production_readiness.get('grade', 'Unknown')}")
        print(f"Production Ready: {'✅ YES' if production_readiness.get('overall_ready', False) else '❌ NO'}")
        print(f"{'='*60}")
        
        return results
        
    except Exception as e:
        print(f"Load testing execution failed: {e}")
        traceback.print_exc()
        return None


if __name__ == "__main__":
    results = asyncio.run(main())