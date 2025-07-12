#!/usr/bin/env python3
"""
VoiceFlow AI Enhancement Pipeline Load Testing Module
====================================================

Specialized load testing framework for AI enhancement pipeline focusing on:
1. Concurrent AI processing request handling
2. Response time scaling with increased load
3. Queue management and backlog processing
4. Ollama integration performance under stress
5. Context-aware processing efficiency
6. Resource utilization during AI operations
7. Error handling and recovery mechanisms

This module validates the production readiness of VoiceFlow's AI enhancement
capabilities under various load conditions and usage patterns.

Author: Senior Load Testing Expert
Version: 1.0.0
Focus: AI Enhancement Pipeline Scalability
"""

import asyncio
import json
import statistics
import time
import threading
import requests
import psutil
import gc
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Callable
from unittest.mock import Mock, patch
import numpy as np

# Import VoiceFlow components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from core.ai_enhancement import AIEnhancer, create_enhancer
    AI_ENHANCEMENT_AVAILABLE = True
except ImportError:
    AI_ENHANCEMENT_AVAILABLE = False


@dataclass
class AIEnhancementMetrics:
    """Comprehensive AI enhancement performance metrics."""
    
    # Processing metrics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    processing_times: List[float] = field(default_factory=list)
    
    # Context-specific metrics
    context_performance: Dict[str, List[float]] = field(default_factory=dict)
    
    # Text size metrics
    text_size_performance: Dict[str, List[float]] = field(default_factory=dict)
    
    # Queue metrics
    queue_wait_times: List[float] = field(default_factory=list)
    max_queue_size: int = 0
    queue_overflow_count: int = 0
    
    # Error tracking
    error_types: Dict[str, int] = field(default_factory=dict)
    timeout_count: int = 0
    
    # Resource metrics
    memory_usage_samples: List[float] = field(default_factory=list)
    cpu_usage_samples: List[float] = field(default_factory=list)
    
    @property
    def success_rate(self) -> float:
        """Success rate percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100
    
    @property
    def avg_processing_time(self) -> float:
        """Average processing time in milliseconds."""
        return statistics.mean(self.processing_times) * 1000 if self.processing_times else 0.0
    
    @property
    def throughput_per_second(self) -> float:
        """Requests processed per second."""
        if not self.processing_times:
            return 0.0
        total_time = sum(self.processing_times)
        return len(self.processing_times) / total_time if total_time > 0 else 0.0


class MockOllamaServer:
    """Mock Ollama server for controlled load testing."""
    
    def __init__(self, response_delay: float = 0.1, error_rate: float = 0.0):
        self.response_delay = response_delay
        self.error_rate = error_rate
        self.request_count = 0
        self.active_requests = 0
        self.max_concurrent_requests = 0
        
    def process_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process AI enhancement request with configurable delays and errors."""
        self.request_count += 1
        self.active_requests += 1
        self.max_concurrent_requests = max(self.max_concurrent_requests, self.active_requests)
        
        try:
            # Simulate processing delay based on text length
            text_length = len(request_data.get("prompt", ""))
            base_delay = self.response_delay
            length_factor = min(text_length / 100, 3.0)  # Scale up to 3x for very long text
            actual_delay = base_delay * (1 + length_factor * 0.5)
            
            time.sleep(actual_delay)
            
            # Simulate random errors
            if np.random.random() < self.error_rate:
                raise Exception("Simulated AI processing error")
            
            # Generate enhanced response
            original_text = request_data.get("prompt", "").replace("Format this text: ", "")
            context = "general"  # Default context
            
            if "email" in request_data.get("prompt", "").lower():
                context = "email"
            elif "code" in request_data.get("prompt", "").lower():
                context = "code"
            elif "document" in request_data.get("prompt", "").lower():
                context = "document"
            
            # Context-aware response simulation
            if context == "email":
                enhanced_text = original_text.strip().capitalize()
                if not enhanced_text.endswith(('.', '!', '?')):
                    enhanced_text += '.'
                enhanced_text = f"Dear recipient,\n\n{enhanced_text}\n\nBest regards"
            elif context == "code":
                enhanced_text = f"```\n{original_text}\n```"
            elif context == "document":
                enhanced_text = original_text.strip().capitalize()
                if not enhanced_text.endswith(('.', '!', '?')):
                    enhanced_text += '.'
            else:
                enhanced_text = original_text.strip().capitalize()
                if not enhanced_text.endswith(('.', '!', '?')):
                    enhanced_text += '.'
            
            return {
                "response": enhanced_text,
                "model": request_data.get("model", "test_model"),
                "context": context,
                "processing_time": actual_delay
            }
        
        finally:
            self.active_requests -= 1


class AIEnhancementLoadTester:
    """Comprehensive AI enhancement load testing framework."""
    
    def __init__(self):
        self.metrics = AIEnhancementMetrics()
        self.mock_server = MockOllamaServer()
        self.resource_monitor_active = False
        self.resource_samples = []
        
        # Test text samples for different scenarios
        self.test_texts = {
            "short": [
                "hello world",
                "test message",
                "quick note",
                "thanks",
                "help needed"
            ],
            "medium": [
                "this is a medium length text that contains several sentences and should take moderate time to process",
                "please help me format this email message for professional communication with my colleagues",
                "i need to transcribe this meeting discussion and make it more formal for documentation purposes",
                "can you enhance this text to make it suitable for a business proposal presentation",
                "transform this casual conversation into proper written format for official records"
            ],
            "long": [
                "this is a very long text sample that contains multiple paragraphs and complex formatting requirements " * 10,
                "comprehensive business proposal document with detailed analysis " * 15,
                "technical documentation with multiple sections and subsections " * 12,
                "meeting transcript with various speakers and topics discussed " * 8,
                "research paper content with citations and references " * 20
            ]
        }
        
        self.test_contexts = ["general", "email", "chat", "document", "code"]
        
    def start_resource_monitoring(self):
        """Start monitoring system resources during AI load testing."""
        self.resource_monitor_active = True
        self.resource_samples = []
        
        def monitor_resources():
            while self.resource_monitor_active:
                try:
                    process = psutil.Process()
                    sample = {
                        'timestamp': time.time(),
                        'cpu_percent': process.cpu_percent(),
                        'memory_rss_mb': process.memory_info().rss / 1024 / 1024,
                        'memory_percent': process.memory_percent(),
                        'num_threads': process.num_threads()
                    }
                    self.resource_samples.append(sample)
                    
                    # Also track AI-specific metrics
                    self.metrics.memory_usage_samples.append(sample['memory_rss_mb'])
                    self.metrics.cpu_usage_samples.append(sample['cpu_percent'])
                    
                except Exception:
                    pass
                
                time.sleep(1.0)
        
        self.monitor_thread = threading.Thread(target=monitor_resources, daemon=True)
        self.monitor_thread.start()
    
    def stop_resource_monitoring(self):
        """Stop resource monitoring."""
        self.resource_monitor_active = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=2)
    
    async def test_concurrent_processing(self, 
                                       concurrent_requests: int = 20,
                                       requests_per_worker: int = 10) -> Dict[str, Any]:
        """Test AI enhancement under concurrent request load."""
        print(f"[AI LOAD] Testing concurrent processing: {concurrent_requests} workers, {requests_per_worker} requests each")
        
        self.start_resource_monitoring()
        
        try:
            # Mock Ollama responses for consistent testing
            with patch('requests.Session.post') as mock_post:
                # Configure mock response
                def mock_ollama_response(*args, **kwargs):
                    response_mock = Mock()
                    response_mock.status_code = 200
                    
                    # Extract request data
                    request_data = kwargs.get('json', {})
                    
                    # Process through mock server
                    result = self.mock_server.process_request(request_data)
                    response_mock.json.return_value = result
                    
                    return response_mock
                
                mock_post.side_effect = mock_ollama_response
                
                async def worker_task(worker_id: int) -> Dict[str, Any]:
                    """Individual worker processing requests."""
                    worker_metrics = AIEnhancementMetrics()
                    worker_start = time.time()
                    
                    # Create AI enhancer instance
                    enhancer = create_enhancer({"enabled": True})
                    
                    for request_id in range(requests_per_worker):
                        try:
                            # Select test text and context
                            text_category = np.random.choice(["short", "medium", "long"], p=[0.5, 0.3, 0.2])
                            test_text = np.random.choice(self.test_texts[text_category])
                            context = np.random.choice(self.test_contexts)
                            
                            # Process enhancement request
                            request_start = time.time()
                            enhanced_text = enhancer.enhance_text(test_text, context)
                            request_time = time.time() - request_start
                            
                            # Record metrics
                            worker_metrics.total_requests += 1
                            worker_metrics.processing_times.append(request_time)
                            
                            if enhanced_text and enhanced_text != test_text:
                                worker_metrics.successful_requests += 1
                            else:
                                worker_metrics.failed_requests += 1
                            
                            # Track context-specific performance
                            if context not in worker_metrics.context_performance:
                                worker_metrics.context_performance[context] = []
                            worker_metrics.context_performance[context].append(request_time)
                            
                            # Track text size performance
                            if text_category not in worker_metrics.text_size_performance:
                                worker_metrics.text_size_performance[text_category] = []
                            worker_metrics.text_size_performance[text_category].append(request_time)
                            
                        except Exception as e:
                            worker_metrics.failed_requests += 1
                            worker_metrics.total_requests += 1
                            error_type = type(e).__name__
                            worker_metrics.error_types[error_type] = \
                                worker_metrics.error_types.get(error_type, 0) + 1
                        
                        # Small delay between requests to simulate realistic usage
                        await asyncio.sleep(0.1)
                    
                    worker_duration = time.time() - worker_start
                    
                    return {
                        "worker_id": worker_id,
                        "total_requests": worker_metrics.total_requests,
                        "successful_requests": worker_metrics.successful_requests,
                        "success_rate": worker_metrics.success_rate,
                        "avg_processing_time_ms": worker_metrics.avg_processing_time,
                        "total_time": worker_duration,
                        "throughput": worker_metrics.throughput_per_second,
                        "context_performance": {
                            ctx: statistics.mean(times) * 1000 
                            for ctx, times in worker_metrics.context_performance.items()
                        },
                        "text_size_performance": {
                            size: statistics.mean(times) * 1000
                            for size, times in worker_metrics.text_size_performance.items()
                        },
                        "errors": dict(worker_metrics.error_types)
                    }
                
                # Execute concurrent workers
                test_start = time.time()
                
                tasks = [worker_task(i) for i in range(concurrent_requests)]
                worker_results = await asyncio.gather(*tasks)
                
                test_duration = time.time() - test_start
                
                # Aggregate results
                total_requests = sum(r["total_requests"] for r in worker_results)
                total_successful = sum(r["successful_requests"] for r in worker_results)
                avg_success_rate = statistics.mean([r["success_rate"] for r in worker_results])
                avg_processing_times = [r["avg_processing_time_ms"] for r in worker_results if r["avg_processing_time_ms"] > 0]
                
                # Aggregate context performance
                all_context_performance = {}
                for result in worker_results:
                    for context, perf in result["context_performance"].items():
                        if context not in all_context_performance:
                            all_context_performance[context] = []
                        all_context_performance[context].append(perf)
                
                context_averages = {
                    ctx: statistics.mean(times) 
                    for ctx, times in all_context_performance.items()
                }
                
                return {
                    "test_config": {
                        "concurrent_requests": concurrent_requests,
                        "requests_per_worker": requests_per_worker,
                        "total_expected_requests": concurrent_requests * requests_per_worker
                    },
                    "performance_results": {
                        "test_duration": test_duration,
                        "total_requests": total_requests,
                        "successful_requests": total_successful,
                        "overall_success_rate": (total_successful / total_requests * 100) if total_requests > 0 else 0,
                        "avg_success_rate": avg_success_rate,
                        "overall_throughput": total_requests / test_duration,
                        "avg_processing_time_ms": statistics.mean(avg_processing_times) if avg_processing_times else 0,
                        "processing_time_p95_ms": np.percentile(avg_processing_times, 95) if avg_processing_times else 0,
                        "max_concurrent_handled": self.mock_server.max_concurrent_requests
                    },
                    "context_analysis": context_averages,
                    "worker_details": worker_results
                }
        
        finally:
            self.stop_resource_monitoring()
    
    async def test_queue_management(self, 
                                  burst_size: int = 50,
                                  processing_capacity: int = 5) -> Dict[str, Any]:
        """Test AI enhancement queue management under burst loads."""
        print(f"[AI LOAD] Testing queue management: burst of {burst_size} requests, capacity {processing_capacity}")
        
        # Configure mock server with limited capacity
        self.mock_server = MockOllamaServer(response_delay=0.5, error_rate=0.05)
        
        # Simulate queue with semaphore
        processing_semaphore = asyncio.Semaphore(processing_capacity)
        queue_metrics = {
            "requests_queued": 0,
            "requests_processed": 0,
            "queue_wait_times": [],
            "processing_times": [],
            "queue_size_samples": []
        }
        
        async def process_with_queue(request_id: int, text: str, context: str) -> Dict[str, Any]:
            """Process request through queue with capacity limits."""
            queue_start = time.time()
            queue_metrics["requests_queued"] += 1
            
            # Wait for processing slot
            async with processing_semaphore:
                queue_wait_time = time.time() - queue_start
                queue_metrics["queue_wait_times"].append(queue_wait_time)
                
                # Sample current queue size
                queue_size = queue_metrics["requests_queued"] - queue_metrics["requests_processed"]
                queue_metrics["queue_size_samples"].append(queue_size)
                
                try:
                    # Simulate AI processing
                    process_start = time.time()
                    
                    with patch('requests.Session.post') as mock_post:
                        response_mock = Mock()
                        response_mock.status_code = 200
                        
                        result = self.mock_server.process_request({
                            "prompt": f"Format this {context} text: {text}",
                            "model": "test_model"
                        })
                        response_mock.json.return_value = result
                        mock_post.return_value = response_mock
                        
                        enhancer = create_enhancer({"enabled": True})
                        enhanced = enhancer.enhance_text(text, context)
                    
                    process_time = time.time() - process_start
                    queue_metrics["processing_times"].append(process_time)
                    queue_metrics["requests_processed"] += 1
                    
                    return {
                        "request_id": request_id,
                        "success": True,
                        "queue_wait_time": queue_wait_time,
                        "processing_time": process_time,
                        "enhanced_text": enhanced
                    }
                
                except Exception as e:
                    queue_metrics["requests_processed"] += 1
                    return {
                        "request_id": request_id,
                        "success": False,
                        "error": str(e),
                        "queue_wait_time": queue_wait_time
                    }
        
        # Generate burst of requests
        burst_start = time.time()
        
        tasks = []
        for i in range(burst_size):
            text = np.random.choice(self.test_texts["medium"])
            context = np.random.choice(self.test_contexts)
            
            task = process_with_queue(i, text, context)
            tasks.append(task)
            
            # Small stagger to simulate burst arrival
            if i < burst_size - 1:
                await asyncio.sleep(0.01)
        
        # Wait for all requests to complete
        results = await asyncio.gather(*tasks)
        burst_duration = time.time() - burst_start
        
        # Analyze queue performance
        successful_results = [r for r in results if r.get("success", False)]
        failed_results = [r for r in results if not r.get("success", False)]
        
        return {
            "test_config": {
                "burst_size": burst_size,
                "processing_capacity": processing_capacity,
                "arrival_rate": burst_size / 0.5  # requests per second during burst
            },
            "queue_performance": {
                "total_requests": len(results),
                "successful_requests": len(successful_results),
                "failed_requests": len(failed_results),
                "success_rate": (len(successful_results) / len(results) * 100) if results else 0,
                "total_duration": burst_duration,
                "avg_queue_wait_time_ms": statistics.mean(queue_metrics["queue_wait_times"]) * 1000 if queue_metrics["queue_wait_times"] else 0,
                "max_queue_wait_time_ms": max(queue_metrics["queue_wait_times"]) * 1000 if queue_metrics["queue_wait_times"] else 0,
                "avg_processing_time_ms": statistics.mean(queue_metrics["processing_times"]) * 1000 if queue_metrics["processing_times"] else 0,
                "max_queue_size": max(queue_metrics["queue_size_samples"]) if queue_metrics["queue_size_samples"] else 0,
                "throughput_requests_per_sec": len(successful_results) / burst_duration,
                "queue_efficiency": (len(successful_results) / processing_capacity / burst_duration) if burst_duration > 0 else 0
            },
            "detailed_results": results
        }
    
    async def test_scaling_characteristics(self, 
                                         load_levels: List[int] = [1, 5, 10, 20, 30]) -> Dict[str, Any]:
        """Test AI enhancement scaling characteristics across different load levels."""
        print(f"[AI LOAD] Testing scaling characteristics across load levels: {load_levels}")
        
        scaling_results = {}
        
        for load_level in load_levels:
            print(f"    Testing load level: {load_level} concurrent requests")
            
            # Test at this load level
            load_result = await self.test_concurrent_processing(
                concurrent_requests=load_level,
                requests_per_worker=5  # Smaller number for scaling test
            )
            
            # Extract key metrics for scaling analysis
            perf_results = load_result.get("performance_results", {})
            
            scaling_results[f"load_{load_level}"] = {
                "concurrent_requests": load_level,
                "success_rate": perf_results.get("overall_success_rate", 0),
                "avg_processing_time_ms": perf_results.get("avg_processing_time_ms", 0),
                "throughput_rps": perf_results.get("overall_throughput", 0),
                "efficiency": perf_results.get("overall_throughput", 0) / load_level if load_level > 0 else 0,
                "max_concurrent_handled": perf_results.get("max_concurrent_handled", 0)
            }
            
            # Brief pause between load levels
            await asyncio.sleep(2)
            gc.collect()  # Force garbage collection
        
        # Analyze scaling characteristics
        load_points = list(scaling_results.keys())
        success_rates = [scaling_results[lp]["success_rate"] for lp in load_points]
        processing_times = [scaling_results[lp]["avg_processing_time_ms"] for lp in load_points]
        throughputs = [scaling_results[lp]["throughput_rps"] for lp in load_points]
        efficiencies = [scaling_results[lp]["efficiency"] for lp in load_points]
        
        return {
            "load_levels_tested": load_levels,
            "scaling_results": scaling_results,
            "scaling_analysis": {
                "linear_scaling_limit": self._find_linear_scaling_limit(load_levels, throughputs),
                "performance_degradation": {
                    "success_rate_drop": max(success_rates) - min(success_rates) if success_rates else 0,
                    "processing_time_increase": max(processing_times) - min(processing_times) if processing_times else 0,
                    "efficiency_drop": max(efficiencies) - min(efficiencies) if efficiencies else 0
                },
                "optimal_concurrency": load_levels[throughputs.index(max(throughputs))] if throughputs else 0,
                "scalability_rating": self._rate_scalability(success_rates, throughputs, efficiencies)
            }
        }
    
    def _find_linear_scaling_limit(self, load_levels: List[int], throughputs: List[float]) -> int:
        """Find the point where linear scaling breaks down."""
        if len(load_levels) < 3 or len(throughputs) < 3:
            return load_levels[0] if load_levels else 0
        
        # Calculate efficiency (throughput per unit load)
        efficiencies = [t / l for t, l in zip(throughputs, load_levels) if l > 0]
        
        # Find point where efficiency drops significantly
        for i in range(1, len(efficiencies)):
            efficiency_drop = (efficiencies[0] - efficiencies[i]) / efficiencies[0]
            if efficiency_drop > 0.2:  # 20% efficiency drop
                return load_levels[i]
        
        return load_levels[-1]  # All levels scale linearly
    
    def _rate_scalability(self, success_rates: List[float], throughputs: List[float], efficiencies: List[float]) -> str:
        """Rate the overall scalability performance."""
        if not all([success_rates, throughputs, efficiencies]):
            return "unknown"
        
        # Check for consistent high performance
        min_success_rate = min(success_rates)
        efficiency_variance = statistics.stdev(efficiencies) if len(efficiencies) > 1 else 0
        throughput_growth = (throughputs[-1] / throughputs[0]) if throughputs[0] > 0 else 0
        
        if min_success_rate > 95 and efficiency_variance < 0.1 and throughput_growth > 2:
            return "excellent"
        elif min_success_rate > 90 and efficiency_variance < 0.2 and throughput_growth > 1.5:
            return "good"
        elif min_success_rate > 80 and throughput_growth > 1.2:
            return "acceptable"
        else:
            return "needs_improvement"
    
    async def test_error_handling_and_recovery(self, error_rate: float = 0.2) -> Dict[str, Any]:
        """Test AI enhancement error handling and recovery under stress."""
        print(f"[AI LOAD] Testing error handling with {error_rate*100:.1f}% error rate")
        
        # Configure mock server with high error rate
        self.mock_server = MockOllamaServer(response_delay=0.2, error_rate=error_rate)
        
        error_test_results = []
        recovery_metrics = {
            "consecutive_failures": [],
            "recovery_times": [],
            "circuit_breaker_activations": 0
        }
        
        with patch('requests.Session.post') as mock_post:
            def error_prone_response(*args, **kwargs):
                response_mock = Mock()
                
                try:
                    result = self.mock_server.process_request(kwargs.get('json', {}))
                    response_mock.status_code = 200
                    response_mock.json.return_value = result
                except Exception:
                    # Simulate different types of failures
                    failure_type = np.random.choice(["timeout", "server_error", "invalid_response"])
                    
                    if failure_type == "timeout":
                        response_mock.status_code = 408
                        response_mock.text = "Request timeout"
                    elif failure_type == "server_error":
                        response_mock.status_code = 500
                        response_mock.text = "Internal server error"
                    else:
                        response_mock.status_code = 200
                        response_mock.json.return_value = {"error": "Invalid response format"}
                
                return response_mock
            
            mock_post.side_effect = error_prone_response
            
            # Test recovery behavior
            enhancer = create_enhancer({"enabled": True})
            consecutive_failures = 0
            
            for i in range(50):  # Test with 50 requests
                test_text = np.random.choice(self.test_texts["medium"])
                
                try:
                    start_time = time.time()
                    enhanced = enhancer.enhance_text(test_text, "general")
                    processing_time = time.time() - start_time
                    
                    if enhanced and enhanced != test_text:
                        # Success - reset failure counter
                        if consecutive_failures > 0:
                            recovery_metrics["recovery_times"].append(i)
                            consecutive_failures = 0
                        
                        error_test_results.append({
                            "request_id": i,
                            "success": True,
                            "processing_time": processing_time,
                            "consecutive_failures_before": consecutive_failures
                        })
                    else:
                        # Enhancement failed
                        consecutive_failures += 1
                        error_test_results.append({
                            "request_id": i,
                            "success": False,
                            "error_type": "enhancement_failed",
                            "consecutive_failures": consecutive_failures
                        })
                
                except Exception as e:
                    consecutive_failures += 1
                    error_test_results.append({
                        "request_id": i,
                        "success": False,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                        "consecutive_failures": consecutive_failures
                    })
                
                # Record consecutive failures
                if consecutive_failures > 0:
                    recovery_metrics["consecutive_failures"].append(consecutive_failures)
                
                await asyncio.sleep(0.1)  # Small delay between requests
        
        # Analyze error handling results
        successful_requests = [r for r in error_test_results if r.get("success", False)]
        failed_requests = [r for r in error_test_results if not r.get("success", False)]
        
        return {
            "test_config": {
                "simulated_error_rate": error_rate,
                "total_requests": len(error_test_results)
            },
            "error_handling_performance": {
                "actual_success_rate": (len(successful_requests) / len(error_test_results) * 100) if error_test_results else 0,
                "total_failures": len(failed_requests),
                "max_consecutive_failures": max(recovery_metrics["consecutive_failures"]) if recovery_metrics["consecutive_failures"] else 0,
                "avg_consecutive_failures": statistics.mean(recovery_metrics["consecutive_failures"]) if recovery_metrics["consecutive_failures"] else 0,
                "recovery_rate": len(recovery_metrics["recovery_times"]) / len(failed_requests) if failed_requests else 0,
                "error_types": self._analyze_error_types(failed_requests)
            },
            "resilience_rating": self._rate_error_resilience(len(successful_requests), len(failed_requests), recovery_metrics),
            "detailed_results": error_test_results
        }
    
    def _analyze_error_types(self, failed_requests: List[Dict]) -> Dict[str, int]:
        """Analyze types of errors encountered."""
        error_counts = {}
        for request in failed_requests:
            error_type = request.get("error_type", "unknown")
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
        return error_counts
    
    def _rate_error_resilience(self, successes: int, failures: int, recovery_metrics: Dict) -> str:
        """Rate the error resilience of the AI enhancement system."""
        total_requests = successes + failures
        if total_requests == 0:
            return "unknown"
        
        success_rate = successes / total_requests
        max_consecutive_failures = max(recovery_metrics["consecutive_failures"]) if recovery_metrics["consecutive_failures"] else 0
        
        if success_rate > 0.8 and max_consecutive_failures < 3:
            return "excellent"
        elif success_rate > 0.7 and max_consecutive_failures < 5:
            return "good"
        elif success_rate > 0.6:
            return "acceptable"
        else:
            return "needs_improvement"
    
    async def run_comprehensive_ai_load_tests(self) -> Dict[str, Any]:
        """Run comprehensive AI enhancement load testing scenarios."""
        print("\n" + "="*70)
        print("AI ENHANCEMENT PIPELINE COMPREHENSIVE LOAD TESTING")
        print("="*70)
        
        all_results = {
            "test_metadata": {
                "start_time": time.time(),
                "ai_enhancement_available": AI_ENHANCEMENT_AVAILABLE
            }
        }
        
        if not AI_ENHANCEMENT_AVAILABLE:
            print("[WARNING] AI Enhancement components not available - using mocked tests")
        
        # Test 1: Concurrent Processing
        print("\n[TEST 1] Concurrent Processing Load")
        all_results["concurrent_processing"] = await self.test_concurrent_processing(
            concurrent_requests=15,
            requests_per_worker=8
        )
        
        # Test 2: Queue Management
        print("\n[TEST 2] Queue Management Under Burst Load")
        all_results["queue_management"] = await self.test_queue_management(
            burst_size=30,
            processing_capacity=5
        )
        
        # Test 3: Scaling Characteristics
        print("\n[TEST 3] Scaling Characteristics Analysis")
        all_results["scaling_characteristics"] = await self.test_scaling_characteristics(
            load_levels=[1, 3, 5, 10, 15]
        )
        
        # Test 4: Error Handling and Recovery
        print("\n[TEST 4] Error Handling and Recovery")
        all_results["error_handling"] = await self.test_error_handling_and_recovery(
            error_rate=0.15
        )
        
        # Generate comprehensive analysis
        all_results["ai_load_analysis"] = self._generate_ai_load_analysis(all_results)
        all_results["production_readiness"] = self._assess_ai_production_readiness(all_results)
        
        all_results["test_metadata"]["end_time"] = time.time()
        all_results["test_metadata"]["total_duration"] = all_results["test_metadata"]["end_time"] - all_results["test_metadata"]["start_time"]
        
        return all_results
    
    def _generate_ai_load_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive AI load test analysis."""
        analysis = {
            "performance_characteristics": {},
            "scalability_assessment": {},
            "reliability_metrics": {},
            "queue_efficiency": {},
            "resource_utilization": {}
        }
        
        # Analyze concurrent processing performance
        if "concurrent_processing" in results:
            concurrent = results["concurrent_processing"]["performance_results"]
            analysis["performance_characteristics"] = {
                "max_tested_concurrency": results["concurrent_processing"]["test_config"]["concurrent_requests"],
                "success_rate": concurrent.get("overall_success_rate", 0),
                "avg_processing_time_ms": concurrent.get("avg_processing_time_ms", 0),
                "throughput_rps": concurrent.get("overall_throughput", 0),
                "performance_rating": "excellent" if concurrent.get("avg_processing_time_ms", 1000) < 500 else ("good" if concurrent.get("avg_processing_time_ms", 1000) < 1000 else "needs_improvement")
            }
        
        # Analyze scaling characteristics
        if "scaling_characteristics" in results:
            scaling = results["scaling_characteristics"]["scaling_analysis"]
            analysis["scalability_assessment"] = {
                "linear_scaling_limit": scaling.get("linear_scaling_limit", 0),
                "optimal_concurrency": scaling.get("optimal_concurrency", 0),
                "scalability_rating": scaling.get("scalability_rating", "unknown"),
                "performance_degradation": scaling.get("performance_degradation", {})
            }
        
        # Analyze queue management
        if "queue_management" in results:
            queue = results["queue_management"]["queue_performance"]
            analysis["queue_efficiency"] = {
                "max_queue_size": queue.get("max_queue_size", 0),
                "avg_queue_wait_ms": queue.get("avg_queue_wait_time_ms", 0),
                "queue_efficiency": queue.get("queue_efficiency", 0),
                "queue_rating": "excellent" if queue.get("avg_queue_wait_time_ms", 1000) < 100 else ("good" if queue.get("avg_queue_wait_time_ms", 1000) < 500 else "needs_improvement")
            }
        
        # Analyze error handling
        if "error_handling" in results:
            error_handling = results["error_handling"]["error_handling_performance"]
            analysis["reliability_metrics"] = {
                "error_resilience_rating": results["error_handling"]["resilience_rating"],
                "success_rate_under_errors": error_handling.get("actual_success_rate", 0),
                "max_consecutive_failures": error_handling.get("max_consecutive_failures", 0),
                "recovery_capability": error_handling.get("recovery_rate", 0)
            }
        
        return analysis
    
    def _assess_ai_production_readiness(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess AI enhancement production readiness based on load test results."""
        readiness_factors = {
            "performance": 0,
            "scalability": 0,
            "reliability": 0,
            "queue_management": 0
        }
        
        # Evaluate performance (25 points)
        if "ai_load_analysis" in results:
            analysis = results["ai_load_analysis"]
            
            # Performance assessment
            perf_rating = analysis.get("performance_characteristics", {}).get("performance_rating", "needs_improvement")
            if perf_rating == "excellent":
                readiness_factors["performance"] = 25
            elif perf_rating == "good":
                readiness_factors["performance"] = 20
            else:
                readiness_factors["performance"] = 10
            
            # Scalability assessment
            scalability_rating = analysis.get("scalability_assessment", {}).get("scalability_rating", "needs_improvement")
            if scalability_rating == "excellent":
                readiness_factors["scalability"] = 25
            elif scalability_rating == "good":
                readiness_factors["scalability"] = 20
            elif scalability_rating == "acceptable":
                readiness_factors["scalability"] = 15
            else:
                readiness_factors["scalability"] = 5
            
            # Reliability assessment
            resilience_rating = analysis.get("reliability_metrics", {}).get("error_resilience_rating", "needs_improvement")
            if resilience_rating == "excellent":
                readiness_factors["reliability"] = 25
            elif resilience_rating == "good":
                readiness_factors["reliability"] = 20
            elif resilience_rating == "acceptable":
                readiness_factors["reliability"] = 15
            else:
                readiness_factors["reliability"] = 5
            
            # Queue management assessment
            queue_rating = analysis.get("queue_efficiency", {}).get("queue_rating", "needs_improvement")
            if queue_rating == "excellent":
                readiness_factors["queue_management"] = 25
            elif queue_rating == "good":
                readiness_factors["queue_management"] = 20
            else:
                readiness_factors["queue_management"] = 10
        
        total_score = sum(readiness_factors.values())
        
        # Assign grade
        if total_score >= 90:
            grade = "A"
            ready = True
        elif total_score >= 80:
            grade = "B"
            ready = True
        elif total_score >= 70:
            grade = "C"
            ready = True  # With monitoring
        else:
            grade = "D"
            ready = False
        
        return {
            "overall_score": total_score,
            "grade": grade,
            "production_ready": ready,
            "readiness_factors": readiness_factors,
            "recommendations": self._generate_ai_recommendations(results, total_score),
            "capacity_planning": self._generate_ai_capacity_planning(results)
        }
    
    def _generate_ai_recommendations(self, results: Dict[str, Any], score: int) -> List[str]:
        """Generate AI enhancement optimization recommendations."""
        recommendations = []
        
        if score < 90:
            recommendations.append("Implement comprehensive AI performance monitoring")
        
        if "ai_load_analysis" in results:
            analysis = results["ai_load_analysis"]
            
            # Performance recommendations
            if analysis.get("performance_characteristics", {}).get("avg_processing_time_ms", 0) > 1000:
                recommendations.append("Optimize AI model selection for faster processing")
                recommendations.append("Consider implementing response caching for frequently enhanced text")
            
            # Scalability recommendations
            if analysis.get("scalability_assessment", {}).get("scalability_rating") != "excellent":
                recommendations.append("Implement async AI processing to improve concurrency")
                recommendations.append("Consider horizontal scaling with multiple Ollama instances")
            
            # Queue management recommendations
            if analysis.get("queue_efficiency", {}).get("avg_queue_wait_ms", 0) > 500:
                recommendations.append("Implement intelligent queue management with priority levels")
                recommendations.append("Add circuit breaker pattern for AI service protection")
            
            # Reliability recommendations
            if analysis.get("reliability_metrics", {}).get("error_resilience_rating") != "excellent":
                recommendations.append("Enhance error handling and retry mechanisms")
                recommendations.append("Implement fallback to basic text formatting when AI fails")
        
        return recommendations
    
    def _generate_ai_capacity_planning(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI enhancement capacity planning guidelines."""
        capacity_planning = {
            "recommended_max_concurrent": 10,
            "optimal_processing_rate": 5,
            "queue_size_limit": 50,
            "monitoring_thresholds": {}
        }
        
        if "ai_load_analysis" in results:
            analysis = results["ai_load_analysis"]
            
            # Set capacity based on optimal concurrency
            optimal_concurrency = analysis.get("scalability_assessment", {}).get("optimal_concurrency", 10)
            capacity_planning["recommended_max_concurrent"] = int(optimal_concurrency * 0.8)  # 80% of tested capacity
            
            # Set processing rate based on throughput
            throughput = analysis.get("performance_characteristics", {}).get("throughput_rps", 5)
            capacity_planning["optimal_processing_rate"] = max(int(throughput * 0.7), 1)  # 70% of max throughput
            
            # Set monitoring thresholds
            avg_processing_time = analysis.get("performance_characteristics", {}).get("avg_processing_time_ms", 500)
            capacity_planning["monitoring_thresholds"] = {
                "processing_time_warning_ms": avg_processing_time * 1.5,
                "processing_time_critical_ms": avg_processing_time * 2.0,
                "queue_size_warning": 20,
                "queue_size_critical": 40,
                "error_rate_warning": 5.0,
                "error_rate_critical": 10.0
            }
        
        return capacity_planning


# Test execution function
async def test_ai_enhancement_load():
    """Main AI enhancement load testing function."""
    tester = AIEnhancementLoadTester()
    results = await tester.run_comprehensive_ai_load_tests()
    
    # Basic assertions
    assert "ai_load_analysis" in results
    assert "production_readiness" in results
    
    readiness = results["production_readiness"]
    assert readiness["overall_score"] >= 50, f"AI load test score too low: {readiness['overall_score']}"
    
    # Save results
    results_file = Path("ai_enhancement_load_test_results.json")
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n[AI LOAD] Results saved to: {results_file}")
    return results


if __name__ == "__main__":
    async def main():
        print("VoiceFlow AI Enhancement Load Testing Suite")
        print("=" * 55)
        
        results = await test_ai_enhancement_load()
        
        # Print summary
        readiness = results.get("production_readiness", {})
        print(f"\nAI Enhancement Load Testing Summary:")
        print(f"Overall Score: {readiness.get('overall_score', 0)}/100")
        print(f"Grade: {readiness.get('grade', 'Unknown')}")
        print(f"Production Ready: {'✅' if readiness.get('production_ready', False) else '❌'}")
        
        if readiness.get("recommendations"):
            print("\nRecommendations:")
            for rec in readiness["recommendations"]:
                print(f"  • {rec}")
        
        capacity = readiness.get("capacity_planning", {})
        if capacity:
            print(f"\nCapacity Planning:")
            print(f"  Max Concurrent Requests: {capacity.get('recommended_max_concurrent', 'Unknown')}")
            print(f"  Optimal Processing Rate: {capacity.get('optimal_processing_rate', 'Unknown')} req/sec")
        
        print("\nAI enhancement load testing complete!")
    
    asyncio.run(main())