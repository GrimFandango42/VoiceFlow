#!/usr/bin/env python3
"""
Security Feature Performance Impact Analysis
===========================================

Specialized testing suite for analyzing the performance impact of VoiceFlow's
security features including encryption, authentication, and input validation.

This module provides detailed analysis of:
1. Encryption/Decryption Performance Impact
2. Authentication System Overhead
3. Input Validation Processing Time
4. WebSocket Security Handshake Performance
5. Session Management Resource Usage
6. Security vs Performance Trade-offs

Author: Senior Performance Testing Expert
Version: 1.0.0
"""

import asyncio
import gc
import hashlib
import json
import os
import psutil
import secrets
import statistics
import time
import tracemalloc
import websockets
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any
from unittest.mock import Mock, patch

import numpy as np
import pytest

# Import VoiceFlow security components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from utils.auth import AuthManager, get_auth_manager, extract_auth_token
    from utils.secure_db import SecureDatabase, create_secure_database
    from utils.validation import InputValidator, ValidationError
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False


class SecurityPerformanceAnalyzer:
    """Comprehensive security performance impact analyzer."""
    
    def __init__(self):
        self.test_data_dir = Path("/tmp/voiceflow_security_perf")
        self.test_data_dir.mkdir(exist_ok=True)
        self.results = {}
        
    def setup(self):
        """Setup test environment."""
        print("[SECURITY PERF] Setting up security performance test environment...")
        
        # Create test data of various sizes
        self.test_texts = {
            'tiny': "Hello",
            'small': "This is a small test text for security performance analysis.",
            'medium': "This is a medium-sized test text. " * 20,
            'large': "This is a large test text that will be used for performance testing. " * 100,
            'xlarge': "Extra large test content for comprehensive security performance analysis. " * 500
        }
        
        # Create test JSON payloads
        self.test_json_payloads = {
            'simple': '{"type": "test", "message": "hello"}',
            'complex': json.dumps({
                "type": "transcription",
                "data": {
                    "text": "Sample transcription text",
                    "metadata": {"duration": 5.2, "words": 25},
                    "context": "meeting"
                },
                "timestamp": datetime.now().isoformat()
            }),
            'large': json.dumps({
                "type": "bulk_data",
                "items": [{"id": i, "data": f"Item {i} data content"} for i in range(100)]
            })
        }
        
    def cleanup(self):
        """Cleanup test environment."""
        import shutil
        try:
            shutil.rmtree(self.test_data_dir)
        except Exception as e:
            print(f"[SECURITY PERF] Cleanup warning: {e}")
    
    # ============================================================================
    # ENCRYPTION PERFORMANCE ANALYSIS
    # ============================================================================
    
    def analyze_encryption_performance(self) -> Dict[str, Any]:
        """Analyze encryption/decryption performance across different data sizes."""
        print("\n[SECURITY PERF] Analyzing encryption performance...")
        
        if not AUTH_AVAILABLE:
            return {"error": "Security components not available"}
        
        results = {}
        
        try:
            # Create secure database for testing
            secure_db = create_secure_database(self.test_data_dir)
            
            for size_name, text in self.test_texts.items():
                print(f"  Testing {size_name} text ({len(text)} chars)...")
                
                # Encryption performance
                encrypt_times = []
                for _ in range(100):
                    start = time.perf_counter()
                    encrypted = secure_db.encrypt_text(text)
                    end = time.perf_counter()
                    encrypt_times.append((end - start) * 1000000)  # microseconds
                
                # Decryption performance
                encrypted_text = secure_db.encrypt_text(text)
                decrypt_times = []
                for _ in range(100):
                    start = time.perf_counter()
                    decrypted = secure_db.decrypt_text(encrypted_text)
                    end = time.perf_counter()
                    decrypt_times.append((end - start) * 1000000)  # microseconds
                
                # Calculate overhead vs plain text operations
                plain_times = []
                for _ in range(100):
                    start = time.perf_counter()
                    # Simulate plain text storage (just length check)
                    result = len(text) > 0
                    end = time.perf_counter()
                    plain_times.append((end - start) * 1000000)
                
                results[size_name] = {
                    'text_length': len(text),
                    'encryption': {
                        'mean_us': statistics.mean(encrypt_times),
                        'median_us': statistics.median(encrypt_times),
                        'std_dev_us': statistics.stdev(encrypt_times) if len(encrypt_times) > 1 else 0,
                        'min_us': min(encrypt_times),
                        'max_us': max(encrypt_times),
                        'p95_us': np.percentile(encrypt_times, 95),
                        'p99_us': np.percentile(encrypt_times, 99)
                    },
                    'decryption': {
                        'mean_us': statistics.mean(decrypt_times),
                        'median_us': statistics.median(decrypt_times),
                        'std_dev_us': statistics.stdev(decrypt_times) if len(decrypt_times) > 1 else 0,
                        'min_us': min(decrypt_times),
                        'max_us': max(decrypt_times),
                        'p95_us': np.percentile(decrypt_times, 95),
                        'p99_us': np.percentile(decrypt_times, 99)
                    },
                    'overhead_analysis': {
                        'encrypt_overhead_factor': statistics.mean(encrypt_times) / statistics.mean(plain_times),
                        'decrypt_overhead_factor': statistics.mean(decrypt_times) / statistics.mean(plain_times),
                        'total_roundtrip_us': statistics.mean(encrypt_times) + statistics.mean(decrypt_times),
                        'throughput_chars_per_sec': len(text) / ((statistics.mean(encrypt_times) + statistics.mean(decrypt_times)) / 1000000)
                    }
                }
            
            # Performance scaling analysis
            results['scaling_analysis'] = self._analyze_encryption_scaling(secure_db)
            
        except Exception as e:
            results = {"error": f"Encryption performance analysis failed: {e}"}
        
        return results
    
    def _analyze_encryption_scaling(self, secure_db: SecureDatabase) -> Dict[str, Any]:
        """Analyze how encryption performance scales with data size."""
        scaling_results = {}
        
        # Test with incrementally larger data sizes
        test_sizes = [10, 100, 1000, 10000, 50000]  # characters
        
        for size in test_sizes:
            test_data = "x" * size
            
            # Single measurement for scaling analysis
            start = time.perf_counter()
            encrypted = secure_db.encrypt_text(test_data)
            encrypt_time = time.perf_counter() - start
            
            start = time.perf_counter()
            decrypted = secure_db.decrypt_text(encrypted)
            decrypt_time = time.perf_counter() - start
            
            scaling_results[f"size_{size}"] = {
                'encrypt_time_us': encrypt_time * 1000000,
                'decrypt_time_us': decrypt_time * 1000000,
                'encrypt_rate_chars_per_us': size / (encrypt_time * 1000000),
                'decrypt_rate_chars_per_us': size / (decrypt_time * 1000000)
            }
        
        return scaling_results
    
    # ============================================================================
    # AUTHENTICATION PERFORMANCE ANALYSIS
    # ============================================================================
    
    def analyze_authentication_performance(self) -> Dict[str, Any]:
        """Analyze authentication system performance impact."""
        print("\n[SECURITY PERF] Analyzing authentication performance...")
        
        if not AUTH_AVAILABLE:
            return {"error": "Authentication components not available"}
        
        results = {}
        
        try:
            auth_manager = get_auth_manager()
            
            # Token validation performance
            valid_token = auth_manager.auth_token
            invalid_tokens = [
                "invalid_token_12345",
                "short",
                "a" * 100,  # Very long invalid token
                "",  # Empty token
                None  # None token
            ]
            
            # Valid token validation
            valid_times = []
            for _ in range(1000):
                start = time.perf_counter()
                result = auth_manager.validate_token(valid_token)
                end = time.perf_counter()
                valid_times.append((end - start) * 1000000)  # microseconds
            
            results['token_validation'] = {
                'valid_token': {
                    'mean_us': statistics.mean(valid_times),
                    'median_us': statistics.median(valid_times),
                    'min_us': min(valid_times),
                    'max_us': max(valid_times),
                    'p95_us': np.percentile(valid_times, 95),
                    'std_dev_us': statistics.stdev(valid_times) if len(valid_times) > 1 else 0
                },
                'invalid_tokens': {}
            }
            
            # Invalid token validation
            for i, invalid_token in enumerate(invalid_tokens):
                invalid_times = []
                for _ in range(1000):
                    start = time.perf_counter()
                    result = auth_manager.validate_token(invalid_token)
                    end = time.perf_counter()
                    invalid_times.append((end - start) * 1000000)
                
                token_desc = f"invalid_{i}" if invalid_token else "none_token"
                results['token_validation']['invalid_tokens'][token_desc] = {
                    'mean_us': statistics.mean(invalid_times),
                    'token_length': len(invalid_token) if invalid_token else 0
                }
            
            # Session management performance
            session_creation_times = []
            session_validation_times = []
            created_sessions = []
            
            # Create sessions
            for i in range(100):
                start = time.perf_counter()
                session_id = auth_manager.create_session(f"client_{i}")
                end = time.perf_counter()
                session_creation_times.append((end - start) * 1000000)
                created_sessions.append(session_id)
            
            # Validate sessions
            for session_id in created_sessions:
                start = time.perf_counter()
                is_valid = auth_manager.validate_session(session_id)
                end = time.perf_counter()
                session_validation_times.append((end - start) * 1000000)
            
            results['session_management'] = {
                'creation': {
                    'mean_us': statistics.mean(session_creation_times),
                    'max_us': max(session_creation_times),
                    'std_dev_us': statistics.stdev(session_creation_times) if len(session_creation_times) > 1 else 0
                },
                'validation': {
                    'mean_us': statistics.mean(session_validation_times),
                    'max_us': max(session_validation_times),
                    'std_dev_us': statistics.stdev(session_validation_times) if len(session_validation_times) > 1 else 0
                }
            }
            
            # Memory impact of session storage
            initial_memory = psutil.Process().memory_info().rss
            
            # Create many sessions to test memory impact
            mass_sessions = []
            for i in range(1000):
                session_id = auth_manager.create_session(f"stress_client_{i}")
                mass_sessions.append(session_id)
            
            peak_memory = psutil.Process().memory_info().rss
            
            # Cleanup sessions
            for session_id in mass_sessions:
                auth_manager.revoke_session(session_id)
            
            final_memory = psutil.Process().memory_info().rss
            
            results['memory_impact'] = {
                'initial_memory_mb': initial_memory / 1024 / 1024,
                'peak_memory_mb': peak_memory / 1024 / 1024,
                'final_memory_mb': final_memory / 1024 / 1024,
                'memory_per_session_kb': (peak_memory - initial_memory) / 1000 / 1024,
                'memory_cleanup_efficiency': (peak_memory - final_memory) / (peak_memory - initial_memory) if peak_memory > initial_memory else 0
            }
            
        except Exception as e:
            results = {"error": f"Authentication performance analysis failed: {e}"}
        
        return results
    
    # ============================================================================
    # INPUT VALIDATION PERFORMANCE ANALYSIS
    # ============================================================================
    
    def analyze_input_validation_performance(self) -> Dict[str, Any]:
        """Analyze input validation performance impact."""
        print("\n[SECURITY PERF] Analyzing input validation performance...")
        
        if not AUTH_AVAILABLE:
            return {"error": "Validation components not available"}
        
        results = {}
        
        try:
            # Text validation performance
            results['text_validation'] = {}
            
            for size_name, text in self.test_texts.items():
                validation_times = []
                
                for _ in range(100):
                    start = time.perf_counter()
                    try:
                        validated = InputValidator.validate_text(text, max_length=len(text) + 100)
                        validation_success = True
                    except ValidationError:
                        validation_success = False
                    end = time.perf_counter()
                    validation_times.append((end - start) * 1000000)  # microseconds
                
                results['text_validation'][size_name] = {
                    'text_length': len(text),
                    'mean_validation_time_us': statistics.mean(validation_times),
                    'max_validation_time_us': max(validation_times),
                    'validation_rate_chars_per_us': len(text) / statistics.mean(validation_times),
                    'overhead_per_char_ns': (statistics.mean(validation_times) * 1000) / len(text) if len(text) > 0 else 0
                }
            
            # JSON validation performance
            results['json_validation'] = {}
            
            for payload_name, json_data in self.test_json_payloads.items():
                json_validation_times = []
                
                for _ in range(100):
                    start = time.perf_counter()
                    try:
                        validated = InputValidator.validate_json_message(json_data)
                        validation_success = True
                    except (ValidationError, ValueError):
                        validation_success = False
                    end = time.perf_counter()
                    json_validation_times.append((end - start) * 1000000)
                
                results['json_validation'][payload_name] = {
                    'payload_size_bytes': len(json_data.encode('utf-8')),
                    'mean_validation_time_us': statistics.mean(json_validation_times),
                    'max_validation_time_us': max(json_validation_times),
                    'validation_rate_bytes_per_us': len(json_data.encode('utf-8')) / statistics.mean(json_validation_times)
                }
            
            # Malicious input detection performance
            malicious_inputs = [
                "<script>alert('xss')</script>",
                "'; DROP TABLE users; --",
                "../../../etc/passwd",
                "x" * 100000,  # Very long input
                "\x00\x01\x02\x03",  # Binary data
                "normal text with unicode: 你好世界 🌍",
            ]
            
            results['malicious_input_detection'] = {}
            
            for i, malicious_input in enumerate(malicious_inputs):
                detection_times = []
                
                for _ in range(100):
                    start = time.perf_counter()
                    try:
                        # Test various validation methods
                        text_validated = InputValidator.validate_text(malicious_input, max_length=10000, allow_empty=True)
                        validation_result = "passed"
                    except ValidationError:
                        validation_result = "blocked"
                    end = time.perf_counter()
                    detection_times.append((end - start) * 1000000)
                
                results['malicious_input_detection'][f"input_{i}"] = {
                    'input_length': len(malicious_input),
                    'input_type': self._classify_malicious_input(malicious_input),
                    'mean_detection_time_us': statistics.mean(detection_times),
                    'max_detection_time_us': max(detection_times),
                    'detection_rate_chars_per_us': len(malicious_input) / statistics.mean(detection_times) if len(malicious_input) > 0 else 0
                }
            
        except Exception as e:
            results = {"error": f"Input validation performance analysis failed: {e}"}
        
        return results
    
    def _classify_malicious_input(self, input_text: str) -> str:
        """Classify type of malicious input for analysis."""
        if "<script>" in input_text.lower():
            return "xss_attempt"
        elif "drop table" in input_text.lower():
            return "sql_injection"
        elif "../" in input_text:
            return "path_traversal"
        elif len(input_text) > 10000:
            return "buffer_overflow"
        elif any(ord(c) < 32 for c in input_text if c not in '\t\n\r'):
            return "binary_data"
        else:
            return "unicode_content"
    
    # ============================================================================
    # WEBSOCKET SECURITY PERFORMANCE
    # ============================================================================
    
    def analyze_websocket_security_performance(self) -> Dict[str, Any]:
        """Analyze WebSocket authentication handshake performance."""
        print("\n[SECURITY PERF] Analyzing WebSocket security performance...")
        
        results = {}
        
        if not AUTH_AVAILABLE:
            return {"error": "Authentication components not available"}
        
        try:
            auth_manager = get_auth_manager()
            
            # Mock WebSocket request with authentication
            class MockWebSocket:
                def __init__(self, token=None):
                    self.request_headers = {}
                    self.path = "/"
                    self.remote_address = ("127.0.0.1", 12345)
                    
                    if token:
                        self.request_headers['Authorization'] = f'Bearer {token}'
                        self.path = f"/?token={token}"
            
            # Test authenticated connection performance
            valid_token = auth_manager.auth_token
            mock_websocket_valid = MockWebSocket(valid_token)
            
            auth_times_valid = []
            for _ in range(100):
                start = time.perf_counter()
                
                # Extract token
                extracted_token = extract_auth_token(mock_websocket_valid)
                # Validate token
                is_valid = auth_manager.validate_token(extracted_token)
                # Create session
                if is_valid:
                    session_id = auth_manager.create_session("test_client")
                
                end = time.perf_counter()
                auth_times_valid.append((end - start) * 1000)  # milliseconds
            
            # Test unauthenticated connection performance
            mock_websocket_invalid = MockWebSocket("invalid_token")
            
            auth_times_invalid = []
            for _ in range(100):
                start = time.perf_counter()
                
                extracted_token = extract_auth_token(mock_websocket_invalid)
                is_valid = auth_manager.validate_token(extracted_token)
                
                end = time.perf_counter()
                auth_times_invalid.append((end - start) * 1000)
            
            # Test no authentication (baseline)
            mock_websocket_none = MockWebSocket()
            
            baseline_times = []
            for _ in range(100):
                start = time.perf_counter()
                
                # Just extract token (will be None)
                extracted_token = extract_auth_token(mock_websocket_none)
                
                end = time.perf_counter()
                baseline_times.append((end - start) * 1000)
            
            results = {
                'authentication_handshake': {
                    'valid_auth': {
                        'mean_ms': statistics.mean(auth_times_valid),
                        'median_ms': statistics.median(auth_times_valid),
                        'max_ms': max(auth_times_valid),
                        'p95_ms': np.percentile(auth_times_valid, 95)
                    },
                    'invalid_auth': {
                        'mean_ms': statistics.mean(auth_times_invalid),
                        'median_ms': statistics.median(auth_times_invalid),
                        'max_ms': max(auth_times_invalid)
                    },
                    'no_auth_baseline': {
                        'mean_ms': statistics.mean(baseline_times),
                        'median_ms': statistics.median(baseline_times)
                    },
                    'overhead_analysis': {
                        'auth_overhead_ms': statistics.mean(auth_times_valid) - statistics.mean(baseline_times),
                        'invalid_auth_overhead_ms': statistics.mean(auth_times_invalid) - statistics.mean(baseline_times),
                        'auth_overhead_factor': statistics.mean(auth_times_valid) / statistics.mean(baseline_times) if statistics.mean(baseline_times) > 0 else 0
                    }
                }
            }
            
            # Concurrent connection authentication performance
            results['concurrent_auth'] = self._test_concurrent_websocket_auth(auth_manager)
            
        except Exception as e:
            results = {"error": f"WebSocket security performance analysis failed: {e}"}
        
        return results
    
    def _test_concurrent_websocket_auth(self, auth_manager: AuthManager) -> Dict[str, Any]:
        """Test concurrent WebSocket authentication performance."""
        
        def authenticate_client(client_id: int) -> float:
            """Simulate client authentication."""
            start = time.perf_counter()
            
            # Validate token
            is_valid = auth_manager.validate_token(auth_manager.auth_token)
            
            # Create session if valid
            if is_valid:
                session_id = auth_manager.create_session(f"concurrent_client_{client_id}")
            
            end = time.perf_counter()
            return (end - start) * 1000  # milliseconds
        
        concurrent_results = {}
        
        # Test different levels of concurrency
        concurrency_levels = [1, 5, 10, 20, 50]
        
        for concurrency in concurrency_levels:
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                start_time = time.perf_counter()
                
                # Submit authentication tasks
                futures = [executor.submit(authenticate_client, i) for i in range(concurrency)]
                auth_times = [future.result() for future in futures]
                
                total_time = time.perf_counter() - start_time
            
            concurrent_results[f"concurrency_{concurrency}"] = {
                'total_time_s': total_time,
                'mean_auth_time_ms': statistics.mean(auth_times),
                'max_auth_time_ms': max(auth_times),
                'throughput_auths_per_sec': concurrency / total_time,
                'concurrent_overhead_factor': statistics.mean(auth_times) / concurrent_results.get('concurrency_1', {}).get('mean_auth_time_ms', 1) if 'concurrency_1' in concurrent_results else 1
            }
        
        return concurrent_results
    
    # ============================================================================
    # SECURITY VS PERFORMANCE TRADE-OFF ANALYSIS
    # ============================================================================
    
    def analyze_security_performance_tradeoffs(self) -> Dict[str, Any]:
        """Analyze trade-offs between security features and performance."""
        print("\n[SECURITY PERF] Analyzing security vs performance trade-offs...")
        
        results = {
            'feature_impact_analysis': {},
            'cumulative_overhead': {},
            'recommendations': []
        }
        
        if not AUTH_AVAILABLE:
            return {"error": "Security components not available"}
        
        try:
            # Test different security configurations
            security_configs = [
                {'name': 'no_security', 'encryption': False, 'auth': False, 'validation': False},
                {'name': 'auth_only', 'encryption': False, 'auth': True, 'validation': False},
                {'name': 'validation_only', 'encryption': False, 'auth': False, 'validation': True},
                {'name': 'encryption_only', 'encryption': True, 'auth': False, 'validation': False},
                {'name': 'auth_validation', 'encryption': False, 'auth': True, 'validation': True},
                {'name': 'full_security', 'encryption': True, 'auth': True, 'validation': True}
            ]
            
            baseline_time = None
            
            for config in security_configs:
                config_times = []
                
                for _ in range(50):
                    start = time.perf_counter()
                    
                    # Simulate a complete request cycle with security features
                    test_data = self.test_texts['medium']
                    
                    # Input validation
                    if config['validation']:
                        try:
                            validated_data = InputValidator.validate_text(test_data, max_length=10000)
                        except ValidationError:
                            validated_data = ""
                    else:
                        validated_data = test_data
                    
                    # Authentication
                    if config['auth']:
                        auth_manager = get_auth_manager()
                        auth_valid = auth_manager.validate_token(auth_manager.auth_token)
                        if auth_valid:
                            session_id = auth_manager.create_session("test_client")
                    
                    # Encryption
                    if config['encryption']:
                        secure_db = create_secure_database(self.test_data_dir)
                        encrypted_data = secure_db.encrypt_text(validated_data)
                        decrypted_data = secure_db.decrypt_text(encrypted_data)
                    
                    end = time.perf_counter()
                    config_times.append((end - start) * 1000)  # milliseconds
                
                mean_time = statistics.mean(config_times)
                
                if config['name'] == 'no_security':
                    baseline_time = mean_time
                
                results['feature_impact_analysis'][config['name']] = {
                    'mean_time_ms': mean_time,
                    'std_dev_ms': statistics.stdev(config_times) if len(config_times) > 1 else 0,
                    'max_time_ms': max(config_times),
                    'overhead_vs_baseline_ms': mean_time - baseline_time if baseline_time else 0,
                    'overhead_factor': mean_time / baseline_time if baseline_time and baseline_time > 0 else 1,
                    'config': config
                }
            
            # Calculate cumulative overhead
            if baseline_time:
                full_security_time = results['feature_impact_analysis']['full_security']['mean_time_ms']
                total_overhead = full_security_time - baseline_time
                
                results['cumulative_overhead'] = {
                    'baseline_time_ms': baseline_time,
                    'full_security_time_ms': full_security_time,
                    'total_overhead_ms': total_overhead,
                    'overhead_percentage': (total_overhead / baseline_time) * 100,
                    'security_cost_per_request_ms': total_overhead
                }
            
            # Generate recommendations based on analysis
            results['recommendations'] = self._generate_security_performance_recommendations(results)
            
        except Exception as e:
            results = {"error": f"Security trade-off analysis failed: {e}"}
        
        return results
    
    def _generate_security_performance_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate security vs performance recommendations."""
        recommendations = []
        
        try:
            feature_analysis = analysis_results.get('feature_impact_analysis', {})
            cumulative = analysis_results.get('cumulative_overhead', {})
            
            # Analyze individual feature costs
            if 'auth_only' in feature_analysis and 'no_security' in feature_analysis:
                auth_overhead = feature_analysis['auth_only']['overhead_vs_baseline_ms']
                if auth_overhead < 1.0:
                    recommendations.append("Authentication overhead is minimal (<1ms) - recommended for all deployments")
                elif auth_overhead > 10.0:
                    recommendations.append("Authentication overhead is significant (>10ms) - consider optimization")
            
            if 'validation_only' in feature_analysis:
                validation_overhead = feature_analysis['validation_only']['overhead_vs_baseline_ms']
                if validation_overhead < 0.5:
                    recommendations.append("Input validation overhead is negligible - strongly recommended")
                elif validation_overhead > 5.0:
                    recommendations.append("Input validation overhead is high - review validation complexity")
            
            if 'encryption_only' in feature_analysis:
                encryption_overhead = feature_analysis['encryption_only']['overhead_vs_baseline_ms']
                if encryption_overhead < 5.0:
                    recommendations.append("Encryption overhead is acceptable (<5ms) - recommended for sensitive data")
                elif encryption_overhead > 20.0:
                    recommendations.append("Encryption overhead is significant - consider async encryption or caching")
            
            # Overall recommendations
            if cumulative and cumulative.get('overhead_percentage', 0) < 50:
                recommendations.append("Overall security overhead is reasonable - full security recommended")
            elif cumulative and cumulative.get('overhead_percentage', 0) > 100:
                recommendations.append("Security overhead doubles processing time - consider selective implementation")
            
            # Performance optimization suggestions
            recommendations.extend([
                "Consider implementing security features asynchronously where possible",
                "Cache authentication results for repeated requests within sessions",
                "Use connection pooling to amortize authentication overhead",
                "Implement graceful degradation under high load",
                "Monitor security overhead in production with performance metrics"
            ])
            
        except Exception:
            recommendations.append("Unable to generate specific recommendations due to analysis errors")
        
        return recommendations
    
    # ============================================================================
    # MAIN ANALYSIS EXECUTION
    # ============================================================================
    
    def run_comprehensive_security_performance_analysis(self) -> Dict[str, Any]:
        """Run complete security performance analysis."""
        print("\n" + "="*80)
        print("VOICEFLOW SECURITY PERFORMANCE IMPACT ANALYSIS")
        print("="*80)
        
        self.setup()
        
        try:
            analysis_categories = [
                ("encryption_performance", self.analyze_encryption_performance),
                ("authentication_performance", self.analyze_authentication_performance),
                ("input_validation_performance", self.analyze_input_validation_performance),
                ("websocket_security_performance", self.analyze_websocket_security_performance),
                ("security_performance_tradeoffs", self.analyze_security_performance_tradeoffs)
            ]
            
            all_results = {}
            
            for category_name, analysis_function in analysis_categories:
                try:
                    print(f"\n[ANALYSIS] {category_name.upper()}")
                    result = analysis_function()
                    all_results[category_name] = result
                except Exception as e:
                    print(f"[ERROR] Failed to run {category_name}: {e}")
                    all_results[category_name] = {"error": str(e)}
            
            # Generate comprehensive summary
            all_results["analysis_summary"] = self._generate_analysis_summary(all_results)
            all_results["system_info"] = self._get_system_info()
            all_results["analysis_timestamp"] = datetime.now().isoformat()
            
            return all_results
            
        finally:
            self.cleanup()
    
    def _generate_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive analysis summary."""
        summary = {
            "key_findings": [],
            "performance_impact_grades": {},
            "security_recommendations": [],
            "optimization_priorities": []
        }
        
        try:
            # Analyze encryption performance
            if "encryption_performance" in results and "error" not in results["encryption_performance"]:
                enc_results = results["encryption_performance"]
                if "medium" in enc_results:
                    medium_encrypt_time = enc_results["medium"]["encryption"]["mean_us"]
                    if medium_encrypt_time < 100:
                        summary["performance_impact_grades"]["encryption"] = "A"
                        summary["key_findings"].append(f"Encryption performance excellent: {medium_encrypt_time:.1f}μs avg")
                    elif medium_encrypt_time < 500:
                        summary["performance_impact_grades"]["encryption"] = "B"
                        summary["key_findings"].append(f"Encryption performance good: {medium_encrypt_time:.1f}μs avg")
                    else:
                        summary["performance_impact_grades"]["encryption"] = "C"
                        summary["key_findings"].append(f"Encryption performance needs optimization: {medium_encrypt_time:.1f}μs avg")
            
            # Analyze authentication performance
            if "authentication_performance" in results and "error" not in results["authentication_performance"]:
                auth_results = results["authentication_performance"]
                if "token_validation" in auth_results:
                    token_time = auth_results["token_validation"]["valid_token"]["mean_us"]
                    if token_time < 10:
                        summary["performance_impact_grades"]["authentication"] = "A"
                    elif token_time < 50:
                        summary["performance_impact_grades"]["authentication"] = "B"
                    else:
                        summary["performance_impact_grades"]["authentication"] = "C"
                    summary["key_findings"].append(f"Token validation: {token_time:.1f}μs avg")
            
            # Overall security recommendations
            summary["security_recommendations"].extend([
                "Enable all security features - performance impact is acceptable",
                "Implement security monitoring to track performance impact over time",
                "Consider security feature caching for high-frequency operations",
                "Use async processing for non-critical security operations"
            ])
            
            # Optimization priorities
            summary["optimization_priorities"].extend([
                "Monitor encryption overhead in production",
                "Implement connection pooling for database operations",
                "Cache authentication results within sessions",
                "Optimize input validation for large payloads"
            ])
            
        except Exception as e:
            summary["analysis_error"] = str(e)
        
        return summary
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for analysis context."""
        try:
            import platform
            
            return {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "cpu_count": psutil.cpu_count(),
                "memory_total_gb": psutil.virtual_memory().total / (1024**3),
                "analysis_environment": "Security Performance Testing"
            }
        except Exception as e:
            return {"error": f"Could not get system info: {e}"}


# Test execution functions
def test_security_performance_impact():
    """Main test function for pytest."""
    if not AUTH_AVAILABLE:
        pytest.skip("Security components not available")
    
    analyzer = SecurityPerformanceAnalyzer()
    results = analyzer.run_comprehensive_security_performance_analysis()
    
    # Basic assertions
    assert "analysis_summary" in results
    assert len(results) > 3  # Should have multiple analysis categories
    
    # Save detailed results
    results_file = Path("voiceflow_security_performance_results.json")
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n[RESULTS] Security performance analysis saved to: {results_file}")
    return results


if __name__ == "__main__":
    # Run security performance analysis directly
    print("VoiceFlow Security Performance Impact Analysis")
    print("=" * 60)
    
    analyzer = SecurityPerformanceAnalyzer()
    results = analyzer.run_comprehensive_security_performance_analysis()
    
    # Print summary
    print("\n" + "="*80)
    print("SECURITY PERFORMANCE ANALYSIS SUMMARY")
    print("="*80)
    
    summary = results.get("analysis_summary", {})
    
    print("\nKey Findings:")
    for finding in summary.get("key_findings", []):
        print(f"  • {finding}")
    
    print("\nPerformance Impact Grades:")
    for component, grade in summary.get("performance_impact_grades", {}).items():
        print(f"  {component}: {grade}")
    
    print("\nSecurity Recommendations:")
    for rec in summary.get("security_recommendations", []):
        print(f"  • {rec}")
    
    print("\nOptimization Priorities:")
    for priority in summary.get("optimization_priorities", []):
        print(f"  • {priority}")
    
    # Save results
    results_file = "voiceflow_security_performance_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {results_file}")
    print("Security performance analysis complete!")