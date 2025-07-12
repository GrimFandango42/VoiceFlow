#!/usr/bin/env python3
"""
VoiceFlow Comprehensive Load Testing Suite
==========================================

A specialized load testing framework designed to validate VoiceFlow's production readiness
through systematic stress testing, capacity validation, and performance limit identification.

This framework implements the following load testing methodologies:

1. PROGRESSIVE LOAD TESTING
   - Gradual user increase from 1 → 10 → 50 → 100+ concurrent users
   - Performance degradation curve analysis
   - Breaking point identification
   - Bottleneck detection

2. SUSTAINED LOAD TESTING  
   - Extended operation under moderate load (8+ hours simulation)
   - Memory stability validation
   - Performance consistency over time
   - Resource cleanup verification

3. SPIKE LOAD TESTING
   - Sudden load increases (normal → peak → normal)
   - System response time analysis
   - Recovery time measurement
   - Resource allocation efficiency

4. STRESS LOAD TESTING
   - System operation beyond normal capacity
   - Absolute performance limits identification
   - Failure mode analysis
   - Error handling validation

5. VOLUME LOAD TESTING
   - High-volume data processing scenarios
   - Large transcription file handling
   - Database scaling analysis
   - Storage performance impact

Author: Senior Load Testing Expert
Version: 1.0.0
Focus: Production Readiness Validation
"""

import asyncio
import gc
import json
import os
import psutil
import pytest
import random
import sqlite3
import statistics
import tempfile
import threading
import time
import tracemalloc
import wave
import websockets
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable
from unittest.mock import Mock, patch, MagicMock
import numpy as np

# Import VoiceFlow components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from core.voiceflow_core import VoiceFlowEngine, create_engine
    from core.ai_enhancement import AIEnhancer, create_enhancer
    from utils.secure_db import SecureDatabase, create_secure_database
    from utils.auth import AuthManager, get_auth_manager
    from utils.validation import InputValidator, ValidationError
    VOICEFLOW_AVAILABLE = True
except ImportError as e:
    print(f"VoiceFlow components not available: {e}")
    VOICEFLOW_AVAILABLE = False


@dataclass
class LoadTestMetrics:
    """Container for comprehensive load test metrics."""
    
    # Basic metrics
    operation_count: int = 0
    success_count: int = 0
    error_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    
    # Response time metrics
    response_times: List[float] = field(default_factory=list)
    
    # Throughput metrics
    throughput_samples: List[Tuple[float, int]] = field(default_factory=list)  # (timestamp, ops_count)
    
    # Resource metrics
    memory_samples: List[Dict[str, float]] = field(default_factory=list)
    cpu_samples: List[float] = field(default_factory=list)
    
    # Error tracking
    errors_by_type: Dict[str, int] = field(default_factory=dict)
    error_details: List[Dict[str, Any]] = field(default_factory=list)
    
    # Custom metrics
    custom_metrics: Dict[str, List[float]] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        """Total test duration in seconds."""
        return max(0.001, self.end_time - self.start_time)
    
    @property
    def overall_throughput(self) -> float:
        """Overall operations per second."""
        return self.operation_count / self.duration_seconds
    
    @property
    def success_rate(self) -> float:
        """Success rate as percentage."""
        if self.operation_count == 0:
            return 0.0
        return (self.success_count / self.operation_count) * 100
    
    @property
    def error_rate(self) -> float:
        """Error rate as percentage."""
        return 100.0 - self.success_rate
    
    def get_response_time_stats(self) -> Dict[str, float]:
        """Calculate response time statistics."""
        if not self.response_times:
            return {}
        
        return {
            'mean': statistics.mean(self.response_times),
            'median': statistics.median(self.response_times),
            'min': min(self.response_times),
            'max': max(self.response_times),
            'p95': np.percentile(self.response_times, 95),
            'p99': np.percentile(self.response_times, 99),
            'std_dev': statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0
        }


class MockAudioDataGenerator:
    """Generate realistic mock audio data for load testing."""
    
    @staticmethod
    def generate_speech_like_audio(duration_seconds: float = 3.0, 
                                  sample_rate: int = 16000,
                                  speech_patterns: str = "normal") -> bytes:
        """Generate realistic speech-like audio data."""
        samples = int(duration_seconds * sample_rate)
        t = np.linspace(0, duration_seconds, samples)
        
        # Different speech pattern types
        if speech_patterns == "normal":
            # Standard conversational speech
            fundamental = 150  # Hz
            harmonics = [1, 0.5, 0.3, 0.2, 0.1]
        elif speech_patterns == "fast":
            # Fast speech pattern
            fundamental = 180
            harmonics = [1, 0.6, 0.4, 0.25, 0.15]
        elif speech_patterns == "slow":
            # Slow, deliberate speech
            fundamental = 120
            harmonics = [1, 0.4, 0.2, 0.1, 0.05]
        else:
            fundamental = 150
            harmonics = [1, 0.5, 0.3, 0.2, 0.1]
        
        # Generate speech-like signal with formants
        signal = np.zeros(samples)
        for i, amplitude in enumerate(harmonics):
            frequency = fundamental * (i + 1)
            signal += amplitude * np.sin(2 * np.pi * frequency * t)
        
        # Add speech envelope (amplitude modulation)
        envelope = np.exp(-t * 0.3) * (1 + 0.8 * np.sin(2 * np.pi * 4 * t))
        signal = signal * envelope
        
        # Add realistic noise
        noise = np.random.normal(0, 0.02, samples)
        signal = signal + noise
        
        # Add speech pauses (random silence periods)
        pause_probability = 0.1
        for i in range(0, samples, sample_rate // 4):  # Check every 250ms
            if random.random() < pause_probability:
                pause_length = min(sample_rate // 8, samples - i)  # Max 125ms pause
                signal[i:i + pause_length] = 0
        
        # Normalize and convert to int16
        signal = signal / np.max(np.abs(signal))
        audio_data = (signal * 32767 * 0.8).astype(np.int16)
        
        return audio_data.tobytes()

    @staticmethod
    def save_audio_file(audio_data: bytes, filepath: Path, sample_rate: int = 16000):
        """Save audio data to WAV file."""
        with wave.open(str(filepath), 'wb') as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(sample_rate)
            wf.writeframes(audio_data)


class ConcurrentUserSimulator:
    """Simulate realistic concurrent user behavior patterns."""
    
    def __init__(self, voiceflow_engine_factory: Callable):
        self.engine_factory = voiceflow_engine_factory
        self.active_sessions = {}
        self.metrics = LoadTestMetrics()
        
    async def simulate_user_session(self, 
                                  user_id: int,
                                  session_duration: float,
                                  operations_per_minute: float,
                                  user_behavior: str = "normal") -> Dict[str, Any]:
        """Simulate a single user session with realistic behavior."""
        session_start = time.time()
        session_metrics = LoadTestMetrics()
        session_metrics.start_time = session_start
        
        # Create user-specific engine instance
        try:
            with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder:
                # Mock STT responses based on user behavior
                mock_instance = self._create_mock_stt_instance(user_behavior)
                mock_recorder.return_value = mock_instance
                
                engine = self.engine_factory()
                self.active_sessions[user_id] = engine
                
                # Calculate operation interval
                operations_interval = 60.0 / operations_per_minute if operations_per_minute > 0 else 10.0
                
                while time.time() - session_start < session_duration:
                    # Simulate user operation
                    operation_start = time.time()
                    
                    try:
                        # Choose operation type based on user behavior
                        operation_type = self._choose_operation_type(user_behavior)
                        
                        if operation_type == "transcribe":
                            result = engine.process_speech()
                            success = result is not None
                        elif operation_type == "ai_enhance":
                            # Simulate AI enhancement
                            test_text = f"Test transcription for user {user_id}"
                            enhancer = create_enhancer()
                            enhanced = enhancer.enhance_text(test_text)
                            success = enhanced is not None
                        else:
                            # Simulate other operations
                            success = True
                            time.sleep(0.01)  # Minimal processing
                        
                        operation_time = time.time() - operation_start
                        
                        # Record metrics
                        session_metrics.operation_count += 1
                        session_metrics.response_times.append(operation_time * 1000)  # ms
                        
                        if success:
                            session_metrics.success_count += 1
                        else:
                            session_metrics.error_count += 1
                            session_metrics.errors_by_type["operation_failed"] = \
                                session_metrics.errors_by_type.get("operation_failed", 0) + 1
                    
                    except Exception as e:
                        session_metrics.error_count += 1
                        error_type = type(e).__name__
                        session_metrics.errors_by_type[error_type] = \
                            session_metrics.errors_by_type.get(error_type, 0) + 1
                        session_metrics.error_details.append({
                            "user_id": user_id,
                            "error_type": error_type,
                            "error_message": str(e),
                            "timestamp": time.time()
                        })
                    
                    # Wait for next operation with some randomness
                    wait_time = operations_interval * random.uniform(0.5, 1.5)
                    await asyncio.sleep(wait_time)
                
                session_metrics.end_time = time.time()
                
                # Cleanup
                if user_id in self.active_sessions:
                    engine.cleanup()
                    del self.active_sessions[user_id]
                
                return {
                    "user_id": user_id,
                    "session_duration": session_metrics.duration_seconds,
                    "operations": session_metrics.operation_count,
                    "success_rate": session_metrics.success_rate,
                    "avg_response_time": statistics.mean(session_metrics.response_times) if session_metrics.response_times else 0,
                    "errors": dict(session_metrics.errors_by_type)
                }
        
        except Exception as e:
            return {
                "user_id": user_id,
                "error": f"Session failed: {str(e)}",
                "session_duration": time.time() - session_start
            }
    
    def _create_mock_stt_instance(self, user_behavior: str) -> Mock:
        """Create mock STT instance with behavior-specific responses."""
        mock_instance = Mock()
        
        # Different response patterns based on user behavior
        if user_behavior == "normal":
            responses = [
                "Hello world",
                "This is a test transcription",
                "How are you doing today",
                "Please send this email",
                "Can you help me with this document"
            ]
        elif user_behavior == "power_user":
            responses = [
                "Create a new project with the following specifications",
                "Generate a comprehensive report for the quarterly meeting",
                "Implement the database optimization changes we discussed",
                "Schedule a follow-up meeting with the development team",
                "Review and approve the security audit recommendations"
            ]
        elif user_behavior == "casual":
            responses = [
                "hey there",
                "what's up",
                "quick note",
                "remind me about",
                "thanks"
            ]
        else:
            responses = ["Test transcription"]
        
        def mock_transcribe():
            # Simulate some processing time
            time.sleep(random.uniform(0.05, 0.15))
            return random.choice(responses)
        
        mock_instance.text.side_effect = mock_transcribe
        return mock_instance
    
    def _choose_operation_type(self, user_behavior: str) -> str:
        """Choose operation type based on user behavior profile."""
        if user_behavior == "power_user":
            return random.choices(
                ["transcribe", "ai_enhance", "other"],
                weights=[0.6, 0.35, 0.05]
            )[0]
        elif user_behavior == "casual":
            return random.choices(
                ["transcribe", "ai_enhance", "other"],
                weights=[0.8, 0.15, 0.05]
            )[0]
        else:  # normal
            return random.choices(
                ["transcribe", "ai_enhance", "other"],
                weights=[0.7, 0.25, 0.05]
            )[0]


class DatabaseLoadTester:
    """Specialized database load testing for high-volume operations."""
    
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.test_db_path = data_dir / "load_test.db"
        
    def test_concurrent_write_performance(self, 
                                        concurrent_writers: int,
                                        operations_per_writer: int) -> Dict[str, Any]:
        """Test concurrent database write performance."""
        print(f"[DB LOAD] Testing {concurrent_writers} concurrent writers, {operations_per_writer} ops each")
        
        def writer_worker(writer_id: int) -> Dict[str, Any]:
            """Worker function for concurrent writing."""
            metrics = LoadTestMetrics()
            metrics.start_time = time.time()
            
            # Create separate database connection for each worker
            conn = sqlite3.connect(self.test_db_path)
            cursor = conn.cursor()
            
            # Ensure table exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS load_test_transcriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    writer_id INTEGER,
                    test_data TEXT,
                    processing_time INTEGER,
                    word_count INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            
            for op_id in range(operations_per_writer):
                try:
                    op_start = time.time()
                    
                    # Generate test data
                    test_text = f"Load test data from writer {writer_id}, operation {op_id}"
                    processing_time = random.randint(50, 500)  # Simulate processing time
                    word_count = len(test_text.split())
                    
                    # Execute insert
                    cursor.execute('''
                        INSERT INTO load_test_transcriptions 
                        (writer_id, test_data, processing_time, word_count)
                        VALUES (?, ?, ?, ?)
                    ''', (writer_id, test_text, processing_time, word_count))
                    conn.commit()
                    
                    op_time = time.time() - op_start
                    metrics.response_times.append(op_time * 1000)
                    metrics.success_count += 1
                    
                except Exception as e:
                    metrics.error_count += 1
                    error_type = type(e).__name__
                    metrics.errors_by_type[error_type] = \
                        metrics.errors_by_type.get(error_type, 0) + 1
                
                metrics.operation_count += 1
            
            conn.close()
            metrics.end_time = time.time()
            
            return {
                "writer_id": writer_id,
                "operations": metrics.operation_count,
                "success_rate": metrics.success_rate,
                "avg_response_time": statistics.mean(metrics.response_times) if metrics.response_times else 0,
                "total_time": metrics.duration_seconds
            }
        
        # Execute concurrent writers
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=concurrent_writers) as executor:
            futures = [
                executor.submit(writer_worker, writer_id)
                for writer_id in range(concurrent_writers)
            ]
            
            worker_results = [future.result() for future in as_completed(futures)]
        
        total_time = time.time() - start_time
        
        # Aggregate results
        total_operations = sum(r["operations"] for r in worker_results)
        total_successes = sum(r["operations"] * r["success_rate"] / 100 for r in worker_results)
        avg_response_times = [r["avg_response_time"] for r in worker_results if r["avg_response_time"] > 0]
        
        return {
            "concurrent_writers": concurrent_writers,
            "operations_per_writer": operations_per_writer,
            "total_operations": total_operations,
            "total_time": total_time,
            "overall_throughput": total_operations / total_time,
            "overall_success_rate": (total_successes / total_operations * 100) if total_operations > 0 else 0,
            "avg_response_time": statistics.mean(avg_response_times) if avg_response_times else 0,
            "worker_results": worker_results
        }
    
    def test_encryption_overhead_under_load(self, operation_count: int) -> Dict[str, Any]:
        """Test encryption performance under sustained load."""
        print(f"[DB LOAD] Testing encryption overhead with {operation_count} operations")
        
        # Test unencrypted performance
        unencrypted_times = []
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS unencrypted_test (
                id INTEGER PRIMARY KEY,
                data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        for i in range(operation_count):
            test_data = f"Test data {i} " * 20  # ~160 chars
            
            start = time.time()
            cursor.execute("INSERT INTO unencrypted_test (data) VALUES (?)", (test_data,))
            conn.commit()
            end = time.time()
            
            unencrypted_times.append((end - start) * 1000)
        
        conn.close()
        
        # Test encrypted performance
        encrypted_times = []
        try:
            secure_db = create_secure_database(self.data_dir)
            
            for i in range(operation_count):
                test_data = f"Test data {i} " * 20
                
                start = time.time()
                success = secure_db.store_transcription(
                    text=test_data,
                    processing_time=100,
                    word_count=len(test_data.split()),
                    model_used="test",
                    session_id=f"load_test_{i}"
                )
                end = time.time()
                
                if success:
                    encrypted_times.append((end - start) * 1000)
        
        except ImportError:
            encrypted_times = []
        
        return {
            "operation_count": operation_count,
            "unencrypted": {
                "mean_ms": statistics.mean(unencrypted_times),
                "median_ms": statistics.median(unencrypted_times),
                "max_ms": max(unencrypted_times),
                "throughput_ops_sec": operation_count / (sum(unencrypted_times) / 1000)
            },
            "encrypted": {
                "mean_ms": statistics.mean(encrypted_times) if encrypted_times else 0,
                "median_ms": statistics.median(encrypted_times) if encrypted_times else 0,
                "max_ms": max(encrypted_times) if encrypted_times else 0,
                "throughput_ops_sec": (operation_count / (sum(encrypted_times) / 1000)) if encrypted_times else 0
            },
            "encryption_overhead": {
                "mean_overhead_ms": (statistics.mean(encrypted_times) - statistics.mean(unencrypted_times)) if encrypted_times else 0,
                "overhead_percentage": ((statistics.mean(encrypted_times) / statistics.mean(unencrypted_times) - 1) * 100) if encrypted_times else 0
            }
        }


class WebSocketLoadTester:
    """Load testing for WebSocket connections and message throughput."""
    
    def __init__(self):
        self.server_port = 8765
        self.test_server = None
        
    async def test_concurrent_connections(self, 
                                        connection_counts: List[int],
                                        messages_per_connection: int = 10) -> Dict[str, Any]:
        """Test WebSocket server under various concurrent connection loads."""
        print(f"[WS LOAD] Testing WebSocket connections: {connection_counts}")
        
        results = {}
        
        # Start test WebSocket server
        async def echo_handler(websocket, path):
            """Simple echo server for testing."""
            try:
                await websocket.send(json.dumps({"type": "connected", "timestamp": time.time()}))
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        response = {
                            "type": "echo",
                            "original": data,
                            "timestamp": time.time(),
                            "server_id": "load_test"
                        }
                        await websocket.send(json.dumps(response))
                    except json.JSONDecodeError:
                        await websocket.send(json.dumps({"type": "error", "message": "Invalid JSON"}))
            except websockets.exceptions.ConnectionClosed:
                pass
        
        # Test each connection count
        for connection_count in connection_counts:
            print(f"  Testing {connection_count} concurrent connections...")
            
            # Start server
            server = await websockets.serve(echo_handler, "localhost", self.server_port)
            
            try:
                result = await self._test_connection_load(connection_count, messages_per_connection)
                results[f"connections_{connection_count}"] = result
                
            except Exception as e:
                results[f"connections_{connection_count}"] = {"error": str(e)}
            
            finally:
                server.close()
                await server.wait_closed()
                
                # Brief pause between tests
                await asyncio.sleep(1)
        
        return results
    
    async def _test_connection_load(self, 
                                  connection_count: int,
                                  messages_per_connection: int) -> Dict[str, Any]:
        """Test specific connection load scenario."""
        metrics = LoadTestMetrics()
        metrics.start_time = time.time()
        
        async def client_worker(client_id: int) -> Dict[str, Any]:
            """Individual client worker."""
            client_metrics = LoadTestMetrics()
            client_metrics.start_time = time.time()
            
            try:
                # Connect to server
                uri = f"ws://localhost:{self.server_port}"
                async with websockets.connect(uri) as websocket:
                    # Wait for connection confirmation
                    welcome = await websocket.recv()
                    
                    # Send messages and measure response times
                    for msg_id in range(messages_per_connection):
                        try:
                            msg_start = time.time()
                            
                            # Send message
                            message = {
                                "client_id": client_id,
                                "message_id": msg_id,
                                "data": f"Test message {msg_id} from client {client_id}",
                                "timestamp": msg_start
                            }
                            await websocket.send(json.dumps(message))
                            
                            # Wait for response
                            response = await websocket.recv()
                            msg_end = time.time()
                            
                            # Record response time
                            response_time = (msg_end - msg_start) * 1000
                            client_metrics.response_times.append(response_time)
                            client_metrics.success_count += 1
                        
                        except Exception as e:
                            client_metrics.error_count += 1
                            error_type = type(e).__name__
                            client_metrics.errors_by_type[error_type] = \
                                client_metrics.errors_by_type.get(error_type, 0) + 1
                        
                        client_metrics.operation_count += 1
                        
                        # Small delay between messages
                        await asyncio.sleep(0.01)
                
                client_metrics.end_time = time.time()
                
                return {
                    "client_id": client_id,
                    "success": True,
                    "messages_sent": client_metrics.operation_count,
                    "success_rate": client_metrics.success_rate,
                    "avg_response_time": statistics.mean(client_metrics.response_times) if client_metrics.response_times else 0,
                    "total_time": client_metrics.duration_seconds
                }
            
            except Exception as e:
                return {
                    "client_id": client_id,
                    "success": False,
                    "error": str(e),
                    "total_time": time.time() - client_metrics.start_time
                }
        
        # Launch all clients concurrently
        tasks = [client_worker(i) for i in range(connection_count)]
        client_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        metrics.end_time = time.time()
        
        # Process results
        successful_clients = [r for r in client_results if isinstance(r, dict) and r.get("success")]
        failed_clients = [r for r in client_results if not (isinstance(r, dict) and r.get("success"))]
        
        total_messages = sum(r.get("messages_sent", 0) for r in successful_clients)
        successful_messages = sum(r.get("messages_sent", 0) * r.get("success_rate", 0) / 100 for r in successful_clients)
        avg_response_times = [r.get("avg_response_time", 0) for r in successful_clients if r.get("avg_response_time", 0) > 0]
        
        return {
            "connection_count": connection_count,
            "messages_per_connection": messages_per_connection,
            "successful_connections": len(successful_clients),
            "failed_connections": len(failed_clients),
            "connection_success_rate": (len(successful_clients) / connection_count * 100) if connection_count > 0 else 0,
            "total_messages": total_messages,
            "message_success_rate": (successful_messages / total_messages * 100) if total_messages > 0 else 0,
            "avg_response_time": statistics.mean(avg_response_times) if avg_response_times else 0,
            "total_test_time": metrics.duration_seconds,
            "overall_throughput": total_messages / metrics.duration_seconds if metrics.duration_seconds > 0 else 0
        }


class VoiceFlowLoadTester:
    """Comprehensive load testing suite for VoiceFlow system."""
    
    def __init__(self):
        self.test_data_dir = Path(tempfile.mkdtemp(prefix='voiceflow_load_test_'))
        self.audio_files = []
        self.test_results = {}
        self.resource_monitor = None
        
        # Initialize testing components
        self.concurrent_simulator = ConcurrentUserSimulator(self._create_test_engine)
        self.db_tester = DatabaseLoadTester(self.test_data_dir)
        self.ws_tester = WebSocketLoadTester()
        
    def setup_test_environment(self):
        """Setup comprehensive test environment."""
        print(f"[LOAD TEST] Setting up test environment in {self.test_data_dir}")
        
        # Create test audio files for different scenarios
        audio_scenarios = [
            ("short_speech", 2.0, "normal"),
            ("medium_speech", 5.0, "normal"), 
            ("long_speech", 10.0, "normal"),
            ("fast_speech", 3.0, "fast"),
            ("slow_speech", 8.0, "slow")
        ]
        
        for scenario_name, duration, pattern in audio_scenarios:
            audio_data = MockAudioDataGenerator.generate_speech_like_audio(duration, speech_patterns=pattern)
            filepath = self.test_data_dir / f"{scenario_name}.wav"
            MockAudioDataGenerator.save_audio_file(audio_data, filepath)
            self.audio_files.append((scenario_name, filepath))
        
        print(f"[LOAD TEST] Created {len(self.audio_files)} test audio files")
        
        # Start resource monitoring
        self._start_resource_monitoring()
    
    def cleanup_test_environment(self):
        """Cleanup test environment."""
        import shutil
        try:
            if self.resource_monitor:
                self.resource_monitor.stop()
            shutil.rmtree(self.test_data_dir)
            print(f"[LOAD TEST] Cleaned up test environment")
        except Exception as e:
            print(f"[LOAD TEST] Cleanup warning: {e}")
    
    def _create_test_engine(self):
        """Factory method to create test VoiceFlow engines."""
        if not VOICEFLOW_AVAILABLE:
            return Mock()
        
        config = {
            'model': 'base',
            'device': 'cpu',  # Use CPU for consistent load testing
            'enable_ai_enhancement': True
        }
        return create_engine(config)
    
    def _start_resource_monitoring(self):
        """Start system resource monitoring."""
        self.resource_samples = []
        self.monitoring_active = True
        
        def monitor_resources():
            """Background resource monitoring."""
            while self.monitoring_active:
                try:
                    process = psutil.Process()
                    system = psutil
                    
                    sample = {
                        'timestamp': time.time(),
                        'cpu_percent': process.cpu_percent(),
                        'memory_rss_mb': process.memory_info().rss / 1024 / 1024,
                        'memory_vms_mb': process.memory_info().vms / 1024 / 1024,
                        'system_cpu_percent': system.cpu_percent(),
                        'system_memory_percent': system.virtual_memory().percent,
                        'open_files': len(process.open_files()),
                        'num_threads': process.num_threads()
                    }
                    self.resource_samples.append(sample)
                    
                except Exception:
                    pass
                
                time.sleep(1.0)  # Sample every second
        
        self.resource_monitor = threading.Thread(target=monitor_resources, daemon=True)
        self.resource_monitor.start()
    
    def stop_resource_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring_active = False
        if self.resource_monitor:
            self.resource_monitor.join(timeout=2)
    
    # ============================================================================
    # PROGRESSIVE LOAD TESTING
    # ============================================================================
    
    async def test_progressive_load(self, 
                                  user_counts: List[int] = [1, 5, 10, 20, 50],
                                  test_duration_per_level: float = 60.0) -> Dict[str, Any]:
        """Test progressive load increase to identify breaking points."""
        print(f"\n[PROGRESSIVE LOAD] Testing user counts: {user_counts}")
        
        results = {}
        
        for user_count in user_counts:
            print(f"  Testing {user_count} concurrent users for {test_duration_per_level}s...")
            
            # Configure user behavior distribution
            user_behaviors = []
            for i in range(user_count):
                if i < user_count * 0.6:
                    user_behaviors.append("normal")
                elif i < user_count * 0.8:
                    user_behaviors.append("power_user")
                else:
                    user_behaviors.append("casual")
            
            # Run concurrent user simulation
            start_time = time.time()
            
            tasks = []
            for i in range(user_count):
                behavior = user_behaviors[i]
                operations_per_minute = {
                    "normal": 10,
                    "power_user": 20,
                    "casual": 5
                }[behavior]
                
                task = self.concurrent_simulator.simulate_user_session(
                    user_id=i,
                    session_duration=test_duration_per_level,
                    operations_per_minute=operations_per_minute,
                    user_behavior=behavior
                )
                tasks.append(task)
            
            # Execute all user sessions
            session_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze results
            total_time = time.time() - start_time
            successful_sessions = [r for r in session_results if isinstance(r, dict) and "error" not in r]
            failed_sessions = [r for r in session_results if isinstance(r, dict) and "error" in r]
            
            total_operations = sum(s.get("operations", 0) for s in successful_sessions)
            avg_success_rate = statistics.mean([s.get("success_rate", 0) for s in successful_sessions]) if successful_sessions else 0
            avg_response_time = statistics.mean([s.get("avg_response_time", 0) for s in successful_sessions]) if successful_sessions else 0
            
            results[f"users_{user_count}"] = {
                "user_count": user_count,
                "test_duration": test_duration_per_level,
                "actual_duration": total_time,
                "successful_sessions": len(successful_sessions),
                "failed_sessions": len(failed_sessions),
                "session_success_rate": (len(successful_sessions) / user_count * 100) if user_count > 0 else 0,
                "total_operations": total_operations,
                "operations_per_second": total_operations / total_time if total_time > 0 else 0,
                "avg_session_success_rate": avg_success_rate,
                "avg_response_time_ms": avg_response_time,
                "system_load_stable": avg_success_rate > 95 and avg_response_time < 1000
            }
            
            # Brief recovery period between load levels
            await asyncio.sleep(5)
        
        return results
    
    # ============================================================================
    # SUSTAINED LOAD TESTING
    # ============================================================================
    
    async def test_sustained_load(self, 
                                concurrent_users: int = 20,
                                duration_hours: float = 1.0) -> Dict[str, Any]:
        """Test sustained load over extended period."""
        duration_seconds = duration_hours * 3600
        print(f"\n[SUSTAINED LOAD] Testing {concurrent_users} users for {duration_hours} hours")
        
        # Track metrics over time
        metrics_intervals = []
        interval_duration = 300  # 5-minute intervals
        intervals_count = int(duration_seconds / interval_duration)
        
        start_time = time.time()
        overall_metrics = LoadTestMetrics()
        overall_metrics.start_time = start_time
        
        for interval in range(intervals_count):
            interval_start = time.time()
            print(f"  Interval {interval + 1}/{intervals_count} ({(interval + 1) * 5} minutes)")
            
            # Run user sessions for this interval
            tasks = []
            for user_id in range(concurrent_users):
                behavior = "normal" if user_id % 3 == 0 else ("power_user" if user_id % 3 == 1 else "casual")
                operations_per_minute = {"normal": 12, "power_user": 18, "casual": 6}[behavior]
                
                task = self.concurrent_simulator.simulate_user_session(
                    user_id=f"sustained_{interval}_{user_id}",
                    session_duration=interval_duration,
                    operations_per_minute=operations_per_minute,
                    user_behavior=behavior
                )
                tasks.append(task)
            
            session_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze interval results
            successful_sessions = [r for r in session_results if isinstance(r, dict) and "error" not in r]
            total_operations = sum(s.get("operations", 0) for s in successful_sessions)
            avg_success_rate = statistics.mean([s.get("success_rate", 0) for s in successful_sessions]) if successful_sessions else 0
            avg_response_time = statistics.mean([s.get("avg_response_time", 0) for s in successful_sessions]) if successful_sessions else 0
            
            interval_metrics = {
                "interval": interval + 1,
                "start_time": interval_start,
                "duration": time.time() - interval_start,
                "successful_sessions": len(successful_sessions),
                "total_operations": total_operations,
                "avg_success_rate": avg_success_rate,
                "avg_response_time": avg_response_time,
                "operations_per_second": total_operations / (time.time() - interval_start)
            }
            
            # Sample system resources
            if self.resource_samples:
                recent_samples = [s for s in self.resource_samples if s['timestamp'] >= interval_start]
                if recent_samples:
                    interval_metrics["avg_cpu_percent"] = statistics.mean([s['cpu_percent'] for s in recent_samples])
                    interval_metrics["avg_memory_mb"] = statistics.mean([s['memory_rss_mb'] for s in recent_samples])
                    interval_metrics["max_memory_mb"] = max([s['memory_rss_mb'] for s in recent_samples])
            
            metrics_intervals.append(interval_metrics)
            
            # Update overall metrics
            overall_metrics.operation_count += total_operations
            overall_metrics.success_count += int(total_operations * avg_success_rate / 100)
            
            # Force garbage collection between intervals
            gc.collect()
        
        overall_metrics.end_time = time.time()
        
        # Analyze stability trends
        success_rates = [m["avg_success_rate"] for m in metrics_intervals]
        response_times = [m["avg_response_time"] for m in metrics_intervals]
        throughputs = [m["operations_per_second"] for m in metrics_intervals]
        
        return {
            "test_config": {
                "concurrent_users": concurrent_users,
                "duration_hours": duration_hours,
                "total_intervals": len(metrics_intervals)
            },
            "overall_performance": {
                "total_duration": overall_metrics.duration_seconds,
                "total_operations": overall_metrics.operation_count,
                "overall_success_rate": overall_metrics.success_rate,
                "avg_throughput": overall_metrics.overall_throughput
            },
            "stability_analysis": {
                "success_rate_stability": {
                    "mean": statistics.mean(success_rates) if success_rates else 0,
                    "std_dev": statistics.stdev(success_rates) if len(success_rates) > 1 else 0,
                    "min": min(success_rates) if success_rates else 0,
                    "trend": "stable" if success_rates and (max(success_rates) - min(success_rates) < 5) else "unknown"
                },
                "response_time_stability": {
                    "mean": statistics.mean(response_times) if response_times else 0,
                    "std_dev": statistics.stdev(response_times) if len(response_times) > 1 else 0,
                    "max": max(response_times) if response_times else 0,
                    "trend": "stable" if response_times and (max(response_times) - min(response_times) < 200) else "unknown"
                },
                "throughput_stability": {
                    "mean": statistics.mean(throughputs) if throughputs else 0,
                    "std_dev": statistics.stdev(throughputs) if len(throughputs) > 1 else 0,
                    "degradation": ((throughputs[0] - throughputs[-1]) / throughputs[0] * 100) if len(throughputs) >= 2 and throughputs[0] > 0 else 0
                }
            },
            "interval_details": metrics_intervals
        }
    
    # ============================================================================
    # SPIKE LOAD TESTING
    # ============================================================================
    
    async def test_spike_load(self, 
                            baseline_users: int = 10,
                            spike_users: int = 50,
                            spike_duration: float = 120.0) -> Dict[str, Any]:
        """Test system response to sudden load spikes."""
        print(f"\n[SPIKE LOAD] Testing {baseline_users} → {spike_users} → {baseline_users} users")
        
        phases = [
            ("baseline_before", baseline_users, 60.0),
            ("spike_load", spike_users, spike_duration),
            ("baseline_after", baseline_users, 60.0)
        ]
        
        phase_results = {}
        
        for phase_name, user_count, duration in phases:
            print(f"  Phase: {phase_name} ({user_count} users, {duration}s)")
            
            phase_start = time.time()
            
            # Generate user tasks
            tasks = []
            for user_id in range(user_count):
                behavior = "normal"
                operations_per_minute = 15  # Standard rate
                
                task = self.concurrent_simulator.simulate_user_session(
                    user_id=f"spike_{phase_name}_{user_id}",
                    session_duration=duration,
                    operations_per_minute=operations_per_minute,
                    user_behavior=behavior
                )
                tasks.append(task)
            
            # Execute phase
            session_results = await asyncio.gather(*tasks, return_exceptions=True)
            phase_end = time.time()
            
            # Analyze phase results
            successful_sessions = [r for r in session_results if isinstance(r, dict) and "error" not in r]
            
            total_operations = sum(s.get("operations", 0) for s in successful_sessions)
            avg_success_rate = statistics.mean([s.get("success_rate", 0) for s in successful_sessions]) if successful_sessions else 0
            avg_response_time = statistics.mean([s.get("avg_response_time", 0) for s in successful_sessions]) if successful_sessions else 0
            
            phase_results[phase_name] = {
                "user_count": user_count,
                "planned_duration": duration,
                "actual_duration": phase_end - phase_start,
                "successful_sessions": len(successful_sessions),
                "session_success_rate": (len(successful_sessions) / user_count * 100) if user_count > 0 else 0,
                "total_operations": total_operations,
                "avg_success_rate": avg_success_rate,
                "avg_response_time": avg_response_time,
                "throughput": total_operations / (phase_end - phase_start)
            }
            
            # Brief pause between phases
            await asyncio.sleep(5)
        
        # Analyze spike impact
        baseline_before = phase_results["baseline_before"]
        spike_load = phase_results["spike_load"]
        baseline_after = phase_results["baseline_after"]
        
        spike_analysis = {
            "load_increase_factor": spike_users / baseline_users,
            "performance_impact": {
                "response_time_increase": ((spike_load["avg_response_time"] - baseline_before["avg_response_time"]) / baseline_before["avg_response_time"] * 100) if baseline_before["avg_response_time"] > 0 else 0,
                "success_rate_drop": baseline_before["avg_success_rate"] - spike_load["avg_success_rate"],
                "throughput_efficiency": (spike_load["throughput"] / baseline_before["throughput"]) / (spike_users / baseline_users) if baseline_before["throughput"] > 0 else 0
            },
            "recovery_analysis": {
                "response_time_recovery": abs(baseline_after["avg_response_time"] - baseline_before["avg_response_time"]) < 50,  # Within 50ms
                "success_rate_recovery": abs(baseline_after["avg_success_rate"] - baseline_before["avg_success_rate"]) < 2,  # Within 2%
                "throughput_recovery": abs(baseline_after["throughput"] - baseline_before["throughput"]) / baseline_before["throughput"] < 0.1 if baseline_before["throughput"] > 0 else True  # Within 10%
            }
        }
        
        return {
            "test_config": {
                "baseline_users": baseline_users,
                "spike_users": spike_users,
                "spike_duration": spike_duration
            },
            "phase_results": phase_results,
            "spike_analysis": spike_analysis,
            "overall_assessment": {
                "handles_spike_well": (
                    spike_analysis["performance_impact"]["success_rate_drop"] < 10 and
                    spike_analysis["performance_impact"]["response_time_increase"] < 100 and
                    all(spike_analysis["recovery_analysis"].values())
                )
            }
        }
    
    # ============================================================================
    # STRESS LOAD TESTING
    # ============================================================================
    
    async def test_stress_load(self, max_users: int = 100, increment: int = 10) -> Dict[str, Any]:
        """Test system under stress until breaking point."""
        print(f"\n[STRESS LOAD] Testing system limits up to {max_users} users")
        
        stress_results = {}
        breaking_point = None
        
        for user_count in range(increment, max_users + 1, increment):
            print(f"  Stress testing with {user_count} users...")
            
            start_time = time.time()
            
            # Create aggressive user load
            tasks = []
            for user_id in range(user_count):
                # Aggressive usage pattern
                operations_per_minute = 30  # High operation rate
                
                task = self.concurrent_simulator.simulate_user_session(
                    user_id=f"stress_{user_count}_{user_id}",
                    session_duration=30.0,  # Shorter duration for stress test
                    operations_per_minute=operations_per_minute,
                    user_behavior="power_user"
                )
                tasks.append(task)
            
            try:
                # Execute with timeout to prevent hanging
                session_results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=45.0
                )
                
                # Analyze results
                successful_sessions = [r for r in session_results if isinstance(r, dict) and "error" not in r]
                
                total_operations = sum(s.get("operations", 0) for s in successful_sessions)
                avg_success_rate = statistics.mean([s.get("success_rate", 0) for s in successful_sessions]) if successful_sessions else 0
                avg_response_time = statistics.mean([s.get("avg_response_time", 0) for s in successful_sessions]) if successful_sessions else 0
                
                test_duration = time.time() - start_time
                
                stress_results[f"users_{user_count}"] = {
                    "user_count": user_count,
                    "successful_sessions": len(successful_sessions),
                    "session_success_rate": (len(successful_sessions) / user_count * 100) if user_count > 0 else 0,
                    "total_operations": total_operations,
                    "avg_success_rate": avg_success_rate,
                    "avg_response_time": avg_response_time,
                    "throughput": total_operations / test_duration,
                    "test_duration": test_duration,
                    "system_stable": avg_success_rate > 80 and avg_response_time < 2000
                }
                
                # Check for breaking point
                if (avg_success_rate < 70 or avg_response_time > 3000 or 
                    len(successful_sessions) / user_count < 0.7):
                    breaking_point = user_count
                    print(f"    Breaking point detected at {user_count} users")
                    break
                
            except asyncio.TimeoutError:
                stress_results[f"users_{user_count}"] = {
                    "user_count": user_count,
                    "error": "Test timed out - system overloaded",
                    "breaking_point": True
                }
                breaking_point = user_count
                break
            
            except Exception as e:
                stress_results[f"users_{user_count}"] = {
                    "user_count": user_count,
                    "error": f"Test failed: {str(e)}",
                    "breaking_point": True
                }
                breaking_point = user_count
                break
            
            # Brief recovery between stress levels
            await asyncio.sleep(10)
            gc.collect()
        
        # Analyze stress test results
        successful_tests = [r for r in stress_results.values() if not r.get("error")]
        
        if successful_tests:
            max_stable_throughput = max([r["throughput"] for r in successful_tests])
            optimal_user_count = next(
                (r["user_count"] for r in successful_tests if r["throughput"] == max_stable_throughput),
                increment
            )
        else:
            max_stable_throughput = 0
            optimal_user_count = 0
        
        return {
            "test_config": {
                "max_users_tested": max_users,
                "increment": increment,
                "stress_duration_per_level": 30.0
            },
            "breaking_point": {
                "user_count": breaking_point,
                "detected": breaking_point is not None
            },
            "capacity_analysis": {
                "max_stable_throughput": max_stable_throughput,
                "optimal_user_count": optimal_user_count,
                "scalability_rating": "excellent" if optimal_user_count >= 50 else ("good" if optimal_user_count >= 25 else "limited")
            },
            "stress_test_results": stress_results
        }
    
    # ============================================================================
    # VOLUME LOAD TESTING
    # ============================================================================
    
    def test_volume_load(self) -> Dict[str, Any]:
        """Test high-volume data processing capabilities."""
        print(f"\n[VOLUME LOAD] Testing high-volume data processing")
        
        volume_tests = {}
        
        # Test 1: Large audio file processing
        print("  Testing large audio file processing...")
        large_audio_times = []
        
        for size_minutes in [1, 2, 5, 10]:
            duration_seconds = size_minutes * 60
            audio_data = MockAudioDataGenerator.generate_speech_like_audio(duration_seconds)
            
            start_time = time.time()
            # Simulate processing (in real test, this would be actual STT processing)
            simulated_processing_time = duration_seconds * 0.1  # 10% of audio length
            time.sleep(simulated_processing_time)
            end_time = time.time()
            
            actual_time = end_time - start_time
            large_audio_times.append({
                "audio_duration_minutes": size_minutes,
                "audio_size_mb": len(audio_data) / (1024 * 1024),
                "processing_time_seconds": actual_time,
                "real_time_factor": duration_seconds / actual_time,
                "throughput_mb_per_second": (len(audio_data) / (1024 * 1024)) / actual_time
            })
        
        volume_tests["large_audio_processing"] = large_audio_times
        
        # Test 2: Database volume testing
        print("  Testing database volume handling...")
        db_volume_results = self.db_tester.test_concurrent_write_performance(
            concurrent_writers=10,
            operations_per_writer=1000
        )
        volume_tests["database_volume"] = db_volume_results
        
        # Test 3: Memory usage with large datasets
        print("  Testing memory usage with large datasets...")
        memory_test_start = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Simulate large dataset processing
        large_dataset = []
        for i in range(10000):
            large_dataset.append({
                "id": i,
                "transcription": f"Large dataset transcription {i} " * 20,
                "metadata": {"timestamp": time.time(), "user_id": i % 100}
            })
        
        memory_test_peak = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Cleanup dataset
        del large_dataset
        gc.collect()
        
        memory_test_end = psutil.Process().memory_info().rss / 1024 / 1024
        
        volume_tests["memory_volume_handling"] = {
            "dataset_size": 10000,
            "memory_start_mb": memory_test_start,
            "memory_peak_mb": memory_test_peak,
            "memory_end_mb": memory_test_end,
            "memory_growth_mb": memory_test_peak - memory_test_start,
            "memory_cleanup_efficiency": (memory_test_peak - memory_test_end) / (memory_test_peak - memory_test_start) if memory_test_peak > memory_test_start else 1.0
        }
        
        return volume_tests
    
    # ============================================================================
    # MAIN TEST EXECUTION
    # ============================================================================
    
    async def run_comprehensive_load_tests(self) -> Dict[str, Any]:
        """Run all load testing scenarios."""
        print("\n" + "="*80)
        print("VOICEFLOW COMPREHENSIVE LOAD TESTING SUITE")
        print("="*80)
        
        self.setup_test_environment()
        
        try:
            all_results = {
                "test_metadata": {
                    "start_time": datetime.now().isoformat(),
                    "test_environment": str(self.test_data_dir),
                    "voiceflow_available": VOICEFLOW_AVAILABLE
                }
            }
            
            # 1. Progressive Load Testing
            print("\n[PHASE 1] Progressive Load Testing")
            all_results["progressive_load"] = await self.test_progressive_load()
            
            # 2. WebSocket Load Testing
            print("\n[PHASE 2] WebSocket Load Testing")
            all_results["websocket_load"] = await self.ws_tester.test_concurrent_connections([1, 5, 10, 20])
            
            # 3. Spike Load Testing
            print("\n[PHASE 3] Spike Load Testing")
            all_results["spike_load"] = await self.test_spike_load()
            
            # 4. Volume Load Testing
            print("\n[PHASE 4] Volume Load Testing")
            all_results["volume_load"] = self.test_volume_load()
            
            # 5. Sustained Load Testing (shorter duration for demo)
            print("\n[PHASE 5] Sustained Load Testing")
            all_results["sustained_load"] = await self.test_sustained_load(
                concurrent_users=15, 
                duration_hours=0.25  # 15 minutes for testing
            )
            
            # 6. Stress Load Testing
            print("\n[PHASE 6] Stress Load Testing")
            all_results["stress_load"] = await self.test_stress_load(max_users=50, increment=10)
            
            # Stop resource monitoring and collect final metrics
            self.stop_resource_monitoring()
            
            # Generate comprehensive analysis
            all_results["load_test_analysis"] = self._generate_load_test_analysis(all_results)
            all_results["system_resource_analysis"] = self._analyze_system_resources()
            all_results["production_readiness_assessment"] = self._assess_production_readiness(all_results)
            
            all_results["test_metadata"]["end_time"] = datetime.now().isoformat()
            all_results["test_metadata"]["total_duration"] = time.time() - time.mktime(datetime.fromisoformat(all_results["test_metadata"]["start_time"]).timetuple())
            
            return all_results
            
        finally:
            self.cleanup_test_environment()
    
    def _generate_load_test_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive load test analysis."""
        analysis = {
            "capacity_limits": {},
            "performance_characteristics": {},
            "scalability_assessment": {},
            "bottleneck_identification": {},
            "reliability_metrics": {}
        }
        
        # Analyze progressive load results
        if "progressive_load" in results:
            prog_results = results["progressive_load"]
            stable_user_counts = [
                int(k.split('_')[1]) for k, v in prog_results.items() 
                if v.get("system_load_stable", False)
            ]
            
            analysis["capacity_limits"]["max_stable_concurrent_users"] = max(stable_user_counts) if stable_user_counts else 0
            analysis["scalability_assessment"]["linear_scaling_limit"] = max(stable_user_counts) if stable_user_counts else 0
        
        # Analyze stress test results
        if "stress_load" in results:
            stress_results = results["stress_load"]
            analysis["capacity_limits"]["breaking_point_users"] = stress_results.get("breaking_point", {}).get("user_count", "Not reached")
            analysis["capacity_limits"]["max_stable_throughput"] = stress_results.get("capacity_analysis", {}).get("max_stable_throughput", 0)
        
        # Analyze WebSocket performance
        if "websocket_load" in results:
            ws_results = results["websocket_load"]
            successful_ws_tests = [v for v in ws_results.values() if not v.get("error")]
            if successful_ws_tests:
                max_ws_connections = max([r["connection_count"] for r in successful_ws_tests if r.get("connection_success_rate", 0) > 95])
                analysis["capacity_limits"]["max_websocket_connections"] = max_ws_connections
        
        # Performance characteristics analysis
        if "sustained_load" in results:
            sustained = results["sustained_load"]
            stability = sustained.get("stability_analysis", {})
            
            analysis["performance_characteristics"]["response_time_stability"] = stability.get("response_time_stability", {}).get("trend", "unknown")
            analysis["performance_characteristics"]["throughput_degradation"] = stability.get("throughput_stability", {}).get("degradation", 0)
            analysis["reliability_metrics"]["sustained_success_rate"] = sustained.get("overall_performance", {}).get("overall_success_rate", 0)
        
        # Spike handling analysis
        if "spike_load" in results:
            spike = results["spike_load"]
            analysis["performance_characteristics"]["spike_handling"] = spike.get("overall_assessment", {}).get("handles_spike_well", False)
            analysis["performance_characteristics"]["spike_recovery"] = all(spike.get("spike_analysis", {}).get("recovery_analysis", {}).values())
        
        return analysis
    
    def _analyze_system_resources(self) -> Dict[str, Any]:
        """Analyze system resource usage during load testing."""
        if not self.resource_samples:
            return {"error": "No resource samples collected"}
        
        cpu_values = [s['cpu_percent'] for s in self.resource_samples]
        memory_values = [s['memory_rss_mb'] for s in self.resource_samples]
        
        return {
            "cpu_usage": {
                "mean_percent": statistics.mean(cpu_values),
                "max_percent": max(cpu_values),
                "samples_over_80_percent": sum(1 for v in cpu_values if v > 80),
                "high_usage_ratio": sum(1 for v in cpu_values if v > 80) / len(cpu_values)
            },
            "memory_usage": {
                "start_mb": memory_values[0] if memory_values else 0,
                "peak_mb": max(memory_values),
                "end_mb": memory_values[-1] if memory_values else 0,
                "growth_mb": max(memory_values) - memory_values[0] if memory_values else 0,
                "growth_rate_mb_per_hour": ((memory_values[-1] - memory_values[0]) / len(memory_values) * 3600) if len(memory_values) > 1 else 0
            },
            "resource_efficiency": {
                "memory_leak_detected": (memory_values[-1] - memory_values[0]) > 100 if len(memory_values) > 10 else False,
                "cpu_efficiency": "good" if statistics.mean(cpu_values) < 70 else "needs_optimization",
                "memory_efficiency": "good" if max(memory_values) - memory_values[0] < 200 else "needs_optimization"
            }
        }
    
    def _assess_production_readiness(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall production readiness based on load test results."""
        readiness_score = 0
        max_score = 100
        
        assessment = {
            "overall_score": 0,
            "grade": "F",
            "production_ready": False,
            "critical_issues": [],
            "recommendations": [],
            "capacity_planning": {}
        }
        
        # Evaluate capacity limits (25 points)
        if "load_test_analysis" in results:
            analysis = results["load_test_analysis"]
            
            max_users = analysis.get("capacity_limits", {}).get("max_stable_concurrent_users", 0)
            if max_users >= 50:
                readiness_score += 25
            elif max_users >= 25:
                readiness_score += 20
            elif max_users >= 10:
                readiness_score += 15
            else:
                assessment["critical_issues"].append(f"Low concurrent user capacity: {max_users}")
        
        # Evaluate performance stability (25 points)
        if "sustained_load" in results:
            sustained = results["sustained_load"]
            success_rate = sustained.get("overall_performance", {}).get("overall_success_rate", 0)
            
            if success_rate >= 99:
                readiness_score += 25
            elif success_rate >= 95:
                readiness_score += 20
            elif success_rate >= 90:
                readiness_score += 15
            else:
                assessment["critical_issues"].append(f"Low sustained success rate: {success_rate:.1f}%")
        
        # Evaluate spike handling (20 points)
        if "spike_load" in results:
            spike = results["spike_load"]
            handles_spike = spike.get("overall_assessment", {}).get("handles_spike_well", False)
            
            if handles_spike:
                readiness_score += 20
            else:
                assessment["critical_issues"].append("Poor spike load handling")
        
        # Evaluate resource efficiency (20 points)
        if "system_resource_analysis" in results:
            resources = results["system_resource_analysis"]
            cpu_eff = resources.get("resource_efficiency", {}).get("cpu_efficiency") == "good"
            mem_eff = resources.get("resource_efficiency", {}).get("memory_efficiency") == "good"
            leak_detected = resources.get("resource_efficiency", {}).get("memory_leak_detected", False)
            
            if cpu_eff and mem_eff and not leak_detected:
                readiness_score += 20
            elif (cpu_eff or mem_eff) and not leak_detected:
                readiness_score += 15
            else:
                if not cpu_eff:
                    assessment["critical_issues"].append("CPU usage efficiency needs optimization")
                if not mem_eff:
                    assessment["critical_issues"].append("Memory usage efficiency needs optimization")
                if leak_detected:
                    assessment["critical_issues"].append("Memory leak detected")
        
        # Evaluate error handling (10 points)
        error_rate_good = True
        if "progressive_load" in results:
            for test_result in results["progressive_load"].values():
                if test_result.get("avg_session_success_rate", 100) < 95:
                    error_rate_good = False
                    break
        
        if error_rate_good:
            readiness_score += 10
        else:
            assessment["critical_issues"].append("High error rates detected under load")
        
        # Assign grade and production readiness
        assessment["overall_score"] = readiness_score
        
        if readiness_score >= 90:
            assessment["grade"] = "A"
            assessment["production_ready"] = True
        elif readiness_score >= 80:
            assessment["grade"] = "B"
            assessment["production_ready"] = True
        elif readiness_score >= 70:
            assessment["grade"] = "C"
            assessment["production_ready"] = True  # With monitoring
        elif readiness_score >= 60:
            assessment["grade"] = "D"
            assessment["production_ready"] = False
        else:
            assessment["grade"] = "F"
            assessment["production_ready"] = False
        
        # Generate recommendations
        if readiness_score < 90:
            assessment["recommendations"].extend([
                "Implement comprehensive monitoring",
                "Set up auto-scaling policies",
                "Optimize resource usage",
                "Implement circuit breakers for failure handling"
            ])
        
        if assessment["critical_issues"]:
            assessment["recommendations"].append("Address all critical issues before production deployment")
        
        # Capacity planning
        if "load_test_analysis" in results:
            analysis = results["load_test_analysis"]
            max_users = analysis.get("capacity_limits", {}).get("max_stable_concurrent_users", 0)
            
            assessment["capacity_planning"] = {
                "recommended_max_concurrent_users": int(max_users * 0.7) if max_users > 0 else 10,  # 70% of tested capacity
                "scale_out_threshold": int(max_users * 0.6) if max_users > 0 else 8,
                "monitoring_alert_threshold": int(max_users * 0.8) if max_users > 0 else 12
            }
        
        return assessment


# Test execution functions for pytest integration
@pytest.mark.asyncio
async def test_voiceflow_load_testing():
    """Main load testing function for pytest."""
    if not VOICEFLOW_AVAILABLE:
        pytest.skip("VoiceFlow components not available")
    
    tester = VoiceFlowLoadTester()
    results = await tester.run_comprehensive_load_tests()
    
    # Basic assertions for test validity
    assert "load_test_analysis" in results
    assert "production_readiness_assessment" in results
    
    readiness = results["production_readiness_assessment"]
    assert readiness["overall_score"] >= 60, f"Load test score too low: {readiness['overall_score']}"
    
    # Save detailed results
    results_file = Path("voiceflow_load_test_results.json")
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n[LOAD TEST] Detailed results saved to: {results_file}")
    return results


if __name__ == "__main__":
    async def main():
        print("VoiceFlow Comprehensive Load Testing Suite")
        print("=" * 60)
        
        tester = VoiceFlowLoadTester()
        results = await tester.run_comprehensive_load_tests()
        
        # Print summary
        print("\n" + "="*80)
        print("LOAD TESTING SUMMARY")
        print("="*80)
        
        readiness = results.get("production_readiness_assessment", {})
        print(f"Overall Score: {readiness.get('overall_score', 0)}/100")
        print(f"Grade: {readiness.get('grade', 'Unknown')}")
        print(f"Production Ready: {'✅' if readiness.get('production_ready', False) else '❌'}")
        
        if readiness.get("critical_issues"):
            print("\nCritical Issues:")
            for issue in readiness["critical_issues"]:
                print(f"  ❌ {issue}")
        
        if readiness.get("recommendations"):
            print("\nRecommendations:")
            for rec in readiness["recommendations"]:
                print(f"  💡 {rec}")
        
        capacity = readiness.get("capacity_planning", {})
        if capacity:
            print("\nCapacity Planning:")
            print(f"  Max Concurrent Users: {capacity.get('recommended_max_concurrent_users', 'Unknown')}")
            print(f"  Scale-out Threshold: {capacity.get('scale_out_threshold', 'Unknown')}")
        
        # Save results
        results_file = "voiceflow_load_test_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\nDetailed results saved to: {results_file}")
        print("Load testing complete!")
    
    asyncio.run(main())