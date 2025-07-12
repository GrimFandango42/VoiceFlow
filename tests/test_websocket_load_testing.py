#!/usr/bin/env python3
"""
VoiceFlow WebSocket Load Testing Module
======================================

Specialized load testing framework for WebSocket components focusing on:
1. Connection establishment performance under load
2. Concurrent connection limits and stability 
3. Message throughput and latency analysis
4. Connection lifecycle management
5. Resource utilization under WebSocket load
6. Real-time communication performance validation

This module provides comprehensive WebSocket load testing capabilities
to validate production readiness of VoiceFlow's real-time communication features.

Author: Senior Load Testing Expert
Version: 1.0.0
Focus: WebSocket Connection Scalability
"""

import asyncio
import json
import statistics
import time
import websockets
import threading
import psutil
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import numpy as np


@dataclass
class WebSocketMetrics:
    """Comprehensive WebSocket performance metrics."""
    
    # Connection metrics
    connection_attempts: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    connection_times: List[float] = field(default_factory=list)
    
    # Message metrics
    messages_sent: int = 0
    messages_received: int = 0
    message_response_times: List[float] = field(default_factory=list)
    
    # Error tracking
    connection_errors: Dict[str, int] = field(default_factory=dict)
    message_errors: Dict[str, int] = field(default_factory=dict)
    
    # Lifecycle metrics
    disconnections: int = 0
    reconnections: int = 0
    connection_duration: List[float] = field(default_factory=list)
    
    @property
    def connection_success_rate(self) -> float:
        """Connection success rate percentage."""
        if self.connection_attempts == 0:
            return 0.0
        return (self.successful_connections / self.connection_attempts) * 100
    
    @property
    def message_success_rate(self) -> float:
        """Message delivery success rate percentage."""
        if self.messages_sent == 0:
            return 0.0
        return (self.messages_received / self.messages_sent) * 100
    
    @property
    def avg_connection_time(self) -> float:
        """Average connection establishment time in milliseconds."""
        return statistics.mean(self.connection_times) * 1000 if self.connection_times else 0.0
    
    @property
    def avg_response_time(self) -> float:
        """Average message response time in milliseconds."""
        return statistics.mean(self.message_response_times) * 1000 if self.message_response_times else 0.0


class WebSocketTestServer:
    """High-performance WebSocket test server for load testing."""
    
    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.server = None
        self.active_connections = set()
        self.message_count = 0
        self.start_time = None
        
    async def start_server(self):
        """Start the WebSocket test server."""
        print(f"[WS SERVER] Starting WebSocket server on {self.host}:{self.port}")
        self.start_time = time.time()
        
        async def handle_client(websocket, path):
            """Handle individual WebSocket client connections."""
            client_id = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
            self.active_connections.add(websocket)
            
            try:
                # Send welcome message
                welcome_msg = {
                    "type": "welcome",
                    "client_id": client_id,
                    "server_time": time.time(),
                    "active_connections": len(self.active_connections)
                }
                await websocket.send(json.dumps(welcome_msg))
                
                # Handle incoming messages
                async for message in websocket:
                    try:
                        self.message_count += 1
                        data = json.loads(message)
                        
                        # Echo message with server processing info
                        response = {
                            "type": "echo",
                            "original_message": data,
                            "server_time": time.time(),
                            "message_id": self.message_count,
                            "active_connections": len(self.active_connections),
                            "server_uptime": time.time() - self.start_time
                        }
                        
                        await websocket.send(json.dumps(response))
                        
                        # Handle special commands
                        if data.get("type") == "ping":
                            ping_response = {
                                "type": "pong", 
                                "timestamp": time.time(),
                                "client_timestamp": data.get("timestamp")
                            }
                            await websocket.send(json.dumps(ping_response))
                        
                        elif data.get("type") == "broadcast_test":
                            # Broadcast to all connected clients
                            broadcast_msg = {
                                "type": "broadcast",
                                "from_client": client_id,
                                "message": data.get("message", "Test broadcast"),
                                "timestamp": time.time()
                            }
                            
                            # Send to all other clients
                            for conn in self.active_connections.copy():
                                if conn != websocket:
                                    try:
                                        await conn.send(json.dumps(broadcast_msg))
                                    except websockets.exceptions.ConnectionClosed:
                                        self.active_connections.discard(conn)
                    
                    except json.JSONDecodeError:
                        error_response = {
                            "type": "error",
                            "message": "Invalid JSON format",
                            "timestamp": time.time()
                        }
                        await websocket.send(json.dumps(error_response))
                    
                    except Exception as e:
                        error_response = {
                            "type": "error", 
                            "message": f"Server error: {str(e)}",
                            "timestamp": time.time()
                        }
                        await websocket.send(json.dumps(error_response))
            
            except websockets.exceptions.ConnectionClosed:
                pass
            except Exception as e:
                print(f"[WS SERVER] Client handler error: {e}")
            finally:
                self.active_connections.discard(websocket)
        
        self.server = await websockets.serve(
            handle_client, 
            self.host, 
            self.port,
            max_size=1024*1024,  # 1MB max message size
            max_queue=1000,      # Max queued messages
            ping_interval=20,    # Ping every 20 seconds
            ping_timeout=10      # Ping timeout 10 seconds
        )
        
        print(f"[WS SERVER] Server started with {len(self.active_connections)} connections")
    
    async def stop_server(self):
        """Stop the WebSocket server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print(f"[WS SERVER] Server stopped. Handled {self.message_count} messages")
    
    def get_server_stats(self) -> Dict[str, Any]:
        """Get current server statistics."""
        uptime = time.time() - self.start_time if self.start_time else 0
        return {
            "uptime_seconds": uptime,
            "active_connections": len(self.active_connections),
            "total_messages": self.message_count,
            "messages_per_second": self.message_count / uptime if uptime > 0 else 0
        }


class WebSocketLoadTestClient:
    """Load testing client for WebSocket connections."""
    
    def __init__(self, client_id: str, server_url: str):
        self.client_id = client_id
        self.server_url = server_url
        self.websocket = None
        self.metrics = WebSocketMetrics()
        self.is_connected = False
        self.message_queue = asyncio.Queue()
        
    async def connect(self) -> bool:
        """Establish WebSocket connection with timing."""
        self.metrics.connection_attempts += 1
        connection_start = time.time()
        
        try:
            self.websocket = await websockets.connect(
                self.server_url,
                ping_interval=20,
                ping_timeout=10,
                max_size=1024*1024
            )
            
            connection_time = time.time() - connection_start
            self.metrics.connection_times.append(connection_time)
            self.metrics.successful_connections += 1
            self.is_connected = True
            
            # Wait for welcome message
            welcome = await self.websocket.recv()
            welcome_data = json.loads(welcome)
            
            return True
            
        except Exception as e:
            connection_time = time.time() - connection_start
            self.metrics.connection_times.append(connection_time)
            self.metrics.failed_connections += 1
            
            error_type = type(e).__name__
            self.metrics.connection_errors[error_type] = \
                self.metrics.connection_errors.get(error_type, 0) + 1
            
            return False
    
    async def send_message(self, message: Dict[str, Any]) -> bool:
        """Send message and measure response time."""
        if not self.is_connected or not self.websocket:
            return False
        
        try:
            self.metrics.messages_sent += 1
            message_start = time.time()
            
            await self.websocket.send(json.dumps(message))
            
            # Wait for response (with timeout)
            try:
                response = await asyncio.wait_for(self.websocket.recv(), timeout=5.0)
                message_time = time.time() - message_start
                self.metrics.message_response_times.append(message_time)
                self.metrics.messages_received += 1
                return True
                
            except asyncio.TimeoutError:
                self.metrics.message_errors["timeout"] = \
                    self.metrics.message_errors.get("timeout", 0) + 1
                return False
        
        except Exception as e:
            error_type = type(e).__name__
            self.metrics.message_errors[error_type] = \
                self.metrics.message_errors.get(error_type, 0) + 1
            return False
    
    async def ping_test(self) -> Optional[float]:
        """Perform ping test and return round-trip time."""
        if not self.is_connected:
            return None
        
        ping_message = {
            "type": "ping",
            "timestamp": time.time(),
            "client_id": self.client_id
        }
        
        ping_start = time.time()
        success = await self.send_message(ping_message)
        
        if success:
            return time.time() - ping_start
        return None
    
    async def disconnect(self):
        """Close WebSocket connection."""
        if self.websocket:
            try:
                await self.websocket.close()
                self.metrics.disconnections += 1
            except Exception:
                pass
            finally:
                self.is_connected = False
                self.websocket = None


class WebSocketLoadTester:
    """Comprehensive WebSocket load testing framework."""
    
    def __init__(self, server_host: str = "localhost", server_port: int = 8765):
        self.server_host = server_host
        self.server_port = server_port
        self.server_url = f"ws://{server_host}:{server_port}"
        self.test_server = WebSocketTestServer(server_host, server_port)
        self.clients = []
        self.test_results = {}
        
    async def test_connection_capacity(self, 
                                     max_connections: int = 100,
                                     connection_rate: float = 10.0) -> Dict[str, Any]:
        """Test maximum concurrent connection capacity."""
        print(f"[WS LOAD] Testing connection capacity up to {max_connections} connections")
        
        # Start test server
        await self.test_server.start_server()
        
        try:
            results = {
                "target_connections": max_connections,
                "connection_rate_per_second": connection_rate,
                "connection_results": [],
                "final_stats": {}
            }
            
            clients = []
            successful_connections = 0
            
            # Calculate connection interval
            connection_interval = 1.0 / connection_rate
            
            for i in range(max_connections):
                client = WebSocketLoadTestClient(f"load_client_{i}", self.server_url)
                
                # Attempt connection
                connected = await client.connect()
                
                if connected:
                    clients.append(client)
                    successful_connections += 1
                    
                    # Test a quick message to verify connection
                    test_msg = {
                        "type": "connection_test",
                        "client_id": client.client_id,
                        "connection_number": i + 1
                    }
                    await client.send_message(test_msg)
                
                # Record progress
                if (i + 1) % 10 == 0:
                    print(f"    Connected {successful_connections}/{i + 1} clients")
                
                # Wait before next connection attempt
                if i < max_connections - 1:
                    await asyncio.sleep(connection_interval)
            
            # Hold connections and test stability
            print(f"    Holding {successful_connections} connections for stability test...")
            stability_start = time.time()
            
            # Send periodic messages to test connection stability
            for round in range(3):  # 3 rounds of messages
                active_clients = [c for c in clients if c.is_connected]
                print(f"      Round {round + 1}: Testing {len(active_clients)} active connections")
                
                tasks = []
                for client in active_clients:
                    test_msg = {
                        "type": "stability_test",
                        "round": round + 1,
                        "timestamp": time.time()
                    }
                    tasks.append(client.send_message(test_msg))
                
                results_round = await asyncio.gather(*tasks, return_exceptions=True)
                successful_messages = sum(1 for r in results_round if r is True)
                
                results["connection_results"].append({
                    "round": round + 1,
                    "active_connections": len(active_clients),
                    "messages_sent": len(tasks),
                    "messages_successful": successful_messages,
                    "success_rate": (successful_messages / len(tasks) * 100) if tasks else 0
                })
                
                await asyncio.sleep(2)  # Wait between rounds
            
            stability_duration = time.time() - stability_start
            
            # Clean up connections
            print(f"    Disconnecting {len(clients)} clients...")
            disconnect_tasks = [client.disconnect() for client in clients]
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)
            
            # Aggregate metrics
            all_metrics = [client.metrics for client in clients]
            
            results["final_stats"] = {
                "total_connection_attempts": sum(m.connection_attempts for m in all_metrics),
                "successful_connections": sum(m.successful_connections for m in all_metrics),
                "connection_success_rate": (successful_connections / max_connections * 100) if max_connections > 0 else 0,
                "avg_connection_time_ms": statistics.mean([m.avg_connection_time for m in all_metrics if m.connection_times]),
                "total_messages_sent": sum(m.messages_sent for m in all_metrics),
                "total_messages_received": sum(m.messages_received for m in all_metrics),
                "overall_message_success_rate": (sum(m.messages_received for m in all_metrics) / sum(m.messages_sent for m in all_metrics) * 100) if sum(m.messages_sent for m in all_metrics) > 0 else 0,
                "stability_test_duration": stability_duration
            }
            
            return results
            
        finally:
            await self.test_server.stop_server()
    
    async def test_message_throughput(self, 
                                    concurrent_connections: int = 20,
                                    messages_per_connection: int = 100,
                                    message_rate_per_second: float = 5.0) -> Dict[str, Any]:
        """Test message throughput under various loads."""
        print(f"[WS LOAD] Testing message throughput: {concurrent_connections} connections, {messages_per_connection} messages each")
        
        await self.test_server.start_server()
        
        try:
            # Establish connections
            clients = []
            for i in range(concurrent_connections):
                client = WebSocketLoadTestClient(f"throughput_client_{i}", self.server_url)
                if await client.connect():
                    clients.append(client)
            
            print(f"    Established {len(clients)} connections")
            
            # Calculate message sending parameters
            message_interval = 1.0 / message_rate_per_second
            
            async def client_message_worker(client: WebSocketLoadTestClient) -> Dict[str, Any]:
                """Worker function to send messages from a single client."""
                client_start = time.time()
                successful_messages = 0
                
                for msg_id in range(messages_per_connection):
                    message = {
                        "type": "throughput_test",
                        "message_id": msg_id,
                        "client_id": client.client_id,
                        "timestamp": time.time(),
                        "data": f"Test message {msg_id} from {client.client_id}"
                    }
                    
                    success = await client.send_message(message)
                    if success:
                        successful_messages += 1
                    
                    # Rate limiting
                    if msg_id < messages_per_connection - 1:
                        await asyncio.sleep(message_interval)
                
                client_duration = time.time() - client_start
                
                return {
                    "client_id": client.client_id,
                    "messages_sent": messages_per_connection,
                    "successful_messages": successful_messages,
                    "success_rate": (successful_messages / messages_per_connection * 100) if messages_per_connection > 0 else 0,
                    "duration": client_duration,
                    "avg_response_time": client.metrics.avg_response_time
                }
            
            # Execute message sending concurrently
            throughput_start = time.time()
            client_tasks = [client_message_worker(client) for client in clients]
            client_results = await asyncio.gather(*client_tasks)
            throughput_duration = time.time() - throughput_start
            
            # Aggregate results
            total_messages_sent = sum(r["messages_sent"] for r in client_results)
            total_successful = sum(r["successful_messages"] for r in client_results)
            avg_client_success_rate = statistics.mean([r["success_rate"] for r in client_results])
            avg_response_times = [r["avg_response_time"] for r in client_results if r["avg_response_time"] > 0]
            
            # Clean up
            disconnect_tasks = [client.disconnect() for client in clients]
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)
            
            return {
                "test_config": {
                    "concurrent_connections": concurrent_connections,
                    "messages_per_connection": messages_per_connection,
                    "target_message_rate": message_rate_per_second
                },
                "performance_results": {
                    "total_test_duration": throughput_duration,
                    "total_messages_sent": total_messages_sent,
                    "total_successful_messages": total_successful,
                    "overall_success_rate": (total_successful / total_messages_sent * 100) if total_messages_sent > 0 else 0,
                    "avg_client_success_rate": avg_client_success_rate,
                    "actual_throughput_msgs_per_sec": total_messages_sent / throughput_duration,
                    "successful_throughput_msgs_per_sec": total_successful / throughput_duration,
                    "avg_response_time_ms": statistics.mean(avg_response_times) if avg_response_times else 0,
                    "response_time_p95_ms": np.percentile(avg_response_times, 95) if avg_response_times else 0
                },
                "client_results": client_results
            }
            
        finally:
            await self.test_server.stop_server()
    
    async def test_connection_stability(self, 
                                      connection_count: int = 25,
                                      test_duration_minutes: float = 5.0) -> Dict[str, Any]:
        """Test WebSocket connection stability over time."""
        print(f"[WS LOAD] Testing connection stability: {connection_count} connections for {test_duration_minutes} minutes")
        
        await self.test_server.start_server()
        
        try:
            test_duration = test_duration_minutes * 60  # Convert to seconds
            
            # Establish connections
            clients = []
            for i in range(connection_count):
                client = WebSocketLoadTestClient(f"stability_client_{i}", self.server_url)
                if await client.connect():
                    clients.append(client)
            
            print(f"    Established {len(clients)} stable connections")
            
            # Track stability metrics
            stability_samples = []
            sample_interval = 30  # Sample every 30 seconds
            samples_count = int(test_duration / sample_interval)
            
            start_time = time.time()
            
            for sample_idx in range(samples_count):
                sample_start = time.time()
                print(f"    Stability sample {sample_idx + 1}/{samples_count}")
                
                # Test all connections with ping
                ping_tasks = []
                active_clients = [c for c in clients if c.is_connected]
                
                for client in active_clients:
                    ping_tasks.append(client.ping_test())
                
                ping_results = await asyncio.gather(*ping_tasks, return_exceptions=True)
                
                # Analyze ping results
                successful_pings = [r for r in ping_results if isinstance(r, float)]
                failed_pings = len(ping_results) - len(successful_pings)
                
                sample_data = {
                    "sample_number": sample_idx + 1,
                    "timestamp": sample_start,
                    "elapsed_minutes": (sample_start - start_time) / 60,
                    "active_connections": len(active_clients),
                    "ping_attempts": len(ping_tasks),
                    "successful_pings": len(successful_pings),
                    "failed_pings": failed_pings,
                    "ping_success_rate": (len(successful_pings) / len(ping_tasks) * 100) if ping_tasks else 0,
                    "avg_ping_time_ms": (statistics.mean(successful_pings) * 1000) if successful_pings else 0,
                    "max_ping_time_ms": (max(successful_pings) * 1000) if successful_pings else 0
                }
                
                stability_samples.append(sample_data)
                
                # Wait for next sample interval
                if sample_idx < samples_count - 1:
                    elapsed = time.time() - sample_start
                    sleep_time = max(0, sample_interval - elapsed)
                    await asyncio.sleep(sleep_time)
            
            total_duration = time.time() - start_time
            
            # Clean up connections
            disconnect_tasks = [client.disconnect() for client in clients]
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)
            
            # Analyze stability trends
            ping_success_rates = [s["ping_success_rate"] for s in stability_samples]
            ping_times = [s["avg_ping_time_ms"] for s in stability_samples if s["avg_ping_time_ms"] > 0]
            active_connection_counts = [s["active_connections"] for s in stability_samples]
            
            return {
                "test_config": {
                    "target_connections": connection_count,
                    "test_duration_minutes": test_duration_minutes,
                    "sample_interval_seconds": sample_interval
                },
                "stability_analysis": {
                    "total_duration": total_duration,
                    "samples_collected": len(stability_samples),
                    "avg_ping_success_rate": statistics.mean(ping_success_rates) if ping_success_rates else 0,
                    "min_ping_success_rate": min(ping_success_rates) if ping_success_rates else 0,
                    "avg_ping_time_ms": statistics.mean(ping_times) if ping_times else 0,
                    "ping_time_std_dev": statistics.stdev(ping_times) if len(ping_times) > 1 else 0,
                    "connection_stability": {
                        "avg_active_connections": statistics.mean(active_connection_counts),
                        "min_active_connections": min(active_connection_counts) if active_connection_counts else 0,
                        "connection_drop_rate": ((connection_count - min(active_connection_counts)) / connection_count * 100) if active_connection_counts and connection_count > 0 else 0
                    },
                    "stability_rating": "excellent" if statistics.mean(ping_success_rates) > 95 else ("good" if statistics.mean(ping_success_rates) > 90 else "needs_improvement")
                },
                "stability_samples": stability_samples
            }
            
        finally:
            await self.test_server.stop_server()
    
    async def test_load_scenarios(self) -> Dict[str, Any]:
        """Run comprehensive WebSocket load testing scenarios."""
        print("\n" + "="*60)
        print("WEBSOCKET COMPREHENSIVE LOAD TESTING")
        print("="*60)
        
        all_results = {}
        
        # Scenario 1: Connection Capacity Testing
        print("\n[SCENARIO 1] Connection Capacity Testing")
        all_results["connection_capacity"] = await self.test_connection_capacity(
            max_connections=50,
            connection_rate=5.0
        )
        
        # Brief pause between tests
        await asyncio.sleep(5)
        
        # Scenario 2: Message Throughput Testing
        print("\n[SCENARIO 2] Message Throughput Testing")
        all_results["message_throughput"] = await self.test_message_throughput(
            concurrent_connections=15,
            messages_per_connection=50,
            message_rate_per_second=3.0
        )
        
        await asyncio.sleep(5)
        
        # Scenario 3: Connection Stability Testing
        print("\n[SCENARIO 3] Connection Stability Testing")
        all_results["connection_stability"] = await self.test_connection_stability(
            connection_count=20,
            test_duration_minutes=2.0  # Shorter for testing
        )
        
        # Generate comprehensive analysis
        all_results["websocket_analysis"] = self._analyze_websocket_performance(all_results)
        
        return all_results
    
    def _analyze_websocket_performance(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze WebSocket performance across all test scenarios."""
        analysis = {
            "capacity_assessment": {},
            "performance_characteristics": {},
            "reliability_metrics": {},
            "production_readiness": {}
        }
        
        # Analyze connection capacity
        if "connection_capacity" in results:
            capacity = results["connection_capacity"]
            final_stats = capacity.get("final_stats", {})
            
            analysis["capacity_assessment"] = {
                "max_tested_connections": capacity.get("target_connections", 0),
                "successful_connection_rate": final_stats.get("connection_success_rate", 0),
                "avg_connection_time_ms": final_stats.get("avg_connection_time_ms", 0),
                "message_success_rate": final_stats.get("overall_message_success_rate", 0),
                "capacity_rating": "excellent" if final_stats.get("connection_success_rate", 0) > 95 else ("good" if final_stats.get("connection_success_rate", 0) > 85 else "needs_improvement")
            }
        
        # Analyze message throughput
        if "message_throughput" in results:
            throughput = results["message_throughput"]
            perf_results = throughput.get("performance_results", {})
            
            analysis["performance_characteristics"] = {
                "max_throughput_msgs_per_sec": perf_results.get("actual_throughput_msgs_per_sec", 0),
                "avg_response_time_ms": perf_results.get("avg_response_time_ms", 0),
                "response_time_p95_ms": perf_results.get("response_time_p95_ms", 0),
                "throughput_success_rate": perf_results.get("overall_success_rate", 0),
                "performance_rating": "excellent" if perf_results.get("avg_response_time_ms", 1000) < 100 else ("good" if perf_results.get("avg_response_time_ms", 1000) < 500 else "needs_improvement")
            }
        
        # Analyze connection stability
        if "connection_stability" in results:
            stability = results["connection_stability"]
            stability_analysis = stability.get("stability_analysis", {})
            
            analysis["reliability_metrics"] = {
                "ping_success_rate": stability_analysis.get("avg_ping_success_rate", 0),
                "connection_drop_rate": stability_analysis.get("connection_stability", {}).get("connection_drop_rate", 0),
                "ping_time_consistency": stability_analysis.get("ping_time_std_dev", 0),
                "stability_rating": stability_analysis.get("stability_rating", "unknown")
            }
        
        # Overall production readiness assessment
        capacity_ok = analysis.get("capacity_assessment", {}).get("successful_connection_rate", 0) > 90
        performance_ok = analysis.get("performance_characteristics", {}).get("avg_response_time_ms", 1000) < 200
        reliability_ok = analysis.get("reliability_metrics", {}).get("ping_success_rate", 0) > 95
        
        analysis["production_readiness"] = {
            "capacity_ready": capacity_ok,
            "performance_ready": performance_ok,
            "reliability_ready": reliability_ok,
            "overall_ready": capacity_ok and performance_ok and reliability_ok,
            "readiness_score": sum([capacity_ok, performance_ok, reliability_ok]) / 3 * 100,
            "recommendations": []
        }
        
        # Generate recommendations
        if not capacity_ok:
            analysis["production_readiness"]["recommendations"].append("Optimize connection handling for higher capacity")
        if not performance_ok:
            analysis["production_readiness"]["recommendations"].append("Improve message processing performance")
        if not reliability_ok:
            analysis["production_readiness"]["recommendations"].append("Enhance connection stability and error handling")
        
        if analysis["production_readiness"]["overall_ready"]:
            analysis["production_readiness"]["recommendations"].append("WebSocket implementation is production ready")
        
        return analysis


# Test execution functions
async def test_websocket_load_scenarios():
    """Main WebSocket load testing function."""
    tester = WebSocketLoadTester()
    results = await tester.test_load_scenarios()
    
    # Basic assertions
    assert "websocket_analysis" in results
    analysis = results["websocket_analysis"]
    
    # Check production readiness
    readiness = analysis.get("production_readiness", {})
    readiness_score = readiness.get("readiness_score", 0)
    
    print(f"\n[WS LOAD] WebSocket readiness score: {readiness_score:.1f}%")
    
    # Save results
    results_file = Path("websocket_load_test_results.json")
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"[WS LOAD] Results saved to: {results_file}")
    return results


if __name__ == "__main__":
    async def main():
        print("VoiceFlow WebSocket Load Testing Suite")
        print("=" * 50)
        
        results = await test_websocket_load_scenarios()
        
        # Print summary
        analysis = results.get("websocket_analysis", {})
        readiness = analysis.get("production_readiness", {})
        
        print(f"\nWebSocket Load Testing Summary:")
        print(f"Readiness Score: {readiness.get('readiness_score', 0):.1f}%")
        print(f"Production Ready: {'✅' if readiness.get('overall_ready', False) else '❌'}")
        
        if readiness.get("recommendations"):
            print("\nRecommendations:")
            for rec in readiness["recommendations"]:
                print(f"  • {rec}")
        
        print("\nWebSocket load testing complete!")
    
    asyncio.run(main())