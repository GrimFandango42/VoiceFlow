"""
Resource Pool: Adaptive Model Loading and Memory Management

Implements intelligent resource management for long-running operation:
- Lazy loading with TTL-based model lifecycle
- Memory-aware resource allocation and cleanup
- GPU/CPU adaptive fallback strategies
- Background resource optimization

Based on production service patterns for ML workloads.
"""

import time
import threading
import logging
import gc
import psutil
import weakref
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Callable, Union
from uuid import uuid4, UUID
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict
import torch

logger = logging.getLogger(__name__)

class ResourceState(Enum):
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    UNLOADING = "unloading"
    ERROR = "error"

class ModelType(Enum):
    WHISPER_ASR = "whisper_asr"
    AUDIO_PROCESSOR = "audio_processor"
    TEXT_PROCESSOR = "text_processor"

@dataclass
class ResourceMetrics:
    """Resource usage and performance metrics"""
    resource_id: UUID
    resource_type: ModelType
    load_time: float = 0.0
    memory_usage_mb: float = 0.0
    gpu_memory_mb: float = 0.0
    last_used: datetime = field(default_factory=datetime.now)
    usage_count: int = 0
    error_count: int = 0
    state: ResourceState = ResourceState.UNLOADED

@dataclass
class ResourceConfig:
    """Configuration for resource management"""
    ttl_seconds: float = 1800.0  # 30 minutes TTL
    max_memory_mb: float = 1500.0  # Max memory per resource
    max_gpu_memory_mb: float = 2000.0  # Max GPU memory per resource
    cleanup_interval: float = 300.0  # 5 minutes cleanup interval
    lazy_loading: bool = True
    preload_critical: bool = False
    gpu_fallback: bool = True

class ResourcePool:
    """
    Production-grade resource pool for managing ML models and components.

    Features:
    - Lazy loading with configurable TTL
    - Memory-aware allocation and cleanup
    - Thread-safe resource access
    - Background resource optimization
    - GPU/CPU adaptive strategies
    """

    def __init__(self, config: Optional[ResourceConfig] = None):
        self.config = config or ResourceConfig()

        # Resource tracking
        self.resources: Dict[ModelType, Any] = {}
        self.resource_metrics: Dict[ModelType, ResourceMetrics] = {}
        self.resource_lock = threading.RLock()

        # Background management
        self.cleanup_thread: Optional[threading.Thread] = None
        self.cleanup_active = False
        self.last_cleanup = time.time()

        # Memory monitoring
        self.process = psutil.Process()
        self.memory_threshold_mb = 2000.0  # System memory limit

        # Lifecycle callbacks
        self.load_callbacks: Dict[ModelType, List[Callable]] = defaultdict(list)
        self.unload_callbacks: Dict[ModelType, List[Callable]] = defaultdict(list)

        # Performance tracking
        self.load_history: List[Dict[str, Any]] = []
        self.memory_history: List[Dict[str, Any]] = []

        logger.info("ResourcePool initialized for adaptive model management")

    def start_background_management(self):
        """Start background resource cleanup and optimization"""
        if self.cleanup_active:
            return

        self.cleanup_active = True
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="ResourceCleanup",
            daemon=True
        )
        self.cleanup_thread.start()
        logger.info("Background resource management started")

    def stop_background_management(self):
        """Stop background resource management"""
        self.cleanup_active = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5.0)
        logger.info("Background resource management stopped")

    def get_resource(self, resource_type: ModelType, **kwargs) -> Any:
        """
        Get resource with lazy loading and TTL management.

        Args:
            resource_type: Type of resource to load
            **kwargs: Additional parameters for resource loading

        Returns:
            Loaded resource instance

        Raises:
            RuntimeError: If resource cannot be loaded
        """
        with self.resource_lock:
            # Check if resource exists and is still valid
            if self._is_resource_valid(resource_type):
                self._update_resource_access(resource_type)
                return self.resources[resource_type]

            # Load resource if not available or expired
            return self._load_resource(resource_type, **kwargs)

    def release_resource(self, resource_type: ModelType, force: bool = False) -> bool:
        """
        Release resource from memory.

        Args:
            resource_type: Type of resource to release
            force: Force release even if recently used

        Returns:
            bool: True if resource was released
        """
        with self.resource_lock:
            if resource_type not in self.resources:
                return False

            metrics = self.resource_metrics.get(resource_type)
            if not force and metrics:
                # Don't release if recently used (within 5 minutes)
                if (datetime.now() - metrics.last_used).total_seconds() < 300:
                    logger.debug(f"Skipping release of recently used resource: {resource_type}")
                    return False

            return self._unload_resource(resource_type)

    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage statistics"""
        process_memory = self.process.memory_info().rss / 1024 / 1024

        usage = {
            'process_memory_mb': process_memory,
            'gpu_memory_mb': 0.0,
            'resource_count': len(self.resources)
        }

        # Add GPU memory if available
        if torch.cuda.is_available():
            try:
                gpu_memory = torch.cuda.memory_allocated() / 1024 / 1024
                usage['gpu_memory_mb'] = gpu_memory
            except Exception:
                pass

        return usage

    def cleanup_expired_resources(self) -> int:
        """
        Clean up expired resources based on TTL.

        Returns:
            int: Number of resources cleaned up
        """
        cleaned_count = 0
        current_time = datetime.now()

        with self.resource_lock:
            expired_resources = []

            for resource_type, metrics in self.resource_metrics.items():
                if resource_type in self.resources:
                    time_since_use = (current_time - metrics.last_used).total_seconds()
                    if time_since_use > self.config.ttl_seconds:
                        expired_resources.append(resource_type)

            for resource_type in expired_resources:
                if self._unload_resource(resource_type):
                    cleaned_count += 1
                    logger.info(f"Cleaned up expired resource: {resource_type}")

        return cleaned_count

    def force_memory_cleanup(self) -> Dict[str, Any]:
        """
        Force aggressive memory cleanup when under pressure.

        Returns:
            Dict: Cleanup results and memory freed
        """
        logger.info("Starting force memory cleanup")

        memory_before = self.get_memory_usage()
        cleaned_resources = []

        with self.resource_lock:
            # Unload all non-critical resources
            for resource_type in list(self.resources.keys()):
                if self._unload_resource(resource_type):
                    cleaned_resources.append(resource_type.value)

        # Force garbage collection
        gc.collect()

        # Clear GPU cache if available
        if torch.cuda.is_available():
            try:
                torch.cuda.empty_cache()
                logger.info("GPU cache cleared")
            except Exception as e:
                logger.warning(f"Failed to clear GPU cache: {e}")

        memory_after = self.get_memory_usage()
        memory_freed = memory_before['process_memory_mb'] - memory_after['process_memory_mb']

        result = {
            'memory_freed_mb': memory_freed,
            'resources_unloaded': cleaned_resources,
            'memory_before': memory_before,
            'memory_after': memory_after
        }

        logger.info(f"Force cleanup completed: {memory_freed:.1f}MB freed, {len(cleaned_resources)} resources unloaded")
        return result

    def get_resource_status(self) -> Dict[str, Any]:
        """Get comprehensive resource status report"""
        with self.resource_lock:
            status = {
                'timestamp': datetime.now().isoformat(),
                'total_resources': len(self.resources),
                'memory_usage': self.get_memory_usage(),
                'resources': {}
            }

            for resource_type, metrics in self.resource_metrics.items():
                is_loaded = resource_type in self.resources
                time_since_use = (datetime.now() - metrics.last_used).total_seconds()

                status['resources'][resource_type.value] = {
                    'loaded': is_loaded,
                    'state': metrics.state.value,
                    'memory_mb': metrics.memory_usage_mb,
                    'gpu_memory_mb': metrics.gpu_memory_mb,
                    'usage_count': metrics.usage_count,
                    'error_count': metrics.error_count,
                    'time_since_use_seconds': time_since_use,
                    'load_time_seconds': metrics.load_time
                }

            return status

    def add_load_callback(self, resource_type: ModelType, callback: Callable):
        """Add callback to execute after resource loading"""
        self.load_callbacks[resource_type].append(callback)

    def add_unload_callback(self, resource_type: ModelType, callback: Callable):
        """Add callback to execute before resource unloading"""
        self.unload_callbacks[resource_type].append(callback)

    def _is_resource_valid(self, resource_type: ModelType) -> bool:
        """Check if resource is loaded and within TTL"""
        if resource_type not in self.resources:
            return False

        metrics = self.resource_metrics.get(resource_type)
        if not metrics:
            return False

        # Check TTL
        time_since_use = (datetime.now() - metrics.last_used).total_seconds()
        return time_since_use <= self.config.ttl_seconds

    def _update_resource_access(self, resource_type: ModelType):
        """Update resource access timestamp and usage count"""
        if resource_type in self.resource_metrics:
            metrics = self.resource_metrics[resource_type]
            metrics.last_used = datetime.now()
            metrics.usage_count += 1

    def _load_resource(self, resource_type: ModelType, **kwargs) -> Any:
        """Load resource with error handling and metrics tracking"""
        logger.info(f"Loading resource: {resource_type}")
        load_start = time.time()

        try:
            # Create metrics if not exists
            if resource_type not in self.resource_metrics:
                self.resource_metrics[resource_type] = ResourceMetrics(
                    resource_id=uuid4(),
                    resource_type=resource_type
                )

            metrics = self.resource_metrics[resource_type]
            metrics.state = ResourceState.LOADING

            # Load resource based on type
            resource = self._create_resource(resource_type, **kwargs)

            # Store resource and update metrics
            self.resources[resource_type] = resource

            load_time = time.time() - load_start
            metrics.load_time = load_time
            metrics.last_used = datetime.now()
            metrics.usage_count += 1
            metrics.state = ResourceState.LOADED

            # Update memory usage
            self._update_memory_metrics(resource_type)

            # Execute load callbacks
            for callback in self.load_callbacks[resource_type]:
                try:
                    callback(resource)
                except Exception as e:
                    logger.error(f"Load callback failed for {resource_type}: {e}")

            # Record load history
            self.load_history.append({
                'timestamp': datetime.now(),
                'resource_type': resource_type.value,
                'load_time': load_time,
                'memory_mb': metrics.memory_usage_mb
            })

            logger.info(f"Resource loaded successfully: {resource_type} ({load_time:.2f}s)")
            return resource

        except Exception as e:
            logger.error(f"Failed to load resource {resource_type}: {e}")
            if resource_type in self.resource_metrics:
                self.resource_metrics[resource_type].state = ResourceState.ERROR
                self.resource_metrics[resource_type].error_count += 1
            raise RuntimeError(f"Resource loading failed: {e}")

    def _unload_resource(self, resource_type: ModelType) -> bool:
        """Unload resource with cleanup and callbacks"""
        if resource_type not in self.resources:
            return False

        logger.info(f"Unloading resource: {resource_type}")

        try:
            metrics = self.resource_metrics.get(resource_type)
            if metrics:
                metrics.state = ResourceState.UNLOADING

            # Execute unload callbacks
            resource = self.resources[resource_type]
            for callback in self.unload_callbacks[resource_type]:
                try:
                    callback(resource)
                except Exception as e:
                    logger.error(f"Unload callback failed for {resource_type}: {e}")

            # Clean up resource
            self._cleanup_resource(resource)

            # Remove from tracking
            del self.resources[resource_type]

            if metrics:
                metrics.state = ResourceState.UNLOADED
                metrics.memory_usage_mb = 0.0
                metrics.gpu_memory_mb = 0.0

            logger.info(f"Resource unloaded successfully: {resource_type}")
            return True

        except Exception as e:
            logger.error(f"Failed to unload resource {resource_type}: {e}")
            return False

    def _create_resource(self, resource_type: ModelType, **kwargs) -> Any:
        """Factory method to create specific resource types"""
        if resource_type == ModelType.WHISPER_ASR:
            return self._create_whisper_asr(**kwargs)
        elif resource_type == ModelType.AUDIO_PROCESSOR:
            return self._create_audio_processor(**kwargs)
        elif resource_type == ModelType.TEXT_PROCESSOR:
            return self._create_text_processor(**kwargs)
        else:
            raise ValueError(f"Unknown resource type: {resource_type}")

    def _create_whisper_asr(self, **kwargs):
        """Create Whisper ASR resource"""
        try:
            from ..core.asr_buffer_safe import BufferSafeWhisperASR
            from ..core.config import Config

            # Use provided config or create default
            config = kwargs.get('config') or Config()

            # Create ASR with adaptive device selection
            asr = BufferSafeWhisperASR(config)

            logger.info(f"Whisper ASR created: model={config.model}, device={config.device}")
            return asr

        except Exception as e:
            logger.error(f"Failed to create Whisper ASR: {e}")
            raise

    def _create_audio_processor(self, **kwargs):
        """Create audio processor resource"""
        try:
            from ..core.audio_enhanced import EnhancedAudioRecorder
            from ..core.config import Config

            config = kwargs.get('config') or Config()

            processor = EnhancedAudioRecorder(
                sample_rate=config.sample_rate,
                channels=config.channels,
                max_duration=config.max_recording_time
            )

            logger.info("Audio processor created")
            return processor

        except Exception as e:
            logger.error(f"Failed to create audio processor: {e}")
            raise

    def _create_text_processor(self, **kwargs):
        """Create text processor resource"""
        try:
            from ..core.textproc import apply_code_mode, format_transcript_text

            # Return a simple processor object with the functions
            class TextProcessor:
                def __init__(self):
                    self.apply_code_mode = apply_code_mode
                    self.format_transcript_text = format_transcript_text

            processor = TextProcessor()
            logger.info("Text processor created")
            return processor

        except Exception as e:
            logger.error(f"Failed to create text processor: {e}")
            raise

    def _cleanup_resource(self, resource):
        """Clean up specific resource instance"""
        try:
            # Call cleanup method if available
            if hasattr(resource, 'cleanup'):
                resource.cleanup()
            elif hasattr(resource, 'close'):
                resource.close()
            elif hasattr(resource, '__del__'):
                del resource

            # Force garbage collection
            gc.collect()

        except Exception as e:
            logger.warning(f"Resource cleanup warning: {e}")

    def _update_memory_metrics(self, resource_type: ModelType):
        """Update memory usage metrics for resource"""
        try:
            process_memory = self.process.memory_info().rss / 1024 / 1024
            gpu_memory = 0.0

            if torch.cuda.is_available():
                try:
                    gpu_memory = torch.cuda.memory_allocated() / 1024 / 1024
                except Exception:
                    pass

            if resource_type in self.resource_metrics:
                metrics = self.resource_metrics[resource_type]
                metrics.memory_usage_mb = process_memory
                metrics.gpu_memory_mb = gpu_memory

        except Exception as e:
            logger.warning(f"Failed to update memory metrics: {e}")

    def _cleanup_loop(self):
        """Background cleanup loop"""
        logger.info("Resource cleanup loop started")

        while self.cleanup_active:
            try:
                current_time = time.time()

                # Skip if too soon since last cleanup
                if current_time - self.last_cleanup < self.config.cleanup_interval:
                    time.sleep(10.0)
                    continue

                self.last_cleanup = current_time

                # Check memory pressure
                memory_usage = self.get_memory_usage()
                if memory_usage['process_memory_mb'] > self.memory_threshold_mb:
                    logger.warning(f"High memory usage detected: {memory_usage['process_memory_mb']:.1f}MB")
                    self.force_memory_cleanup()
                else:
                    # Normal cleanup of expired resources
                    cleaned = self.cleanup_expired_resources()
                    if cleaned > 0:
                        logger.info(f"Cleaned up {cleaned} expired resources")

                # Record memory history
                self.memory_history.append({
                    'timestamp': datetime.now(),
                    'memory_usage': memory_usage
                })

                # Keep only last 100 entries
                if len(self.memory_history) > 100:
                    self.memory_history = self.memory_history[-100:]

                time.sleep(10.0)

            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
                time.sleep(30.0)

        logger.info("Resource cleanup loop stopped")


# Global resource pool instance
_resource_pool: Optional[ResourcePool] = None

def get_resource_pool() -> ResourcePool:
    """Get global resource pool instance"""
    global _resource_pool
    if _resource_pool is None:
        _resource_pool = ResourcePool()
    return _resource_pool

def initialize_resource_management():
    """Initialize global resource management"""
    pool = get_resource_pool()
    pool.start_background_management()
    logger.info("Resource management initialized for 24/7 operation")
    return pool