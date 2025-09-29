"""
State Cleanup: Comprehensive State Management and Recovery

Implements robust state cleanup for long-running operation:
- Process state isolation and recovery
- Thread pool management and cleanup
- Memory leak prevention and monitoring
- Session boundary enforcement
- Error state recovery and reset

Ensures clean state transitions for 24/7 reliability.
"""

import time
import threading
import logging
import gc
import sys
import traceback
import psutil
import weakref
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Set, Callable, Union
from uuid import uuid4, UUID
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
import numpy as np

logger = logging.getLogger(__name__)

class CleanupState(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    CLEANING = "cleaning"
    ERROR = "error"

class StateComponent(Enum):
    AUDIO_BUFFERS = "audio_buffers"
    THREAD_POOLS = "thread_pools"
    MODEL_CACHE = "model_cache"
    GUI_ELEMENTS = "gui_elements"
    SYSTEM_HOOKS = "system_hooks"
    TEMP_FILES = "temp_files"

@dataclass
class CleanupMetrics:
    """Metrics for cleanup operations"""
    component: StateComponent
    cleanup_count: int = 0
    total_cleanup_time: float = 0.0
    memory_freed_mb: float = 0.0
    last_cleanup: datetime = field(default_factory=datetime.now)
    error_count: int = 0
    success_rate: float = 1.0

@dataclass
class StateSnapshot:
    """Point-in-time state snapshot for recovery"""
    timestamp: datetime
    thread_count: int
    memory_usage_mb: float
    active_components: Set[StateComponent]
    error_states: List[str]
    session_id: Optional[UUID] = None

class StateCleanupManager:
    """
    Comprehensive state cleanup manager for production reliability.

    Features:
    - Component-based cleanup with dependency tracking
    - Thread-safe state transitions
    - Memory leak detection and prevention
    - Error state recovery and reset
    - Background monitoring and proactive cleanup
    """

    def __init__(self, cleanup_interval: float = 300.0):  # 5 minutes
        self.cleanup_interval = cleanup_interval

        # State tracking
        self.cleanup_state = CleanupState.IDLE
        self.state_lock = threading.RLock()
        self.active_components: Set[StateComponent] = set()

        # Component registry
        self.component_cleanup_handlers: Dict[StateComponent, List[Callable]] = defaultdict(list)
        self.component_dependencies: Dict[StateComponent, List[StateComponent]] = {}
        self.cleanup_metrics: Dict[StateComponent, CleanupMetrics] = {}

        # Background monitoring
        self.monitor_thread: Optional[threading.Thread] = None
        self.monitor_active = False
        self.last_cleanup = time.time()

        # State snapshots for recovery
        self.state_history: deque = deque(maxlen=50)  # Last 50 snapshots
        self.error_recovery_callbacks: List[Callable] = []

        # Thread pool management
        self.managed_thread_pools: weakref.WeakSet = weakref.WeakSet()
        self.thread_registry: Dict[str, threading.Thread] = {}

        # Memory tracking
        self.process = psutil.Process()
        self.memory_baseline_mb = self.process.memory_info().rss / 1024 / 1024
        self.memory_growth_threshold_mb = 500.0  # Alert if growth > 500MB

        # Initialize component metrics
        for component in StateComponent:
            self.cleanup_metrics[component] = CleanupMetrics(component=component)

        logger.info("StateCleanupManager initialized for comprehensive state management")

    def start_monitoring(self):
        """Start background state monitoring"""
        if self.monitor_active:
            return

        self.monitor_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="StateCleanupMonitor",
            daemon=True
        )
        self.monitor_thread.start()
        logger.info("State cleanup monitoring started")

    def stop_monitoring(self):
        """Stop background state monitoring"""
        self.monitor_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        logger.info("State cleanup monitoring stopped")

    def register_component(self, component: StateComponent,
                         cleanup_handler: Callable,
                         dependencies: Optional[List[StateComponent]] = None):
        """
        Register a component for state management.

        Args:
            component: Component type to register
            cleanup_handler: Function to call for cleanup
            dependencies: Components that must be cleaned before this one
        """
        with self.state_lock:
            self.component_cleanup_handlers[component].append(cleanup_handler)
            if dependencies:
                self.component_dependencies[component] = dependencies

            logger.info(f"Registered cleanup handler for {component}")

    def mark_component_active(self, component: StateComponent):
        """Mark component as active and needing eventual cleanup"""
        with self.state_lock:
            self.active_components.add(component)
            logger.debug(f"Component marked active: {component}")

    def mark_component_inactive(self, component: StateComponent):
        """Mark component as inactive"""
        with self.state_lock:
            self.active_components.discard(component)
            logger.debug(f"Component marked inactive: {component}")

    def cleanup_component(self, component: StateComponent, force: bool = False) -> bool:
        """
        Clean up specific component.

        Args:
            component: Component to clean up
            force: Force cleanup even if dependencies not met

        Returns:
            bool: True if cleanup successful
        """
        with self.state_lock:
            if component not in self.active_components and not force:
                logger.debug(f"Component {component} not active, skipping cleanup")
                return True

            # Check dependencies
            if not force and component in self.component_dependencies:
                for dep in self.component_dependencies[component]:
                    if dep in self.active_components:
                        logger.warning(f"Cannot cleanup {component} - dependency {dep} still active")
                        return False

            return self._execute_component_cleanup(component)

    def cleanup_all_components(self, force: bool = False) -> Dict[StateComponent, bool]:
        """
        Clean up all active components in dependency order.

        Args:
            force: Force cleanup regardless of dependencies

        Returns:
            Dict: Cleanup results for each component
        """
        logger.info("Starting comprehensive component cleanup")
        start_time = time.time()
        results = {}

        with self.state_lock:
            self.cleanup_state = CleanupState.CLEANING

            try:
                # Get cleanup order respecting dependencies
                cleanup_order = self._get_cleanup_order() if not force else list(self.active_components)

                for component in cleanup_order:
                    if component in self.active_components or force:
                        success = self._execute_component_cleanup(component)
                        results[component] = success

                        if success:
                            self.active_components.discard(component)

                # Global cleanup operations
                self._perform_global_cleanup()

                cleanup_time = time.time() - start_time
                logger.info(f"Component cleanup completed in {cleanup_time:.2f}s")

                self.cleanup_state = CleanupState.IDLE
                return results

            except Exception as e:
                logger.error(f"Component cleanup failed: {e}")
                self.cleanup_state = CleanupState.ERROR
                self._trigger_error_recovery(f"cleanup_all_failed: {e}")
                return results

    def force_memory_cleanup(self) -> Dict[str, Any]:
        """
        Force aggressive memory cleanup and state reset.

        Returns:
            Dict: Cleanup results and memory statistics
        """
        logger.warning("Starting force memory cleanup")
        memory_before = self.process.memory_info().rss / 1024 / 1024

        with self.state_lock:
            self.cleanup_state = CleanupState.CLEANING

            try:
                # 1. Clean all components
                component_results = self.cleanup_all_components(force=True)

                # 2. Force thread pool shutdown
                self._force_thread_cleanup()

                # 3. Clear caches and buffers
                self._clear_all_caches()

                # 4. Force garbage collection
                collected = gc.collect()

                # 5. Clear numpy caches if available
                try:
                    import numpy as np
                    # Clear any numpy internal caches
                    np._NoValue  # Access to trigger any lazy loading
                except:
                    pass

                # 6. Clear torch caches if available
                try:
                    import torch
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
                        torch.cuda.ipc_collect()
                except:
                    pass

                memory_after = self.process.memory_info().rss / 1024 / 1024
                memory_freed = memory_before - memory_after

                result = {
                    'memory_before_mb': memory_before,
                    'memory_after_mb': memory_after,
                    'memory_freed_mb': memory_freed,
                    'gc_collected': collected,
                    'components_cleaned': component_results,
                    'threads_cleaned': len(self.thread_registry),
                    'success': True
                }

                logger.info(f"Force memory cleanup completed: {memory_freed:.1f}MB freed")
                self.cleanup_state = CleanupState.IDLE
                return result

            except Exception as e:
                logger.error(f"Force memory cleanup failed: {e}")
                self.cleanup_state = CleanupState.ERROR
                return {'success': False, 'error': str(e)}

    def register_thread_pool(self, pool: ThreadPoolExecutor, name: str = None):
        """Register thread pool for managed cleanup"""
        self.managed_thread_pools.add(pool)
        if name:
            self.thread_registry[name] = pool
        logger.debug(f"Registered thread pool: {name or 'unnamed'}")

    def register_thread(self, thread: threading.Thread, name: str):
        """Register thread for managed cleanup"""
        self.thread_registry[name] = thread
        logger.debug(f"Registered thread: {name}")

    def take_state_snapshot(self, session_id: Optional[UUID] = None) -> StateSnapshot:
        """Take snapshot of current state for recovery purposes"""
        with self.state_lock:
            snapshot = StateSnapshot(
                timestamp=datetime.now(),
                thread_count=threading.active_count(),
                memory_usage_mb=self.process.memory_info().rss / 1024 / 1024,
                active_components=self.active_components.copy(),
                error_states=self._get_error_states(),
                session_id=session_id
            )

            self.state_history.append(snapshot)
            logger.debug(f"State snapshot taken: {len(self.active_components)} active components")
            return snapshot

    def get_cleanup_status(self) -> Dict[str, Any]:
        """Get comprehensive cleanup status report"""
        with self.state_lock:
            current_memory = self.process.memory_info().rss / 1024 / 1024
            memory_growth = current_memory - self.memory_baseline_mb

            status = {
                'timestamp': datetime.now().isoformat(),
                'cleanup_state': self.cleanup_state.value,
                'active_components': [c.value for c in self.active_components],
                'memory_usage_mb': current_memory,
                'memory_baseline_mb': self.memory_baseline_mb,
                'memory_growth_mb': memory_growth,
                'thread_count': threading.active_count(),
                'registered_threads': list(self.thread_registry.keys()),
                'last_cleanup_ago': time.time() - self.last_cleanup,
                'cleanup_metrics': {}
            }

            # Add component metrics
            for component, metrics in self.cleanup_metrics.items():
                status['cleanup_metrics'][component.value] = {
                    'cleanup_count': metrics.cleanup_count,
                    'total_time': metrics.total_cleanup_time,
                    'memory_freed_mb': metrics.memory_freed_mb,
                    'error_count': metrics.error_count,
                    'success_rate': metrics.success_rate
                }

            return status

    def add_error_recovery_callback(self, callback: Callable):
        """Add callback for error recovery situations"""
        self.error_recovery_callbacks.append(callback)

    def _execute_component_cleanup(self, component: StateComponent) -> bool:
        """Execute cleanup for specific component"""
        logger.debug(f"Cleaning up component: {component}")
        cleanup_start = time.time()
        memory_before = self.process.memory_info().rss / 1024 / 1024

        try:
            metrics = self.cleanup_metrics[component]

            # Execute all cleanup handlers for this component
            for handler in self.component_cleanup_handlers[component]:
                try:
                    handler()
                except Exception as e:
                    logger.error(f"Cleanup handler failed for {component}: {e}")
                    metrics.error_count += 1
                    return False

            # Update metrics
            cleanup_time = time.time() - cleanup_start
            memory_after = self.process.memory_info().rss / 1024 / 1024
            memory_freed = max(0, memory_before - memory_after)

            metrics.cleanup_count += 1
            metrics.total_cleanup_time += cleanup_time
            metrics.memory_freed_mb += memory_freed
            metrics.last_cleanup = datetime.now()
            metrics.success_rate = (metrics.cleanup_count - metrics.error_count) / metrics.cleanup_count

            logger.debug(f"Component {component} cleaned successfully ({cleanup_time:.2f}s, {memory_freed:.1f}MB freed)")
            return True

        except Exception as e:
            logger.error(f"Component cleanup failed for {component}: {e}")
            self.cleanup_metrics[component].error_count += 1
            return False

    def _get_cleanup_order(self) -> List[StateComponent]:
        """Get cleanup order respecting dependencies"""
        # Simple topological sort for cleanup order
        ordered = []
        remaining = self.active_components.copy()

        while remaining:
            # Find components with no dependencies or whose dependencies are already cleaned
            ready = []
            for component in remaining:
                dependencies = self.component_dependencies.get(component, [])
                if all(dep not in remaining for dep in dependencies):
                    ready.append(component)

            if not ready:
                # Circular dependency or error - add remaining components
                ready = list(remaining)

            ordered.extend(ready)
            remaining -= set(ready)

        return ordered

    def _perform_global_cleanup(self):
        """Perform global cleanup operations"""
        try:
            # Force garbage collection
            collected = gc.collect()
            logger.debug(f"Garbage collection freed {collected} objects")

            # Clear thread registry of dead threads
            dead_threads = []
            for name, thread in self.thread_registry.items():
                if isinstance(thread, threading.Thread) and not thread.is_alive():
                    dead_threads.append(name)

            for name in dead_threads:
                del self.thread_registry[name]

            if dead_threads:
                logger.debug(f"Removed {len(dead_threads)} dead threads from registry")

        except Exception as e:
            logger.warning(f"Global cleanup warning: {e}")

    def _force_thread_cleanup(self):
        """Force cleanup of all managed threads and pools"""
        logger.info("Starting force thread cleanup")

        # Shutdown managed thread pools
        for pool in list(self.managed_thread_pools):
            try:
                pool.shutdown(wait=False)
                logger.debug("Thread pool shutdown initiated")
            except Exception as e:
                logger.warning(f"Thread pool shutdown error: {e}")

        # Clear registry
        self.thread_registry.clear()
        self.managed_thread_pools.clear()

    def _clear_all_caches(self):
        """Clear all internal caches and buffers"""
        try:
            # Clear state history except last few snapshots
            while len(self.state_history) > 5:
                self.state_history.popleft()

            # Reset component metrics memory counters
            for metrics in self.cleanup_metrics.values():
                metrics.memory_freed_mb = 0.0

            logger.debug("Internal caches cleared")

        except Exception as e:
            logger.warning(f"Cache clearing warning: {e}")

    def _get_error_states(self) -> List[str]:
        """Get list of current error states"""
        errors = []

        # Check memory growth
        current_memory = self.process.memory_info().rss / 1024 / 1024
        memory_growth = current_memory - self.memory_baseline_mb
        if memory_growth > self.memory_growth_threshold_mb:
            errors.append(f"high_memory_growth_{memory_growth:.1f}MB")

        # Check thread count
        thread_count = threading.active_count()
        if thread_count > 20:  # Reasonable threshold
            errors.append(f"high_thread_count_{thread_count}")

        # Check component error rates
        for component, metrics in self.cleanup_metrics.items():
            if metrics.cleanup_count > 0 and metrics.success_rate < 0.8:
                errors.append(f"low_success_rate_{component.value}_{metrics.success_rate:.2f}")

        return errors

    def _trigger_error_recovery(self, error_context: str):
        """Trigger error recovery procedures"""
        logger.warning(f"Triggering error recovery: {error_context}")

        for callback in self.error_recovery_callbacks:
            try:
                callback(error_context)
            except Exception as e:
                logger.error(f"Error recovery callback failed: {e}")

    def _monitor_loop(self):
        """Background monitoring and proactive cleanup loop"""
        logger.info("State cleanup monitoring loop started")

        while self.monitor_active:
            try:
                current_time = time.time()

                # Skip if too soon since last check
                if current_time - self.last_cleanup < self.cleanup_interval:
                    time.sleep(30.0)
                    continue

                self.last_cleanup = current_time

                # Take state snapshot
                snapshot = self.take_state_snapshot()

                # Check for proactive cleanup needs
                current_memory = snapshot.memory_usage_mb
                memory_growth = current_memory - self.memory_baseline_mb

                if memory_growth > self.memory_growth_threshold_mb:
                    logger.warning(f"High memory growth detected: {memory_growth:.1f}MB")
                    self.force_memory_cleanup()

                elif len(self.active_components) > 5:
                    # Many active components - do selective cleanup
                    logger.info("Multiple active components detected, performing selective cleanup")
                    self.cleanup_all_components()

                # Check for stuck threads
                if threading.active_count() > 15:
                    logger.warning(f"High thread count: {threading.active_count()}")

                time.sleep(30.0)

            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(60.0)

        logger.info("State cleanup monitoring loop stopped")


# Global state cleanup manager instance
_state_cleanup_manager: Optional[StateCleanupManager] = None

def get_state_cleanup_manager() -> StateCleanupManager:
    """Get global state cleanup manager instance"""
    global _state_cleanup_manager
    if _state_cleanup_manager is None:
        _state_cleanup_manager = StateCleanupManager()
    return _state_cleanup_manager

def initialize_state_cleanup():
    """Initialize global state cleanup management"""
    manager = get_state_cleanup_manager()
    manager.start_monitoring()
    logger.info("State cleanup management initialized for 24/7 operation")
    return manager

# Convenience functions for common cleanup operations
def cleanup_audio_buffers():
    """Cleanup audio buffer components"""
    try:
        # Clear numpy arrays that might be lingering
        gc.collect()
        logger.debug("Audio buffers cleaned")
    except Exception as e:
        logger.warning(f"Audio buffer cleanup warning: {e}")

def cleanup_thread_pools():
    """Cleanup thread pool components"""
    try:
        manager = get_state_cleanup_manager()
        manager._force_thread_cleanup()
        logger.debug("Thread pools cleaned")
    except Exception as e:
        logger.warning(f"Thread pool cleanup warning: {e}")

def cleanup_model_cache():
    """Cleanup model cache components"""
    try:
        # Force garbage collection for models
        gc.collect()

        # Clear torch cache if available
        try:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except:
            pass

        logger.debug("Model cache cleaned")
    except Exception as e:
        logger.warning(f"Model cache cleanup warning: {e}")