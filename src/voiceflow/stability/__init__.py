"""
VoiceFlow Stability Module

Comprehensive stability and reliability improvements for 24/7 transcription operation:
- Session lifecycle management with health monitoring
- Adaptive resource pooling with TTL-based cleanup
- State cleanup and memory management
- Error recovery and circuit breaker patterns
- Hallucination detection and filtering

Transforms VoiceFlow into a production-ready long-running service.
"""

import logging

logger = logging.getLogger(__name__)

# Core stability components
try:
    from .session_manager import (
        SessionManager, SessionState, SessionMetrics,
        get_session_manager, initialize_session_management
    )
except ImportError:
    logger.warning("Session manager not available")
    SessionManager = None

try:
    from .resource_pool import (
        ResourcePool, ResourceState, ModelType, ResourceConfig,
        get_resource_pool, initialize_resource_management
    )
except ImportError:
    logger.warning("Resource pool not available")
    ResourcePool = None

try:
    from .state_cleanup import (
        StateCleanupManager, CleanupState, StateComponent,
        get_state_cleanup_manager, initialize_state_cleanup,
        cleanup_audio_buffers, cleanup_thread_pools, cleanup_model_cache
    )
except ImportError:
    logger.warning("State cleanup not available")
    StateCleanupManager = None

# Data models
from .models import (
    AudioSessionInfo,
    TranscriptionRequestInfo,
    SystemStateInfo,
    ErrorRecoveryContext,
    PerformanceMetrics
)

# Error handling and detection
try:
    from .error_recovery import ErrorRecovery
except ImportError:
    logger.warning("Error recovery not available")
    ErrorRecovery = None

try:
    from .hallucination_detector import HallucinationDetector
except ImportError:
    logger.warning("Hallucination detector not available")
    HallucinationDetector = None

# Legacy placeholders
PerformanceMonitor = None
StabilityController = None
AudioValidator = None
StabilityTester = None

__all__ = [
    # Data Models
    'AudioSessionInfo',
    'TranscriptionRequestInfo',
    'SystemStateInfo',
    'ErrorRecoveryContext',
    'PerformanceMetrics',

    # Session Management
    'SessionManager', 'SessionState', 'SessionMetrics',
    'get_session_manager', 'initialize_session_management',

    # Resource Management
    'ResourcePool', 'ResourceState', 'ModelType', 'ResourceConfig',
    'get_resource_pool', 'initialize_resource_management',

    # State Cleanup
    'StateCleanupManager', 'CleanupState', 'StateComponent',
    'get_state_cleanup_manager', 'initialize_state_cleanup',
    'cleanup_audio_buffers', 'cleanup_thread_pools', 'cleanup_model_cache',

    # Error Handling and Detection
    'ErrorRecovery',
    'HallucinationDetector',

    # Legacy placeholders
    'PerformanceMonitor',
    'StabilityController',
    'AudioValidator',
    'StabilityTester',
]

# Stability integration functions
def initialize_stability_system():
    """
    Initialize the complete stability system for 24/7 operation.

    Returns:
        dict: Initialized components
    """
    logger.info("Initializing VoiceFlow stability system...")

    components = {}

    try:
        # Initialize session management
        if SessionManager:
            session_manager = initialize_session_management()
            components['session_manager'] = session_manager

        # Initialize resource management
        if ResourcePool:
            resource_pool = initialize_resource_management()
            components['resource_pool'] = resource_pool

        # Initialize state cleanup
        if StateCleanupManager:
            state_cleanup = initialize_state_cleanup()
            components['state_cleanup'] = state_cleanup

            # Register cleanup handlers
            _register_cleanup_handlers(state_cleanup, components.get('resource_pool'))

        # Register recovery callbacks
        _register_recovery_callbacks(components)

        logger.info("VoiceFlow stability system initialized successfully")
        return components

    except Exception as e:
        logger.error(f"Failed to initialize stability system: {e}")
        raise

def shutdown_stability_system():
    """Shutdown the stability system cleanly"""
    logger.info("Shutting down VoiceFlow stability system...")

    try:
        # Stop monitoring threads
        if SessionManager:
            session_manager = get_session_manager()
            session_manager.stop_health_monitoring()

        if ResourcePool:
            resource_pool = get_resource_pool()
            resource_pool.stop_background_management()

        if StateCleanupManager:
            state_cleanup = get_state_cleanup_manager()
            state_cleanup.stop_monitoring()

            # Final cleanup
            state_cleanup.cleanup_all_components(force=True)

        logger.info("VoiceFlow stability system shutdown complete")

    except Exception as e:
        logger.error(f"Error during stability system shutdown: {e}")

def _register_cleanup_handlers(state_cleanup, resource_pool):
    """Register cleanup handlers for all components"""
    if not state_cleanup:
        return

    # Audio buffer cleanup
    state_cleanup.register_component(
        StateComponent.AUDIO_BUFFERS,
        cleanup_audio_buffers
    )

    # Thread pool cleanup
    state_cleanup.register_component(
        StateComponent.THREAD_POOLS,
        cleanup_thread_pools
    )

    # Model cache cleanup
    state_cleanup.register_component(
        StateComponent.MODEL_CACHE,
        cleanup_model_cache,
        dependencies=[StateComponent.THREAD_POOLS]  # Clean threads first
    )

    # Resource pool cleanup
    if resource_pool:
        def cleanup_resource_pool():
            resource_pool.force_memory_cleanup()

        state_cleanup.register_component(
            StateComponent.MODEL_CACHE,
            cleanup_resource_pool
        )

def _register_recovery_callbacks(components):
    """Register recovery callbacks for error handling"""
    session_manager = components.get('session_manager')
    resource_pool = components.get('resource_pool')
    state_cleanup = components.get('state_cleanup')

    if not session_manager:
        return

    def session_recovery():
        """Recovery callback for session errors"""
        logger.info("Executing session recovery")
        try:
            # Force resource cleanup
            if resource_pool:
                resource_pool.force_memory_cleanup()

            # Force state cleanup
            if state_cleanup:
                state_cleanup.cleanup_all_components(force=True)

        except Exception as e:
            logger.error(f"Session recovery failed: {e}")

    def resource_recovery():
        """Recovery callback for resource errors"""
        logger.info("Executing resource recovery")
        try:
            # Clear all resources
            if resource_pool:
                resource_pool.force_memory_cleanup()

            # Clean up state
            if state_cleanup:
                state_cleanup.cleanup_component(StateComponent.MODEL_CACHE, force=True)

        except Exception as e:
            logger.error(f"Resource recovery failed: {e}")

    # Register callbacks
    session_manager.add_recovery_callback(session_recovery)
    if state_cleanup:
        state_cleanup.add_error_recovery_callback(resource_recovery)

__version__ = "1.0.0"