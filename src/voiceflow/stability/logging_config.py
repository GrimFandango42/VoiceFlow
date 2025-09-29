"""
Stability Logging Configuration

Configures comprehensive logging for stability monitoring and diagnostics.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

def setup_stability_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    enable_performance_logging: bool = True,
    enable_error_tracking: bool = True
) -> logging.Logger:
    """
    Setup comprehensive logging for stability monitoring.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (defaults to logs/stability.log)
        enable_performance_logging: Enable performance metrics logging
        enable_error_tracking: Enable detailed error tracking

    Returns:
        Configured logger for stability monitoring
    """
    # Create logs directory if it doesn't exist
    logs_dir = Path(__file__).parent.parent.parent.parent / "logs"
    logs_dir.mkdir(exist_ok=True)

    # Default log file
    if log_file is None:
        log_file = logs_dir / "stability.log"

    # Create logger
    logger = logging.getLogger("voiceflow.stability")
    logger.setLevel(getattr(logging, log_level.upper()))

    # Clear existing handlers
    logger.handlers.clear()

    # Create formatters
    detailed_formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    simple_formatter = logging.Formatter(
        fmt='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )

    # Console handler with simple format
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)

    # File handler with detailed format and rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    logger.addHandler(file_handler)

    # Performance logging handler (if enabled)
    if enable_performance_logging:
        perf_handler = logging.handlers.RotatingFileHandler(
            logs_dir / "performance.log",
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=3,
            encoding='utf-8'
        )
        perf_handler.setLevel(logging.INFO)
        perf_handler.setFormatter(detailed_formatter)

        # Create performance logger
        perf_logger = logging.getLogger("voiceflow.stability.performance")
        perf_logger.setLevel(logging.INFO)
        perf_logger.addHandler(perf_handler)

    # Error tracking handler (if enabled)
    if enable_error_tracking:
        error_handler = logging.handlers.RotatingFileHandler(
            logs_dir / "errors.log",
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=10,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)

        # Create error logger
        error_logger = logging.getLogger("voiceflow.stability.errors")
        error_logger.setLevel(logging.ERROR)
        error_logger.addHandler(error_handler)

    logger.info("Stability logging configured successfully")
    return logger

def get_performance_logger() -> logging.Logger:
    """Get performance metrics logger."""
    return logging.getLogger("voiceflow.stability.performance")

def get_error_logger() -> logging.Logger:
    """Get error tracking logger."""
    return logging.getLogger("voiceflow.stability.errors")

def log_performance_metric(
    metric_name: str,
    value: float,
    unit: str = "",
    context: Optional[dict] = None
) -> None:
    """
    Log a performance metric.

    Args:
        metric_name: Name of the metric
        value: Metric value
        unit: Unit of measurement
        context: Additional context information
    """
    perf_logger = get_performance_logger()
    context_str = f" | Context: {context}" if context else ""
    perf_logger.info(f"METRIC | {metric_name}: {value}{unit}{context_str}")

def log_error_with_context(
    error: Exception,
    context: dict,
    component: str = "unknown"
) -> None:
    """
    Log an error with detailed context.

    Args:
        error: The exception that occurred
        context: Context information about the error
        component: Component where the error occurred
    """
    error_logger = get_error_logger()
    error_logger.error(
        f"ERROR | Component: {component} | "
        f"Error: {type(error).__name__}: {error} | "
        f"Context: {context}"
    )