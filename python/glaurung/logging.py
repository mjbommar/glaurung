"""
Structured logging configuration for Glaurung.

This module provides centralized logging configuration using structlog,
with support for both development and production environments.
"""

import logging
import sys
from enum import Enum
from typing import Optional

import structlog
from structlog.contextvars import bind_contextvars, unbind_contextvars

# Try to import the native logging functions
try:
    from glaurung._native import LogLevel, init_logging as _init_native_logging
    HAS_NATIVE_LOGGING = True
except ImportError:
    HAS_NATIVE_LOGGING = False
    
    class LogLevel(Enum):
        """Fallback log level enum if native not available."""
        TRACE = "TRACE"
        DEBUG = "DEBUG" 
        INFO = "INFO"
        WARN = "WARN"
        ERROR = "ERROR"


def configure_logging(
    level: str = "INFO",
    json_output: bool = False,
    add_timestamp: bool = True,
    colorize: bool = None,
) -> None:
    """
    Configure structured logging for Glaurung.
    
    Args:
        level: Log level (TRACE, DEBUG, INFO, WARN, ERROR)
        json_output: Output logs as JSON for machine parsing
        add_timestamp: Include timestamps in log output
        colorize: Colorize output (auto-detect if None)
    """
    # Configure Python logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )
    
    # Determine if we should colorize
    if colorize is None:
        colorize = sys.stdout.isatty() and not json_output
    
    # Build processor chain
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    if add_timestamp:
        processors.insert(0, structlog.processors.TimeStamper(fmt="iso"))
    
    # Add final renderer
    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(
            structlog.dev.ConsoleRenderer(colors=colorize)
        )
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Initialize native Rust logging if available
    if HAS_NATIVE_LOGGING:
        _init_native_logging(json_output)


def get_logger(name: Optional[str] = None) -> structlog.BoundLogger:
    """
    Get a structured logger instance.
    
    Args:
        name: Logger name (defaults to module name)
        
    Returns:
        Configured structlog BoundLogger
    """
    return structlog.get_logger(name)


class LogContext:
    """Context manager for temporary logging context."""
    
    def __init__(self, **kwargs):
        self.context = kwargs
        
    def __enter__(self):
        bind_contextvars(**self.context)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        unbind_contextvars(*self.context.keys())


def log_operation(operation: str, **context):
    """
    Decorator for logging function execution.
    
    Args:
        operation: Name of the operation being performed
        **context: Additional context to bind
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger = get_logger()
            
            with LogContext(operation=operation, **context):
                logger.info(f"Starting {operation}")
                try:
                    result = func(*args, **kwargs)
                    logger.info(f"Completed {operation}")
                    return result
                except Exception:
                    logger.error(f"Failed {operation}", exc_info=True)
                    raise
                    
        return wrapper
    return decorator


def log_binary_analysis(binary_path: str, format_type: str = None):
    """
    Create logging context for binary analysis.
    
    Args:
        binary_path: Path to the binary being analyzed
        format_type: Binary format (ELF, PE, etc.)
    """
    context = {"binary_path": binary_path}
    if format_type:
        context["format"] = format_type
    return LogContext(**context)


def log_triage_step(step: str, artifact_id: str = None):
    """
    Create logging context for triage pipeline steps.
    
    Args:
        step: Name of the triage step
        artifact_id: ID of the artifact being processed
    """
    context = {"triage_step": step}
    if artifact_id:
        context["artifact_id"] = artifact_id
    return LogContext(**context)


# Module-level logger
logger = get_logger(__name__)

# Example usage in docstring
"""
Example usage:

    from glaurung.logging import configure_logging, get_logger, log_operation

    # Configure logging at startup
    configure_logging(level="DEBUG", json_output=False)
    
    # Get a logger
    logger = get_logger(__name__)
    
    # Basic logging
    logger.info("Starting analysis", binary="test.exe", size=1024)
    
    # Using context
    with log_binary_analysis("/path/to/binary", "ELF"):
        logger.info("Parsing headers")
        # ... do work
        
    # Using decorator
    @log_operation("parse_elf")
    def parse_elf_binary(path):
        # ... implementation
        pass
"""