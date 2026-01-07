"""
Logger utility for IAMCloud CLI
Provides consistent logging across all components
"""

import logging
import sys
from datetime import datetime


def setup_logger(name: str = None, level: int = logging.INFO, 
                format_string: str = None) -> logging.Logger:
    """
    Set up a logger with consistent formatting.
    
    Args:
        name: Logger name (defaults to calling module)
        level: Logging level (default: INFO)
        format_string: Custom format string (optional)
    
    Returns:
        Configured logger instance
    """
    
    if name is None:
        name = __name__
    
    # Remove existing handlers to avoid duplicates
    logger = logging.getLogger(name)
    logger.handlers.clear()
    
    # Set level
    logger.setLevel(level)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    # Create formatter
    if format_string is None:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    formatter = logging.Formatter(format_string)
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)
    
    # Prevent propagation to avoid duplicate logs
    logger.propagate = False
    
    return logger


def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name
    
    Returns:
        Logger instance
    """
    return logging.getLogger(name or __name__)


# Set up default logger for the module
logger = setup_logger(__name__)