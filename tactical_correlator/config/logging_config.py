"""
Logging configuration for TacticalCorrelator
"""

import logging
import logging.handlers
from pathlib import Path
from typing import Optional

def setup_logging(config: Optional[object] = None):
    """Setup logging configuration"""
    
    # Default values
    level = "INFO"
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path = "./logs/tactical_correlator.log"
    max_file_size_mb = 10
    backup_count = 5
    enable_console = True
    enable_file = True
    
    # Use config if provided
    if config:
        level = getattr(config, 'level', level)
        log_format = getattr(config, 'format', log_format)
        file_path = getattr(config, 'file_path', file_path)
        max_file_size_mb = getattr(config, 'max_file_size_mb', max_file_size_mb)
        backup_count = getattr(config, 'backup_count', backup_count)
        enable_console = getattr(config, 'enable_console', enable_console)
        enable_file = getattr(config, 'enable_file', enable_file)
    
    # Clear existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Set logging level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)
    
    # Create formatter
    formatter = logging.Formatter(log_format)
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # File handler with rotation
    if enable_file:
        # Create logs directory if it doesn't exist
        log_path = Path(file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            file_path,
            maxBytes=max_file_size_mb * 1024 * 1024,
            backupCount=backup_count
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Suppress noisy loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('neo4j').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    
    logging.info("Logging configuration initialized")