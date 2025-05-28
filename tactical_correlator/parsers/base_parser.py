"""
Base parser class for forensic artifacts
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

class BaseParser(ABC):
    """Base class for all forensic artifact parsers"""
    
    def __init__(self, settings):
        self.settings = settings
        self.logger = logging.getLogger(self.__class__.__name__)
        self.supported_extensions = []
        self.parser_name = self.__class__.__name__
    
    @abstractmethod
    async def parse_async(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse a file asynchronously and return events"""
        pass
    
    @abstractmethod
    def parse_sync(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse a file synchronously and return events"""
        pass
    
    def can_parse(self, file_path: str) -> bool:
        """Check if this parser can handle the given file"""
        file_ext = Path(file_path).suffix.lower()
        return file_ext in self.supported_extensions
    
    def validate_file(self, file_path: str) -> bool:
        """Validate that the file exists and is readable"""
        try:
            path = Path(file_path)
            if not path.exists():
                self.logger.error(f"File does not exist: {file_path}")
                return False
            
            if not path.is_file():
                self.logger.error(f"Path is not a file: {file_path}")
                return False
            
            # Check file size
            max_size = self.settings.parsers.max_file_size_mb * 1024 * 1024
            if path.stat().st_size > max_size:
                self.logger.warning(
                    f"File size ({path.stat().st_size} bytes) exceeds maximum "
                    f"({max_size} bytes): {file_path}"
                )
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating file {file_path}: {e}")
            return False
    
    def normalize_timestamp(self, timestamp: Any) -> Optional[datetime]:
        """Normalize various timestamp formats to datetime"""
        if isinstance(timestamp, datetime):
            return timestamp
        
        if isinstance(timestamp, str):
            # Try common timestamp formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S.%f",
                "%m/%d/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M:%S"
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp, fmt)
                except ValueError:
                    continue
        
        self.logger.warning(f"Could not parse timestamp: {timestamp}")
        return None
    
    def create_base_event(self, raw_data: Dict) -> Dict[str, Any]:
        """Create a base event structure"""
        return {
            'timestamp': None,
            'source': self.parser_name,
            'event_id': None,
            'description': '',
            'hostname': None,
            'username': None,
            'process_name': None,
            'process_id': None,
            'ip_address': None,
            'port': None,
            'raw_data': raw_data,
            'parsed_at': datetime.now().isoformat()
        }
    
    async def parse_with_timeout(self, file_path: str, timeout: int = 300) -> List[Dict[str, Any]]:
        """Parse with timeout to prevent hanging"""
        try:
            return await asyncio.wait_for(
                self.parse_async(file_path), 
                timeout=timeout
            )
        except asyncio.TimeoutError:
            self.logger.error(f"Parsing timeout for {file_path}")
            return []
        except Exception as e:
            self.logger.error(f"Error parsing {file_path}: {e}")
            return []