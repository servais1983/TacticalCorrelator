"""
Data utilities for TacticalCorrelator
"""

import hashlib
import json
from datetime import datetime
from typing import Any, Optional

def normalize_timestamp(timestamp: Any) -> Optional[datetime]:
    """Normalize various timestamp formats to datetime object"""
    if isinstance(timestamp, datetime):
        return timestamp
    
    if isinstance(timestamp, str):
        # Common timestamp formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d %H:%M:%S.%f",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%Y-%m-%d",
            "%m/%d/%Y",
            "%d/%m/%Y"
        ]
        
        # Remove timezone indicators
        clean_timestamp = timestamp.replace('Z', '').replace('+00:00', '')
        
        for fmt in formats:
            try:
                return datetime.strptime(clean_timestamp, fmt)
            except ValueError:
                continue
    
    # Try parsing as Unix timestamp
    if isinstance(timestamp, (int, float)):
        try:
            return datetime.fromtimestamp(timestamp)
        except (ValueError, OSError):
            pass
    
    return None

def hash_event(event: dict) -> str:
    """Generate a hash for an event for deduplication"""
    # Create a normalized representation of the event
    normalized_event = {
        'timestamp': str(event.get('timestamp', '')),
        'source': event.get('source', ''),
        'description': event.get('description', ''),
        'hostname': event.get('hostname', ''),
        'username': event.get('username', ''),
        'process_name': event.get('process_name', ''),
        'ip_address': event.get('ip_address', '')
    }
    
    # Convert to JSON string and hash
    event_str = json.dumps(normalized_event, sort_keys=True)
    return hashlib.md5(event_str.encode()).hexdigest()

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for cross-platform compatibility"""
    import re
    
    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(' .')
    
    # Limit length
    if len(sanitized) > 200:
        sanitized = sanitized[:200]
    
    return sanitized or 'unnamed_file'

def format_bytes(bytes_count: int) -> str:
    """Format bytes into human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    import math
    from collections import Counter
    
    if not data:
        return 0.0
    
    # Count character frequencies
    char_counts = Counter(data)
    data_len = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def extract_ip_addresses(text: str) -> list:
    """Extract IP addresses from text"""
    import re
    
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    return ip_pattern.findall(text)

def extract_domains(text: str) -> list:
    """Extract domain names from text"""
    import re
    
    domain_pattern = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b')
    return domain_pattern.findall(text)

def is_private_ip(ip: str) -> bool:
    """Check if IP address is in private range"""
    import ipaddress
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def parse_user_agent(user_agent: str) -> dict:
    """Parse user agent string"""
    import re
    
    # Simple user agent parsing
    result = {
        'browser': 'Unknown',
        'os': 'Unknown',
        'device': 'Unknown'
    }
    
    ua_lower = user_agent.lower()
    
    # Browser detection
    if 'chrome' in ua_lower:
        result['browser'] = 'Chrome'
    elif 'firefox' in ua_lower:
        result['browser'] = 'Firefox'
    elif 'safari' in ua_lower:
        result['browser'] = 'Safari'
    elif 'edge' in ua_lower:
        result['browser'] = 'Edge'
    elif 'opera' in ua_lower:
        result['browser'] = 'Opera'
    
    # OS detection
    if 'windows' in ua_lower:
        result['os'] = 'Windows'
    elif 'mac' in ua_lower or 'darwin' in ua_lower:
        result['os'] = 'macOS'
    elif 'linux' in ua_lower:
        result['os'] = 'Linux'
    elif 'android' in ua_lower:
        result['os'] = 'Android'
    elif 'ios' in ua_lower:
        result['os'] = 'iOS'
    
    # Device detection
    if 'mobile' in ua_lower:
        result['device'] = 'Mobile'
    elif 'tablet' in ua_lower:
        result['device'] = 'Tablet'
    else:
        result['device'] = 'Desktop'
    
    return result