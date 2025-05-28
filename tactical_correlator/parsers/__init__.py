"""
Evidence parsers for TacticalCorrelator

Supports multiple forensic artifact formats across different platforms.
"""

from .base_parser import BaseParser
from .windows.evtx_parser import EVTXParser
from .network.dns_parser import DNSParser
from .edr.sysmon_parser import SysmonParser

__all__ = [
    "BaseParser",
    "EVTXParser",
    "DNSParser", 
    "SysmonParser"
]