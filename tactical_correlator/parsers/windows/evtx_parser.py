"""
Windows Event Log (EVTX) parser
"""

import asyncio
from typing import List, Dict, Any
from pathlib import Path

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
except ImportError:
    evtx = None
    e_views = None

from ..base_parser import BaseParser

class EVTXParser(BaseParser):
    """Parser for Windows Event Log (EVTX) files"""
    
    def __init__(self, settings):
        super().__init__(settings)
        self.supported_extensions = ['.evtx']
        
        if evtx is None:
            self.logger.warning(
                "python-evtx not installed. EVTX parsing will be limited."
            )
    
    async def parse_async(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse EVTX file asynchronously"""
        if not self.validate_file(file_path):
            return []
        
        # Run parsing in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.parse_sync, file_path)
    
    def parse_sync(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse EVTX file synchronously"""
        events = []
        
        if evtx is None:
            self.logger.error("python-evtx not available for parsing")
            return events
        
        try:
            with evtx.Evtx(file_path) as log:
                for record in log.records():
                    try:
                        event_data = self._parse_record(record)
                        if event_data:
                            events.append(event_data)
                    except Exception as e:
                        self.logger.debug(f"Error parsing record: {e}")
                        continue
            
            self.logger.info(f"Parsed {len(events)} events from {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error parsing EVTX file {file_path}: {e}")
        
        return events
    
    def _parse_record(self, record) -> Dict[str, Any]:
        """Parse individual EVTX record"""
        try:
            # Parse XML data
            xml_data = record.xml()
            
            # Extract basic event information
            event = self.create_base_event({})
            
            # Parse timestamp
            timestamp_node = record.timestamp()
            if timestamp_node:
                event['timestamp'] = timestamp_node
            
            # Parse event ID
            try:
                event_id = record.event_id()
                event['event_id'] = event_id
            except:
                pass
            
            # Parse computer name
            try:
                computer_name = record.computer_name()
                event['hostname'] = computer_name
            except:
                pass
            
            # Extract additional data from XML
            event_data = self._extract_from_xml(xml_data)
            event.update(event_data)
            
            # Store raw XML
            event['raw_data'] = xml_data
            
            return event
            
        except Exception as e:
            self.logger.debug(f"Error parsing EVTX record: {e}")
            return None
    
    def _extract_from_xml(self, xml_data: str) -> Dict[str, Any]:
        """Extract relevant data from EVTX XML"""
        extracted = {}
        
        try:
            import xml.etree.ElementTree as ET
            
            root = ET.fromstring(xml_data)
            
            # Namespace handling
            ns = {'event': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            # Extract system data
            system = root.find('.//event:System', ns)
            if system is not None:
                # Event ID
                event_id_elem = system.find('.//event:EventID', ns)
                if event_id_elem is not None:
                    extracted['event_id'] = event_id_elem.text
                
                # Computer
                computer_elem = system.find('.//event:Computer', ns)
                if computer_elem is not None:
                    extracted['hostname'] = computer_elem.text
                
                # Security data
                security = system.find('.//event:Security', ns)
                if security is not None:
                    user_id = security.get('UserID')
                    if user_id:
                        extracted['user_id'] = user_id
            
            # Extract event data
            event_data = root.find('.//event:EventData', ns)
            if event_data is not None:
                data_items = {}
                for data in event_data.findall('.//event:Data', ns):
                    name = data.get('Name')
                    if name and data.text:
                        data_items[name] = data.text
                
                # Map common fields
                if 'TargetUserName' in data_items:
                    extracted['username'] = data_items['TargetUserName']
                elif 'SubjectUserName' in data_items:
                    extracted['username'] = data_items['SubjectUserName']
                
                if 'ProcessName' in data_items:
                    extracted['process_name'] = data_items['ProcessName']
                elif 'NewProcessName' in data_items:
                    extracted['process_name'] = data_items['NewProcessName']
                
                if 'ProcessId' in data_items:
                    extracted['process_id'] = data_items['ProcessId']
                elif 'NewProcessId' in data_items:
                    extracted['process_id'] = data_items['NewProcessId']
                
                if 'IpAddress' in data_items:
                    extracted['ip_address'] = data_items['IpAddress']
                elif 'ClientAddress' in data_items:
                    extracted['ip_address'] = data_items['ClientAddress']
                
                # Store all event data
                extracted['event_data'] = data_items
            
            # Generate description
            extracted['description'] = self._generate_description(extracted)
            
        except Exception as e:
            self.logger.debug(f"Error extracting XML data: {e}")
        
        return extracted
    
    def _generate_description(self, event_data: Dict) -> str:
        """Generate human-readable description"""
        event_id = event_data.get('event_id', 'Unknown')
        hostname = event_data.get('hostname', 'Unknown')
        username = event_data.get('username', '')
        process_name = event_data.get('process_name', '')
        
        # Common event ID descriptions
        descriptions = {
            '4624': f"Successful logon by {username} on {hostname}",
            '4625': f"Failed logon attempt by {username} on {hostname}",
            '4648': f"Logon using explicit credentials by {username} on {hostname}",
            '4672': f"Special privileges assigned to {username} on {hostname}",
            '4688': f"Process created: {process_name} by {username} on {hostname}",
            '4689': f"Process terminated: {process_name} on {hostname}",
            '4697': f"Service installed on {hostname}",
            '5140': f"Network share accessed on {hostname}",
            '5156': f"Network connection allowed on {hostname}"
        }
        
        if event_id in descriptions:
            return descriptions[event_id]
        else:
            return f"Event {event_id} on {hostname}"