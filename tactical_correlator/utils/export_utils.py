"""
Export utilities for TacticalCorrelator

Supports multiple output formats including JSON, CSV, STIX, MISP, and YARA.
"""

import json
import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import asdict

from .data_utils import sanitize_filename

class ExportManager:
    """Manager for exporting analysis results to various formats"""
    
    def __init__(self, settings=None):
        self.settings = settings
        self.logger = logging.getLogger(__name__)
        
        # Supported export formats
        self.supported_formats = {
            'json': self._export_json,
            'csv': self._export_csv,
            'stix': self._export_stix,
            'misp': self._export_misp,
            'yara': self._export_yara,
            'html': self._export_html,
            'xml': self._export_xml
        }
    
    def export_results(
        self, 
        results: Dict[str, Any], 
        format_type: str, 
        output_path: Optional[str] = None
    ) -> str:
        """Export results to specified format"""
        
        if format_type not in self.supported_formats:
            raise ValueError(f"Unsupported format: {format_type}. Supported: {list(self.supported_formats.keys())}")
        
        # Generate output filename if not provided
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            case_name = results.get('case_name', 'analysis')
            output_path = f"{sanitize_filename(case_name)}_{timestamp}.{format_type}"
        
        # Ensure output directory exists
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Export using appropriate method
        export_func = self.supported_formats[format_type]
        export_func(results, output_file)
        
        self.logger.info(f"Results exported to {output_path} in {format_type.upper()} format")
        return str(output_path)
    
    def _export_json(self, results: Dict[str, Any], output_path: Path):
        """Export to JSON format"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str, ensure_ascii=False)
    
    def _export_csv(self, results: Dict[str, Any], output_path: Path):
        """Export to CSV format"""
        # Extract high priority events for CSV export
        events = results.get('high_priority_events', [])
        
        if not events:
            # Create empty CSV
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['No events to export'])
            return
        
        # Get all unique keys from events
        all_keys = set()
        for event in events:
            all_keys.update(event.keys())
        
        # Remove complex nested objects
        simple_keys = [key for key in all_keys if not isinstance(events[0].get(key), (dict, list))]
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=simple_keys)
            writer.writeheader()
            
            for event in events:
                # Create simplified row
                row = {key: str(event.get(key, '')) for key in simple_keys}
                writer.writerow(row)
    
    def _export_stix(self, results: Dict[str, Any], output_path: Path):
        """Export to STIX 2.1 format"""
        
        # Create STIX bundle
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{self._generate_uuid()}",
            "objects": []
        }
        
        # Create incident object
        incident = {
            "type": "incident",
            "id": f"incident--{self._generate_uuid()}",
            "created": datetime.now().isoformat() + "Z",
            "modified": datetime.now().isoformat() + "Z",
            "name": results.get('case_name', 'TacticalCorrelator Analysis'),
            "description": f"Forensic analysis results with {len(results.get('high_priority_events', []))} high priority events",
            "labels": ["forensic-analysis"]
        }
        stix_bundle["objects"].append(incident)
        
        # Convert high priority events to indicators
        for event in results.get('high_priority_events', [])[:50]:  # Limit to 50 events
            indicator = self._event_to_stix_indicator(event)
            if indicator:
                stix_bundle["objects"].append(indicator)
        
        # Add attack patterns if detected
        for pattern in results.get('attack_patterns', []):
            attack_pattern = {
                "type": "attack-pattern",
                "id": f"attack-pattern--{self._generate_uuid()}",
                "created": datetime.now().isoformat() + "Z",
                "modified": datetime.now().isoformat() + "Z",
                "name": pattern.replace('_', ' ').title(),
                "description": f"Attack pattern detected: {pattern}"
            }
            stix_bundle["objects"].append(attack_pattern)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(stix_bundle, f, indent=2)
    
    def _export_misp(self, results: Dict[str, Any], output_path: Path):
        """Export to MISP format"""
        
        misp_event = {
            "Event": {
                "id": "1",
                "orgc_id": "1",
                "org_id": "1",
                "date": datetime.now().strftime("%Y-%m-%d"),
                "threat_level_id": "2",
                "info": results.get('case_name', 'TacticalCorrelator Analysis'),
                "published": False,
                "uuid": self._generate_uuid(),
                "analysis": "1",
                "timestamp": str(int(datetime.now().timestamp())),
                "distribution": "1",
                "sharing_group_id": "0",
                "proposal_email_lock": False,
                "locked": False,
                "publish_timestamp": "0",
                "sighting_timestamp": "0",
                "disable_correlation": False,
                "extends_uuid": "",
                "Attribute": []
            }
        }
        
        # Convert events to MISP attributes
        for event in results.get('high_priority_events', [])[:100]:  # Limit to 100
            attributes = self._event_to_misp_attributes(event)
            misp_event["Event"]["Attribute"].extend(attributes)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(misp_event, f, indent=2)
    
    def _export_yara(self, results: Dict[str, Any], output_path: Path):
        """Export to YARA rules format"""
        
        yara_rules = []
        
        # Generate rules based on suspicious processes
        suspicious_processes = set()
        for event in results.get('high_priority_events', []):
            if event.get('process_name'):
                suspicious_processes.add(event['process_name'])
        
        for i, process in enumerate(suspicious_processes, 1):
            rule = f"""
rule SuspiciousProcess_{i}
{{
    meta:
        description = "Detects suspicious process from TacticalCorrelator analysis"
        author = "TacticalCorrelator"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        
    strings:
        $process = "{process}" nocase
        
    condition:
        $process
}}
"""
            yara_rules.append(rule)
        
        # Generate rules based on network indicators
        suspicious_ips = set()
        suspicious_domains = set()
        
        for event in results.get('high_priority_events', []):
            if event.get('ip_address'):
                suspicious_ips.add(event['ip_address'])
            if event.get('domain'):
                suspicious_domains.add(event['domain'])
        
        if suspicious_ips or suspicious_domains:
            network_rule = f"""
rule SuspiciousNetworkActivity
{{
    meta:
        description = "Detects suspicious network activity from TacticalCorrelator analysis"
        author = "TacticalCorrelator"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        
    strings:
"""
            
            for i, ip in enumerate(suspicious_ips, 1):
                network_rule += f'        $ip{i} = "{ip}"\n'
            
            for i, domain in enumerate(suspicious_domains, 1):
                network_rule += f'        $domain{i} = "{domain}" nocase\n'
            
            network_rule += "\n    condition:\n        any of them\n}\n"
            yara_rules.append(network_rule)
        
        # Write all rules
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("// YARA rules generated by TacticalCorrelator\n")
            f.write(f"// Generated on: {datetime.now().isoformat()}\n\n")
            f.write("\n".join(yara_rules))
    
    def _export_html(self, results: Dict[str, Any], output_path: Path):
        """Export to HTML report format"""
        
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>TacticalCorrelator Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .high-priority {{ background-color: #ffe6e6; }}
        .medium-priority {{ background-color: #fff3cd; }}
        .low-priority {{ background-color: #e6f3ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .stats {{ display: flex; justify-content: space-around; }}
        .stat-box {{ text-align: center; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>TacticalCorrelator Analysis Report</h1>
        <p>Case: {results.get('case_name', 'Unknown')}</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Confidence Score: {results.get('confidence_score', 0):.2f}</p>
    </div>
    
    <div class="section">
        <h2>Summary Statistics</h2>
        <div class="stats">
            <div class="stat-box">
                <h3>{results.get('stats', {}).get('total_events', 0)}</h3>
                <p>Total Events</p>
            </div>
            <div class="stat-box">
                <h3>{len(results.get('high_priority_events', []))}</h3>
                <p>High Priority Events</p>
            </div>
            <div class="stat-box">
                <h3>{len(results.get('correlations', []))}</h3>
                <p>Correlations Found</p>
            </div>
            <div class="stat-box">
                <h3>{len(results.get('attack_patterns', []))}</h3>
                <p>Attack Patterns</p>
            </div>
        </div>
    </div>
"""
        
        # Add high priority events
        if results.get('high_priority_events'):
            html_template += """
    <div class="section high-priority">
        <h2>High Priority Events</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Description</th>
                <th>Source</th>
                <th>Priority Score</th>
            </tr>
"""
            
            for event in results['high_priority_events'][:20]:  # Top 20
                html_template += f"""
            <tr>
                <td>{event.get('timestamp', 'Unknown')}</td>
                <td>{event.get('description', 'No description')}</td>
                <td>{event.get('source', 'Unknown')}</td>
                <td>{event.get('priority_score', 0):.2f}</td>
            </tr>
"""
            
            html_template += "        </table>\n    </div>\n"
        
        # Add attack patterns
        if results.get('attack_patterns'):
            html_template += """
    <div class="section">
        <h2>Detected Attack Patterns</h2>
        <ul>
"""
            
            for pattern in results['attack_patterns']:
                html_template += f"            <li>{pattern.replace('_', ' ').title()}</li>\n"
            
            html_template += "        </ul>\n    </div>\n"
        
        html_template += """
</body>
</html>
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_template)
    
    def _export_xml(self, results: Dict[str, Any], output_path: Path):
        """Export to XML format"""
        
        xml_content = f"""
<?xml version="1.0" encoding="UTF-8"?>
<TacticalCorrelatorAnalysis>
    <CaseName>{results.get('case_name', 'Unknown')}</CaseName>
    <Timestamp>{datetime.now().isoformat()}</Timestamp>
    <ConfidenceScore>{results.get('confidence_score', 0):.2f}</ConfidenceScore>
    
    <Statistics>
        <TotalEvents>{results.get('stats', {}).get('total_events', 0)}</TotalEvents>
        <Correlations>{len(results.get('correlations', []))}</Correlations>
        <HighPriorityEvents>{len(results.get('high_priority_events', []))}</HighPriorityEvents>
    </Statistics>
    
    <HighPriorityEvents>
"""
        
        for event in results.get('high_priority_events', [])[:50]:  # Limit to 50
            xml_content += f"""
        <Event>
            <Timestamp>{event.get('timestamp', 'Unknown')}</Timestamp>
            <Description><![CDATA[{event.get('description', 'No description')}]]></Description>
            <Source>{event.get('source', 'Unknown')}</Source>
            <PriorityScore>{event.get('priority_score', 0):.2f}</PriorityScore>
        </Event>
"""
        
        xml_content += """
    </HighPriorityEvents>
    
    <AttackPatterns>
"""
        
        for pattern in results.get('attack_patterns', []):
            xml_content += f"        <Pattern>{pattern}</Pattern>\n"
        
        xml_content += """
    </AttackPatterns>
</TacticalCorrelatorAnalysis>
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(xml_content)
    
    def _event_to_stix_indicator(self, event: Dict) -> Optional[Dict]:
        """Convert event to STIX indicator"""
        
        # Determine indicator type and pattern
        if event.get('ip_address'):
            pattern = f"[ipv4-addr:value = '{event['ip_address']}']"
            labels = ["malicious-activity"]
        elif event.get('domain'):
            pattern = f"[domain-name:value = '{event['domain']}']"
            labels = ["malicious-activity"]
        elif event.get('process_name'):
            pattern = f"[process:name = '{event['process_name']}']"
            labels = ["suspicious-process"]
        else:
            return None
        
        return {
            "type": "indicator",
            "id": f"indicator--{self._generate_uuid()}",
            "created": datetime.now().isoformat() + "Z",
            "modified": datetime.now().isoformat() + "Z",
            "pattern": pattern,
            "labels": labels,
            "description": event.get('description', 'Suspicious activity detected')
        }
    
    def _event_to_misp_attributes(self, event: Dict) -> List[Dict]:
        """Convert event to MISP attributes"""
        attributes = []
        
        if event.get('ip_address'):
            attributes.append({
                "type": "ip-dst",
                "category": "Network activity",
                "value": event['ip_address'],
                "comment": event.get('description', '')
            })
        
        if event.get('domain'):
            attributes.append({
                "type": "domain",
                "category": "Network activity",
                "value": event['domain'],
                "comment": event.get('description', '')
            })
        
        if event.get('process_name'):
            attributes.append({
                "type": "filename",
                "category": "Artifacts dropped",
                "value": event['process_name'],
                "comment": event.get('description', '')
            })
        
        return attributes
    
    def _generate_uuid(self) -> str:
        """Generate UUID for STIX/MISP objects"""
        import uuid
        return str(uuid.uuid4())
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported export formats"""
        return list(self.supported_formats.keys())