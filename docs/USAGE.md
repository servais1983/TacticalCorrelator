# Usage Guide - TacticalCorrelator

This comprehensive guide shows you how to use TacticalCorrelator for forensic analysis and incident response.

## Table of Contents

- [Quick Start](#quick-start)
- [Command Line Interface](#command-line-interface)
- [Python API](#python-api)
- [Supported Evidence Types](#supported-evidence-types)
- [Analysis Workflow](#analysis-workflow)
- [Output Formats](#output-formats)
- [Advanced Features](#advanced-features)
- [Best Practices](#best-practices)
- [Examples](#examples)

## Quick Start

### 1. Basic Analysis via CLI

```bash
# Analyze a directory of evidence
tactical-correlator analyze \
  --case "incident_2025_001" \
  --evidence ./evidence/ \
  --output ./results/ \
  --timeline \
  --graph \
  --ml

# Monitor real-time (coming soon)
tactical-correlator monitor \
  --sources "evtx,dns,proxy" \
  --threshold 0.8

# Export results to different formats
tactical-correlator export \
  --input ./results/incident_2025_001_analysis.json \
  --format stix \
  --output ./incident_report.json
```

### 2. Basic Analysis via Python

```python
from tactical_correlator import TacticalCorrelator
import asyncio

async def analyze_incident():
    # Initialize correlator
    correlator = TacticalCorrelator()
    
    # Define evidence paths
    evidence_paths = {
        "windows": ["./evidence/System.evtx", "./evidence/Security.evtx"],
        "network": ["./evidence/dns.log", "./evidence/proxy.log"],
        "edr": ["./evidence/sysmon.json"]
    }
    
    # Run analysis
    results = await correlator.analyze_case(
        case_name="incident_2025_001",
        evidence_paths=evidence_paths,
        output_dir="./results/",
        generate_timeline=True,
        build_graph=True,
        enable_ml=True
    )
    
    # Display key findings
    print(f"Confidence Score: {results.confidence_score:.2f}")
    print(f"High Priority Events: {len(results.high_priority_events)}")
    print(f"Attack Patterns: {results.attack_patterns}")
    
    return results

# Run analysis
results = asyncio.run(analyze_incident())
```

## Command Line Interface

### Main Commands

#### analyze
Perform forensic analysis on evidence files.

```bash
tactical-correlator analyze [OPTIONS]

Options:
  -c, --case TEXT          Case name for the analysis [required]
  -e, --evidence PATH      Path to evidence directory [required]
  -o, --output PATH        Output directory for results [required]
  -s, --sources TEXT       Specific sources to analyze (evtx,dns,proxy,etc.)
  -t, --threshold FLOAT    Anomaly detection threshold (0.0-1.0) [default: 0.7]
  --timeline              Generate intelligent timeline
  --graph                 Build relationship graph
  --ml                    Enable ML analysis
  --config PATH           Path to configuration file
  -v, --verbose           Enable verbose output
```

**Examples:**
```bash
# Basic analysis
tactical-correlator analyze -c "case001" -e ./evidence -o ./results

# Analysis with specific sources and ML
tactical-correlator analyze \
  -c "apt_investigation" \
  -e ./apt_evidence \
  -o ./apt_results \
  -s evtx,dns,sysmon \
  --ml --graph --timeline \
  -t 0.6

# Verbose analysis with custom config
tactical-correlator analyze \
  -c "incident_response" \
  -e ./ir_evidence \
  -o ./ir_results \
  --config ./custom_config.yaml \
  --verbose
```

#### export
Export analysis results to various formats.

```bash
tactical-correlator export [OPTIONS]

Options:
  -i, --input PATH         Input results file [required]
  -f, --format CHOICE      Export format [json|csv|stix|misp|yara|html|xml]
  -o, --output PATH        Output file path
```

**Examples:**
```bash
# Export to STIX format
tactical-correlator export \
  -i ./results/case001_analysis.json \
  -f stix \
  -o ./case001_indicators.json

# Export to HTML report
tactical-correlator export \
  -i ./results/case001_analysis.json \
  -f html \
  -o ./case001_report.html

# Export to YARA rules
tactical-correlator export \
  -i ./results/case001_analysis.json \
  -f yara \
  -o ./case001_rules.yar
```

#### serve
Start the web interface.

```bash
tactical-correlator serve [OPTIONS]

Options:
  --host TEXT     Host to bind to [default: localhost]
  --port INTEGER  Port to bind to [default: 8000]
  --dev          Enable development mode
```

## Python API

### Core Classes

#### TacticalCorrelator
Main analysis engine.

```python
from tactical_correlator import TacticalCorrelator

# Initialize with default settings
correlator = TacticalCorrelator()

# Initialize with custom config
correlator = TacticalCorrelator(config_path="./config.yaml")

# Run full analysis
results = await correlator.analyze_case(
    case_name="investigation_001",
    evidence_paths={
        "windows": ["System.evtx", "Security.evtx"],
        "network": ["dns.log"],
        "edr": ["sysmon.json"]
    },
    output_dir="./results",
    generate_timeline=True,
    build_graph=True,
    enable_ml=True,
    anomaly_threshold=0.7
)
```

#### Individual Components

```python
from tactical_correlator import (
    TimelineGenerator,
    GraphEngine,
    MLEngine,
    ExportManager
)

# Use components individually
settings = Settings()
timeline_gen = TimelineGenerator(settings)
graph_engine = GraphEngine(settings)
ml_engine = MLEngine(settings)
export_manager = ExportManager(settings)
```

### Parsers

```python
from tactical_correlator.parsers import (
    EVTXParser,
    DNSParser,
    SysmonParser
)

# Use parsers individually
settings = Settings()
evtx_parser = EVTXParser(settings)
dns_parser = DNSParser(settings)
sysmon_parser = SysmonParser(settings)

# Parse specific files
events = await evtx_parser.parse_async("System.evtx")
dns_events = await dns_parser.parse_async("dns.log")
sysmon_events = await sysmon_parser.parse_async("sysmon.json")
```

## Supported Evidence Types

### Windows Artifacts

| Artifact Type | File Extensions | Description |
|--------------|----------------|-------------|
| **Event Logs (EVTX)** | `.evtx` | Windows Event Log files |
| **Prefetch** | `.pf` | Windows Prefetch files |
| **Amcache** | `Amcache.hve` | Application compatibility cache |
| **Jump Lists** | `.automaticDestinations-ms` | Windows Jump List files |
| **Registry** | `.reg`, `.hive` | Windows Registry files |

### Network Artifacts

| Artifact Type | File Extensions | Description |
|--------------|----------------|-------------|
| **DNS Logs** | `.log`, `.txt` | DNS query logs |
| **Proxy Logs** | `.log`, `.txt` | Web proxy access logs |
| **Firewall Logs** | `.log`, `.txt` | Firewall rule logs |
| **PCAP Files** | `.pcap`, `.pcapng` | Network packet captures |

### EDR/Security Tools

| Tool | File Formats | Description |
|------|-------------|-------------|
| **Sysmon** | `.json`, `.xml` | Windows Sysmon events |
| **CrowdStrike** | `.json` | CrowdStrike Falcon logs |
| **Microsoft Sentinel** | `.json`, `.csv` | Azure Sentinel data |
| **Carbon Black** | `.json` | VMware Carbon Black logs |

### Linux Artifacts

| Artifact Type | File Paths | Description |
|--------------|-----------|-------------|
| **System Logs** | `/var/log/syslog`, `/var/log/messages` | System event logs |
| **Authentication** | `/var/log/auth.log`, `/var/log/secure` | Authentication logs |
| **Process Logs** | `/var/log/audit/audit.log` | Process execution logs |

## Analysis Workflow

### 1. Evidence Collection

```python
# Organize evidence by type
evidence_paths = {
    "windows": [
        "./evidence/System.evtx",
        "./evidence/Security.evtx",
        "./evidence/Application.evtx"
    ],
    "network": [
        "./evidence/dns.log",
        "./evidence/proxy.log",
        "./evidence/firewall.log"
    ],
    "edr": [
        "./evidence/sysmon.json",
        "./evidence/crowdstrike.json"
    ]
}
```

### 2. Parsing and Normalization

```python
# Automatic parsing based on file types
results = await correlator.analyze_case(
    case_name="comprehensive_analysis",
    evidence_paths=evidence_paths,
    output_dir="./results"
)

# Manual parsing for specific files
evtx_parser = EVTXParser(settings)
events = await evtx_parser.parse_async("System.evtx")
```

### 3. Correlation Analysis

```python
# Enable different correlation types
results = await correlator.analyze_case(
    case_name="correlation_analysis",
    evidence_paths=evidence_paths,
    output_dir="./results",
    generate_timeline=True,  # Temporal correlations
    build_graph=True,       # Entity relationships
    enable_ml=True,         # ML-based correlations
    anomaly_threshold=0.7
)

# Access correlation results
for correlation in results.correlations:
    print(f"Type: {correlation['type']}")
    print(f"Score: {correlation['correlation_score']}")
    print(f"Events: {len(correlation['events'])}")
```

### 4. Timeline Analysis

```python
# Generate intelligent timeline
timeline = results.timeline

# Access timeline events
for event in timeline['timeline_events']:
    print(f"[{event['timestamp']}] {event['description']}")
    print(f"  Severity: {event['severity']}")
    print(f"  Anomaly Score: {event['anomaly_score']}")

# Access time windows
for window in timeline['time_windows']:
    print(f"Window: {window['start_time']} - {window['end_time']}")
    print(f"  Activity Score: {window['activity_score']}")
    print(f"  Event Count: {window['event_count']}")
```

### 5. Graph Analysis

```python
# Access graph data
graph_data = results.graph_data

# Examine nodes and relationships
print(f"Nodes: {len(graph_data['nodes'])}")
print(f"Relationships: {len(graph_data['relationships'])}")

# Find most connected entities
centrality = graph_data['centrality']
for entity in centrality['degree_centrality'][:5]:
    print(f"{entity['name']} ({entity['type']}): {entity['degree']} connections")

# Custom graph queries
query = "MATCH (u:Users)-[:ACCESSED]->(h:Hosts) RETURN u.name, h.name"
results_query = await correlator.graph_engine.query_graph(query)
```

### 6. ML Analysis

```python
# Access ML insights
ml_insights = results.ml_insights

print(f"ML Confidence: {ml_insights['confidence']}")
print(f"Patterns Detected: {ml_insights['patterns_detected']}")

# Anomaly scores
for event_id, score in ml_insights['anomaly_scores'].items():
    if score > 0.8:
        print(f"High anomaly: Event {event_id} (Score: {score:.3f})")

# Priority scores
high_priority = {
    k: v for k, v in ml_insights['priority_scores'].items() 
    if v > 0.7
}
print(f"High priority events: {len(high_priority)}")
```

## Output Formats

### JSON (Default)
Comprehensive analysis results in structured JSON format.

```json
{
  "case_name": "incident_2025_001",
  "timestamp": "2025-05-28T18:45:30.123456",
  "confidence_score": 0.85,
  "high_priority_events": [...],
  "correlations": [...],
  "timeline": {...},
  "graph_data": {...},
  "ml_insights": {...},
  "attack_patterns": ["brute_force_attempt", "lateral_movement"]
}
```

### STIX 2.1
Standard format for threat intelligence sharing.

```python
# Export to STIX
export_manager = ExportManager()
stix_path = export_manager.export_results(results, 'stix', './indicators.json')
```

### MISP
Malware Information Sharing Platform format.

```python
# Export to MISP
misp_path = export_manager.export_results(results, 'misp', './misp_event.json')
```

### YARA Rules
Generate YARA rules from suspicious indicators.

```python
# Export to YARA
yara_path = export_manager.export_results(results, 'yara', './rules.yar')
```

### HTML Report
Human-readable analysis report.

```python
# Export to HTML
html_path = export_manager.export_results(results, 'html', './report.html')
```

### CSV
Tabular format for further analysis.

```python
# Export high-priority events to CSV
csv_path = export_manager.export_results(results, 'csv', './events.csv')
```

## Advanced Features

### Custom ML Model Training

```python
# Train custom models with your data
training_data = [
    {
        'correlation_score': 0.9,
        'type': 'malicious_activity',
        'events': [...]
    }
]
labels = [1, 0, 1, 0]  # 1 = malicious, 0 = benign

await correlator.ml_engine.train_models(training_data, labels)
```

### Graph Queries

```python
# Find lateral movement patterns
query = """
MATCH (u:Users)-[:ACCESSED]->(h1:Hosts),
      (u)-[:ACCESSED]->(h2:Hosts)
WHERE h1 <> h2
RETURN u.name, h1.name, h2.name
"""

lateral_movement = await correlator.graph_engine.query_graph(query)

# Find attack paths
attack_paths = await correlator.graph_engine.find_attack_paths(
    'suspicious_user', 'domain_controller'
)
```

### Timeline Pattern Analysis

```python
# Custom timeline analysis
timeline_gen = TimelineGenerator(settings)

# Generate timeline with custom parameters
custom_timeline = await timeline_gen.generate_smart_timeline(
    correlations=results.correlations,
    anomaly_threshold=0.6
)

# Analyze specific patterns
patterns = custom_timeline['patterns']
if 'off_hours_activity' in patterns:
    print("Suspicious off-hours activity detected")
```

### Real-time Analysis (Coming Soon)

```python
# Monitor log sources in real-time
from tactical_correlator.monitors import RealTimeMonitor

monitor = RealTimeMonitor(settings)
await monitor.start_monitoring([
    '/var/log/syslog',
    '/var/log/auth.log'
], callback=handle_alert)
```

## Best Practices

### Evidence Handling

1. **Preserve Original Evidence**
   ```bash
   # Create working copies
   cp -r ./original_evidence ./working_evidence
   
   # Use read-only mounts in Docker
   docker run -v ./evidence:/app/evidence:ro tactical-correlator
   ```

2. **Organize by Source Type**
   ```
   evidence/
   ├── windows/
   │   ├── evtx/
   │   ├── prefetch/
   │   └── registry/
   ├── network/
   │   ├── dns/
   │   ├── proxy/
   │   └── firewall/
   └── edr/
       ├── sysmon/
       └── crowdstrike/
   ```

3. **Document Evidence Chain**
   ```python
   # Include metadata in analysis
   results = await correlator.analyze_case(
       case_name="case_001",
       evidence_paths=evidence_paths,
       metadata={
           'investigator': 'John Doe',
           'acquisition_date': '2025-05-28',
           'case_number': 'IR-2025-001'
       }
   )
   ```

### Performance Optimization

1. **Use Appropriate Thresholds**
   ```python
   # Lower thresholds = more sensitive but more false positives
   # Higher thresholds = less sensitive but fewer false positives
   
   # For initial triage (high sensitivity)
   results = await correlator.analyze_case(
       ..., anomaly_threshold=0.5
   )
   
   # For focused investigation (high precision)
   results = await correlator.analyze_case(
       ..., anomaly_threshold=0.8
   )
   ```

2. **Limit Evidence Size**
   ```python
   # Configure max file sizes
   settings = Settings()
   settings.parsers.max_file_size_mb = 500  # 500MB limit
   
   correlator = TacticalCorrelator(settings)
   ```

3. **Use Parallel Processing**
   ```python
   # Configure worker processes
   settings.parsers.max_workers = 8
   settings.parsers.parallel_parsing = True
   ```

### Analysis Strategy

1. **Start Broad, Then Narrow**
   ```python
   # Phase 1: Broad analysis
   broad_results = await correlator.analyze_case(
       ..., anomaly_threshold=0.6
   )
   
   # Phase 2: Focus on high-priority events
   focused_analysis = analyze_high_priority_events(
       broad_results.high_priority_events
   )
   ```

2. **Combine Multiple Sources**
   ```python
   # Correlate across different evidence types
   evidence_paths = {
       "windows": windows_files,
       "network": network_files,
       "edr": edr_files
   }
   ```

3. **Validate Findings**
   ```python
   # Cross-reference with external intelligence
   for event in results.high_priority_events:
       ip = event.get('ip_address')
       if ip:
           reputation = check_ip_reputation(ip)
           event['reputation'] = reputation
   ```

## Examples

See the [examples/](../examples/) directory for complete examples:

- **[basic_analysis.py](../examples/basic_analysis.py)**: Simple analysis workflow
- **[advanced_correlation.py](../examples/advanced_correlation.py)**: Advanced features demonstration
- **Custom parsers**: Extending TacticalCorrelator for new evidence types
- **Integration examples**: Using TacticalCorrelator with other tools

## Troubleshooting

### Common Issues

1. **Memory Issues with Large Files**
   ```python
   # Process files in chunks
   settings.parsers.batch_size = 1000
   ```

2. **Neo4j Connection Problems**
   ```bash
   # Check Neo4j status
   docker ps | grep neo4j
   
   # Test connection
   curl http://localhost:7474
   ```

3. **Parser Errors**
   ```python
   # Enable debug logging
   settings.logging.level = "DEBUG"
   
   # Check parser compatibility
   parser = EVTXParser(settings)
   can_parse = parser.can_parse("suspicious_file.evtx")
   ```

### Getting Help

- Check the [API documentation](API.md)
- Review [installation issues](INSTALLATION.md#troubleshooting)
- Search [GitHub issues](https://github.com/servais1983/TacticalCorrelator/issues)
- Join [community discussions](https://github.com/servais1983/TacticalCorrelator/discussions)

---

**Next:** [API Reference](API.md) | **Previous:** [Installation](INSTALLATION.md)