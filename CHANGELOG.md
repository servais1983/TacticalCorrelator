# Changelog

All notable changes to TacticalCorrelator will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Real-time monitoring capabilities
- Advanced visualization components
- Additional EDR integrations (SentinelOne, Cylance)
- Custom rule engine
- API rate limiting and authentication

### Changed
- Improved ML model accuracy
- Enhanced performance for large datasets
- Better error handling and logging

### Fixed
- Memory leaks in long-running analyses
- Neo4j connection stability issues
- Windows path handling in Docker

## [1.0.0] - 2025-05-28

### Added
- **Core Framework**
  - Multi-source forensic artifact correlation
  - Intelligent timeline generation
  - Graph-based relationship analysis
  - Machine learning-powered anomaly detection
  - Priority scoring system

- **Supported Evidence Types**
  - Windows: EVTX, Prefetch, Amcache, JumpLists
  - Network: DNS logs, Proxy logs, Firewall logs
  - EDR: Sysmon, CrowdStrike, Microsoft Sentinel
  - Linux: Syslog, Auth logs, Process artifacts

- **Machine Learning Features**
  - Isolation Forest for anomaly detection
  - Random Forest for priority scoring
  - LSTM for pattern matching
  - DBSCAN clustering for event grouping
  - Custom model training capabilities

- **Graph Database Integration**
  - Neo4j integration for relationship storage
  - Cypher query support
  - Centrality analysis
  - Attack path discovery
  - Graph visualization data export

- **Timeline Analysis**
  - Smart time window generation
  - Contextual anomaly scoring
  - Pattern detection (brute force, lateral movement, etc.)
  - Off-hours activity detection
  - Event clustering and correlation

- **Export Formats**
  - JSON (comprehensive results)
  - STIX 2.1 (threat intelligence)
  - MISP (malware intelligence)
  - YARA rules (detection rules)
  - HTML reports (human-readable)
  - CSV (tabular data)
  - XML (structured data)

- **Command Line Interface**
  - `analyze` command for forensic analysis
  - `export` command for format conversion
  - `serve` command for web interface
  - Comprehensive help and documentation

- **Python API**
  - Async/await support
  - Modular architecture
  - Extensible parser system
  - Configuration management
  - Comprehensive logging

- **Docker Support**
  - Multi-service Docker Compose setup
  - Neo4j integration
  - Volume mounting for evidence
  - Health checks and monitoring

- **Development Tools**
  - Comprehensive test suite
  - CI/CD pipeline (GitHub Actions)
  - Code quality tools (Black, Flake8, MyPy)
  - Security scanning (Bandit, Safety)
  - Documentation generation

- **Examples and Documentation**
  - Basic analysis example
  - Advanced correlation example
  - Comprehensive installation guide
  - Detailed usage documentation
  - API reference
  - Best practices guide

### Technical Details

#### Architecture
- **Modular Design**: Separate components for parsing, correlation, ML, and graph analysis
- **Async Processing**: Full async/await support for concurrent processing
- **Extensible Parsers**: Plugin-based parser system for new evidence types
- **Configuration Management**: YAML-based configuration with environment variable support
- **Error Resilience**: Comprehensive error handling and recovery mechanisms

#### Performance
- **Parallel Processing**: Multi-threaded parsing and analysis
- **Memory Optimization**: Streaming processing for large files
- **Caching**: Model and result caching for improved performance
- **Database Optimization**: Efficient Neo4j queries and indexing

#### Security
- **Input Validation**: Comprehensive input sanitization
- **Safe File Handling**: Protected file operations and path validation
- **Dependency Security**: Regular security scanning of dependencies
- **Audit Logging**: Comprehensive audit trail for all operations

#### Compatibility
- **Python**: 3.8+ support
- **Operating Systems**: Windows, macOS, Linux
- **Neo4j**: 5.0+ compatibility
- **Docker**: Multi-platform container support

### Dependencies

#### Core Dependencies
- pandas>=2.0.0 (data manipulation)
- numpy>=1.21.0 (numerical computing)
- scikit-learn>=1.3.0 (machine learning)
- neo4j>=5.0.0 (graph database)
- python-evtx>=0.8.0 (Windows event log parsing)
- click>=8.0.0 (CLI framework)
- rich>=13.0.0 (CLI formatting)
- fastapi>=0.100.0 (web framework)
- pydantic>=2.0.0 (data validation)

#### Optional Dependencies
- tensorflow>=2.13.0 (deep learning)
- torch>=2.0.0 (PyTorch)
- plotly>=5.15.0 (visualization)
- dash>=2.14.0 (web apps)

### Breaking Changes
- N/A (initial release)

### Migration Guide
- N/A (initial release)

### Contributors
- TacticalCorrelator Team
- Community contributors

### Acknowledgments
- Neo4j team for graph database technology
- scikit-learn contributors for ML algorithms
- Digital forensics community for domain expertise
- Open source security tools that inspired this project

---

## Release Process

### Version Numbering
We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality in a backwards compatible manner
- **PATCH**: Backwards compatible bug fixes

### Release Checklist
- [ ] Update version numbers in `pyproject.toml` and `__init__.py`
- [ ] Update CHANGELOG.md with new features and fixes
- [ ] Run full test suite
- [ ] Update documentation
- [ ] Create GitHub release with artifacts
- [ ] Publish to PyPI
- [ ] Update Docker images

### Support Policy
- **Current version**: Full support with new features and bug fixes
- **Previous major version**: Security fixes and critical bug fixes
- **Older versions**: Community support only

---

For more information about releases, see our [GitHub Releases](https://github.com/servais1983/TacticalCorrelator/releases) page.