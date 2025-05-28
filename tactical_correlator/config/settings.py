"""
Configuration settings for TacticalCorrelator
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

@dataclass
class DatabaseConfig:
    """Configuration for database connections"""
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_username: str = "neo4j"
    neo4j_password: str = "password"
    connection_timeout: int = 30
    max_retry_attempts: int = 3

@dataclass
class MLConfig:
    """Configuration for machine learning models"""
    anomaly_detection_model: str = "isolation_forest"
    priority_scoring_model: str = "random_forest"
    pattern_matching_model: str = "lstm"
    anomaly_threshold: float = 0.8
    priority_threshold: float = 0.7
    confidence_threshold: float = 0.9
    model_cache_dir: str = "./models/cache"
    enable_model_training: bool = True
    batch_size: int = 1000

@dataclass
class ParserConfig:
    """Configuration for evidence parsers"""
    windows_parsers: list = field(default_factory=lambda: ["evtx", "prefetch", "amcache"])
    linux_parsers: list = field(default_factory=lambda: ["syslog", "auth"])
    network_parsers: list = field(default_factory=lambda: ["dns", "proxy", "firewall"])
    edr_parsers: list = field(default_factory=lambda: ["crowdstrike", "sentinel", "sysmon"])
    max_file_size_mb: int = 500
    parallel_parsing: bool = True
    max_workers: int = 4

@dataclass
class TimelineConfig:
    """Configuration for timeline generation"""
    time_window_minutes: int = 5
    max_events_per_window: int = 1000
    enable_clustering: bool = True
    cluster_threshold: float = 0.6
    generate_heatmap: bool = True

@dataclass
class LoggingConfig:
    """Configuration for logging"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: str = "./logs/tactical_correlator.log"
    max_file_size_mb: int = 10
    backup_count: int = 5
    enable_console: bool = True
    enable_file: bool = True

class Settings:
    """Main settings class for TacticalCorrelator"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.database = DatabaseConfig()
        self.machine_learning = MLConfig()
        self.parsers = ParserConfig()
        self.timeline = TimelineConfig()
        self.logging = LoggingConfig()
        
        # Load configuration from file or environment
        if config_path:
            self.load_from_file(config_path)
        else:
            self.load_from_env()
    
    def load_from_file(self, config_path: str):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            # Update database config
            if 'database' in config_data:
                db_config = config_data['database']
                if 'neo4j' in db_config:
                    neo4j_config = db_config['neo4j']
                    self.database.neo4j_uri = neo4j_config.get('uri', self.database.neo4j_uri)
                    self.database.neo4j_username = neo4j_config.get('username', self.database.neo4j_username)
                    self.database.neo4j_password = neo4j_config.get('password', self.database.neo4j_password)
            
            # Update ML config
            if 'machine_learning' in config_data:
                ml_config = config_data['machine_learning']
                if 'models' in ml_config:
                    models = ml_config['models']
                    self.machine_learning.anomaly_detection_model = models.get(
                        'anomaly_detection', self.machine_learning.anomaly_detection_model
                    )
                    self.machine_learning.priority_scoring_model = models.get(
                        'priority_scoring', self.machine_learning.priority_scoring_model
                    )
                    self.machine_learning.pattern_matching_model = models.get(
                        'pattern_matching', self.machine_learning.pattern_matching_model
                    )
                
                if 'thresholds' in ml_config:
                    thresholds = ml_config['thresholds']
                    self.machine_learning.anomaly_threshold = thresholds.get(
                        'anomaly_score', self.machine_learning.anomaly_threshold
                    )
                    self.machine_learning.priority_threshold = thresholds.get(
                        'priority_score', self.machine_learning.priority_threshold
                    )
                    self.machine_learning.confidence_threshold = thresholds.get(
                        'confidence_level', self.machine_learning.confidence_threshold
                    )
            
            # Update parser config
            if 'parsers' in config_data:
                parser_config = config_data['parsers']
                self.parsers.windows_parsers = parser_config.get('windows', self.parsers.windows_parsers)
                self.parsers.linux_parsers = parser_config.get('linux', self.parsers.linux_parsers)
                self.parsers.network_parsers = parser_config.get('network', self.parsers.network_parsers)
                self.parsers.edr_parsers = parser_config.get('edr', self.parsers.edr_parsers)
            
        except Exception as e:
            print(f"Warning: Could not load config file {config_path}: {e}")
    
    def load_from_env(self):
        """Load configuration from environment variables"""
        # Database
        self.database.neo4j_uri = os.getenv('NEO4J_URI', self.database.neo4j_uri)
        self.database.neo4j_username = os.getenv('NEO4J_USERNAME', self.database.neo4j_username)
        self.database.neo4j_password = os.getenv('NEO4J_PASSWORD', self.database.neo4j_password)
        
        # ML
        self.machine_learning.anomaly_threshold = float(
            os.getenv('ML_ANOMALY_THRESHOLD', self.machine_learning.anomaly_threshold)
        )
        self.machine_learning.priority_threshold = float(
            os.getenv('ML_PRIORITY_THRESHOLD', self.machine_learning.priority_threshold)
        )
        
        # Logging
        self.logging.level = os.getenv('LOG_LEVEL', self.logging.level)
        self.logging.file_path = os.getenv('LOG_FILE_PATH', self.logging.file_path)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary"""
        return {
            'database': self.database.__dict__,
            'machine_learning': self.machine_learning.__dict__,
            'parsers': self.parsers.__dict__,
            'timeline': self.timeline.__dict__,
            'logging': self.logging.__dict__
        }
    
    def save_to_file(self, config_path: str):
        """Save current settings to YAML file"""
        config_data = self.to_dict()
        
        Path(config_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, indent=2)