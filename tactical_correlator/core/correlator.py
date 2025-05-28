"""
TacticalCorrelator - Main correlation engine

Combines multi-source forensic data parsing, correlation analysis,
and intelligent prioritization using machine learning.
"""

import asyncio
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

import pandas as pd
import numpy as np
from dataclasses import dataclass, field

from ..config.settings import Settings
from ..parsers.base_parser import BaseParser
from ..parsers.windows.evtx_parser import EVTXParser
from ..parsers.network.dns_parser import DNSParser
from ..parsers.edr.sysmon_parser import SysmonParser
from .timeline import TimelineGenerator
from .graph_engine import GraphEngine
from .ml_engine import MLEngine
from ..utils.data_utils import normalize_timestamp, hash_event

@dataclass
class CorrelationResult:
    """Résultat d'une corrélation d'événements"""
    case_name: str
    timestamp: datetime
    high_priority_events: List[Dict] = field(default_factory=list)
    correlations: List[Dict] = field(default_factory=list)
    timeline: Optional[Dict] = None
    graph_data: Optional[Dict] = None
    ml_insights: Optional[Dict] = None
    stats: Dict = field(default_factory=dict)
    attack_patterns: List[str] = field(default_factory=list)
    confidence_score: float = 0.0

class TacticalCorrelator:
    """Moteur principal de corrélation forensique multi-sources"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.settings = Settings(config_path)
        self.logger = logging.getLogger(__name__)
        
        # Initialisation des composants
        self.timeline_generator = TimelineGenerator(self.settings)
        self.graph_engine = GraphEngine(self.settings)
        self.ml_engine = MLEngine(self.settings)
        
        # Parsers disponibles
        self.parsers = {
            'evtx': EVTXParser(self.settings),
            'dns': DNSParser(self.settings),
            'sysmon': SysmonParser(self.settings)
        }
        
        # Cache des données parsées
        self._parsed_cache = {}
        
        self.logger.info("TacticalCorrelator initialized")
    
    async def analyze_case(
        self,
        case_name: str,
        evidence_paths: Dict[str, List[str]],
        output_dir: str,
        generate_timeline: bool = True,
        build_graph: bool = True,
        enable_ml: bool = True,
        anomaly_threshold: float = 0.7
    ) -> CorrelationResult:
        """
        Analyse complète d'un cas forensique
        
        Args:
            case_name: Nom du cas
            evidence_paths: Chemins des artefacts par catégorie
            output_dir: Répertoire de sortie
            generate_timeline: Générer la timeline intelligente
            build_graph: Construire le graphe de relations
            enable_ml: Activer l'analyse ML
            anomaly_threshold: Seuil de détection d'anomalies
            
        Returns:
            Résultats de l'analyse
        """
        start_time = time.time()
        self.logger.info(f"Starting analysis for case: {case_name}")
        
        try:
            # 1. Parsing des artefacts
            parsed_data = await self._parse_evidence(evidence_paths)
            
            # 2. Corrélation des événements
            correlations = await self._correlate_events(parsed_data)
            
            # 3. Génération de timeline (optionnel)
            timeline_data = None
            if generate_timeline:
                timeline_data = await self.timeline_generator.generate_smart_timeline(
                    correlations, anomaly_threshold
                )
            
            # 4. Construction du graphe (optionnel)
            graph_data = None
            if build_graph:
                graph_data = await self.graph_engine.build_relationship_graph(
                    correlations
                )
            
            # 5. Analyse ML (optionnel)
            ml_insights = None
            if enable_ml:
                ml_insights = await self.ml_engine.analyze_and_score(
                    correlations, timeline_data, anomaly_threshold
                )
            
            # 6. Identification des événements prioritaires
            high_priority_events = self._extract_high_priority_events(
                correlations, ml_insights, anomaly_threshold
            )
            
            # 7. Détection de patterns d'attaque
            attack_patterns = self._detect_attack_patterns(correlations)
            
            # 8. Calcul du score de confiance global
            confidence_score = self._calculate_confidence_score(
                correlations, ml_insights
            )
            
            # Statistiques
            stats = {
                'total_events': sum(len(events) for events in parsed_data.values()),
                'correlations': len(correlations),
                'anomalies': len([e for e in high_priority_events 
                               if e.get('priority_score', 0) > anomaly_threshold]),
                'duration': time.time() - start_time,
                'sources_processed': list(evidence_paths.keys())
            }
            
            result = CorrelationResult(
                case_name=case_name,
                timestamp=datetime.now(),
                high_priority_events=high_priority_events,
                correlations=correlations,
                timeline=timeline_data,
                graph_data=graph_data,
                ml_insights=ml_insights,
                stats=stats,
                attack_patterns=attack_patterns,
                confidence_score=confidence_score
            )
            
            # Sauvegarde des résultats
            await self._save_results(result, output_dir)
            
            self.logger.info(
                f"Analysis completed for {case_name}. "
                f"Found {len(correlations)} correlations in {stats['duration']:.2f}s"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error during case analysis: {e}")
            raise
    
    async def _parse_evidence(self, evidence_paths: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
        """Parse tous les artefacts en parallèle"""
        parsed_data = {}
        
        for source_type, file_paths in evidence_paths.items():
            if not file_paths:
                continue
                
            parsed_data[source_type] = []
            
            # Parsing en parallèle pour chaque type de source
            tasks = []
            for file_path in file_paths:
                if source_type in self.parsers:
                    task = self._parse_single_file(
                        self.parsers[source_type], file_path
                    )
                    tasks.append(task)
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        self.logger.warning(f"Parsing error: {result}")
                    elif result:
                        parsed_data[source_type].extend(result)
        
        return parsed_data
    
    async def _parse_single_file(self, parser: BaseParser, file_path: str) -> List[Dict]:
        """Parse un fichier unique"""
        try:
            # Vérification du cache
            cache_key = f"{file_path}_{hash(file_path)}"
            if cache_key in self._parsed_cache:
                return self._parsed_cache[cache_key]
            
            # Parsing asynchrone
            events = await parser.parse_async(file_path)
            
            # Normalisation et enrichissement
            normalized_events = []
            for event in events:
                normalized_event = self._normalize_event(event)
                normalized_events.append(normalized_event)
            
            # Mise en cache
            self._parsed_cache[cache_key] = normalized_events
            
            return normalized_events
            
        except Exception as e:
            self.logger.error(f"Error parsing {file_path}: {e}")
            return []
    
    def _normalize_event(self, event: Dict) -> Dict:
        """Normalise un événement pour la corrélation"""
        normalized = {
            'timestamp': normalize_timestamp(event.get('timestamp')),
            'source': event.get('source', 'unknown'),
            'event_id': event.get('event_id'),
            'description': event.get('description', ''),
            'hostname': event.get('hostname'),
            'username': event.get('username'),
            'process_name': event.get('process_name'),
            'ip_address': event.get('ip_address'),
            'raw_data': event,
            'hash': hash_event(event)
        }
        
        # Suppression des valeurs None
        return {k: v for k, v in normalized.items() if v is not None}
    
    async def _correlate_events(self, parsed_data: Dict[str, List[Dict]]) -> List[Dict]:
        """Corrèle les événements entre sources"""
        correlations = []
        
        # Conversion en DataFrame pour faciliter les corrélations
        all_events = []
        for source_type, events in parsed_data.items():
            for event in events:
                event['source_type'] = source_type
                all_events.append(event)
        
        if not all_events:
            return correlations
        
        df = pd.DataFrame(all_events)
        
        # Corrélation temporelle (événements dans une fenêtre de temps)
        temporal_correlations = self._find_temporal_correlations(df)
        correlations.extend(temporal_correlations)
        
        # Corrélation par entité (même utilisateur, même machine, même IP)
        entity_correlations = self._find_entity_correlations(df)
        correlations.extend(entity_correlations)
        
        # Corrélation par processus
        process_correlations = self._find_process_correlations(df)
        correlations.extend(process_correlations)
        
        return correlations
    
    def _find_temporal_correlations(self, df: pd.DataFrame) -> List[Dict]:
        """Trouve les corrélations temporelles"""
        correlations = []
        
        # Groupement par fenêtre temporelle (5 minutes)
        df['time_window'] = pd.to_datetime(df['timestamp']).dt.floor('5min')
        
        for window, group in df.groupby('time_window'):
            if len(group) > 1:
                # Événements dans la même fenêtre temporelle
                events_list = group.to_dict('records')
                correlation = {
                    'type': 'temporal',
                    'window': str(window),
                    'events': events_list,
                    'count': len(events_list),
                    'correlation_score': min(1.0, len(events_list) / 10.0)
                }
                correlations.append(correlation)
        
        return correlations
    
    def _find_entity_correlations(self, df: pd.DataFrame) -> List[Dict]:
        """Trouve les corrélations par entité"""
        correlations = []
        
        # Corrélation par utilisateur
        for username, group in df.groupby('username'):
            if pd.notna(username) and len(group) > 1:
                correlation = {
                    'type': 'user_activity',
                    'entity': str(username),
                    'events': group.to_dict('records'),
                    'count': len(group),
                    'correlation_score': min(1.0, len(group) / 20.0)
                }
                correlations.append(correlation)
        
        # Corrélation par hostname
        for hostname, group in df.groupby('hostname'):
            if pd.notna(hostname) and len(group) > 1:
                correlation = {
                    'type': 'host_activity',
                    'entity': str(hostname),
                    'events': group.to_dict('records'),
                    'count': len(group),
                    'correlation_score': min(1.0, len(group) / 15.0)
                }
                correlations.append(correlation)
        
        return correlations
    
    def _find_process_correlations(self, df: pd.DataFrame) -> List[Dict]:
        """Trouve les corrélations par processus"""
        correlations = []
        
        for process_name, group in df.groupby('process_name'):
            if pd.notna(process_name) and len(group) > 1:
                correlation = {
                    'type': 'process_activity',
                    'entity': str(process_name),
                    'events': group.to_dict('records'),
                    'count': len(group),
                    'correlation_score': min(1.0, len(group) / 25.0)
                }
                correlations.append(correlation)
        
        return correlations
    
    def _extract_high_priority_events(
        self, 
        correlations: List[Dict], 
        ml_insights: Optional[Dict],
        threshold: float
    ) -> List[Dict]:
        """Extrait les événements haute priorité"""
        high_priority = []
        
        for correlation in correlations:
            # Score basé sur la corrélation
            base_score = correlation.get('correlation_score', 0)
            
            # Boost ML si disponible
            ml_boost = 0
            if ml_insights and 'anomaly_scores' in ml_insights:
                correlation_id = correlation.get('id', str(hash(str(correlation))))
                ml_boost = ml_insights['anomaly_scores'].get(correlation_id, 0)
            
            final_score = min(1.0, base_score + ml_boost * 0.3)
            
            if final_score >= threshold:
                for event in correlation.get('events', []):
                    event_copy = event.copy()
                    event_copy['priority_score'] = final_score
                    event_copy['correlation_type'] = correlation.get('type')
                    high_priority.append(event_copy)
        
        # Tri par score décroissant
        high_priority.sort(key=lambda x: x.get('priority_score', 0), reverse=True)
        
        return high_priority[:100]  # Top 100
    
    def _detect_attack_patterns(self, correlations: List[Dict]) -> List[str]:
        """Détecte des patterns d'attaque connus"""
        patterns = []
        
        # Pattern: Brute force
        auth_failures = [c for c in correlations 
                        if c.get('type') == 'user_activity' and 
                        any('failed' in str(e.get('description', '')).lower() 
                            for e in c.get('events', []))]
        if len(auth_failures) > 3:
            patterns.append('brute_force_attempt')
        
        # Pattern: Lateral movement
        host_correlations = [c for c in correlations if c.get('type') == 'host_activity']
        if len(host_correlations) > 5:
            patterns.append('potential_lateral_movement')
        
        # Pattern: Process injection
        process_correlations = [c for c in correlations 
                              if c.get('type') == 'process_activity']
        if any('inject' in str(c.get('entity', '')).lower() 
               for c in process_correlations):
            patterns.append('process_injection')
        
        return patterns
    
    def _calculate_confidence_score(
        self, 
        correlations: List[Dict], 
        ml_insights: Optional[Dict]
    ) -> float:
        """Calcule un score de confiance global"""
        if not correlations:
            return 0.0
        
        # Score basé sur le nombre de corrélations
        correlation_score = min(1.0, len(correlations) / 50.0)
        
        # Score basé sur la qualité des corrélations
        avg_correlation_score = np.mean([
            c.get('correlation_score', 0) for c in correlations
        ])
        
        # Score ML si disponible
        ml_score = 0
        if ml_insights and 'confidence' in ml_insights:
            ml_score = ml_insights['confidence']
        
        # Score combiné
        final_score = (
            correlation_score * 0.4 + 
            avg_correlation_score * 0.4 + 
            ml_score * 0.2
        )
        
        return min(1.0, final_score)
    
    async def _save_results(self, result: CorrelationResult, output_dir: str):
        """Sauvegarde les résultats"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Sauvegarde JSON principale
        result_dict = {
            'case_name': result.case_name,
            'timestamp': result.timestamp.isoformat(),
            'high_priority_events': result.high_priority_events,
            'correlations': result.correlations,
            'timeline': result.timeline,
            'graph_data': result.graph_data,
            'ml_insights': result.ml_insights,
            'stats': result.stats,
            'attack_patterns': result.attack_patterns,
            'confidence_score': result.confidence_score
        }
        
        import json
        with open(output_path / f"{result.case_name}_analysis.json", 'w') as f:
            json.dump(result_dict, f, indent=2, default=str)
        
        self.logger.info(f"Results saved to {output_path}")