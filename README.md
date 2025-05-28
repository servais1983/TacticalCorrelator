# TacticalCorrelator 🔍

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/servais1983/TacticalCorrelator/workflows/CI/badge.svg)](https://github.com/servais1983/TacticalCorrelator/actions)
[![Code Coverage](https://codecov.io/gh/servais1983/TacticalCorrelator/branch/main/graph/badge.svg)](https://codecov.io/gh/servais1983/TacticalCorrelator)

**TacticalCorrelator** est un framework de corrélation forensique multi-sources avancé qui utilise le machine learning et les bases de données graphiques pour identifier automatiquement les connexions entre les artefacts numériques.

## 🚀 Fonctionnalités

### Analyse Multi-Sources
- **Windows**: EVTX, Prefetch, Amcache, JumpLists, Registry
- **Linux**: Syslog, Auth logs, Process artifacts
- **Network**: DNS logs, Proxy logs, Firewall logs
- **EDR**: CrowdStrike, Microsoft Sentinel, Sysmon

### Intelligence Artificielle Intégrée
- **Détection d'anomalies**: ML models pour identifier les comportements suspects
- **Scoring de priorité**: Algorithmes de priorisation automatique des événements
- **Pattern matching**: Reconnaissance de motifs d'attaque connus
- **Timeline intelligente**: Corrélation temporelle avec scoring contextuel

### Visualisation et Analyse
- **Graphe de relations**: Neo4j pour visualiser les connexions entre entités
- **Interface web**: Dashboard interactif pour l'analyse
- **Export multi-format**: JSON, CSV, STIX, OpenIOC
- **API REST**: Intégration avec d'autres outils

## 🛠️ Installation

### Installation Rapide
```bash
pip install tactical-correlator
```

### Installation Développeur
```bash
git clone https://github.com/servais1983/TacticalCorrelator.git
cd TacticalCorrelator
pip install -e .
```

### Installation Docker
```bash
docker-compose up -d
```

## 📖 Usage Rapide

### Analyse de Base
```python
from tactical_correlator import TacticalCorrelator

# Initialisation
correlator = TacticalCorrelator()

# Analyse d'un cas
results = correlator.analyze_case(
    case_name="incident_2025",
    evidence_paths={
        "windows": ["./evidence/System.evtx", "./evidence/Security.evtx"],
        "network": ["./evidence/dns.log", "./evidence/proxy.log"],
        "edr": ["./evidence/crowdstrike.json"]
    },
    output_dir="./results/"
)

# Affichage des résultats prioritaires
for event in results.high_priority_events:
    print(f"[{event.timestamp}] {event.description} (Score: {event.priority_score})")
```

### CLI
```bash
# Analyse complète
tactical-correlator analyze --case "incident_2025" --evidence ./evidence/ --output ./results/

# Analyse en temps réel
tactical-correlator monitor --sources "evtx,dns,proxy" --threshold 0.8

# Export des résultats
tactical-correlator export --format stix --output report.json
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data Sources  │    │   Correlation   │    │   Intelligence  │
│                 │    │     Engine      │    │     Layer       │
│ • EVTX         │───▶│                 │───▶│                 │
│ • Prefetch     │    │ • Timeline Gen  │    │ • ML Models     │
│ • DNS Logs     │    │ • Graph Engine  │    │ • Anomaly Det   │
│ • EDR Data     │    │ • Event Corr    │    │ • Priority Scor │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    Parsers      │    │    Neo4j        │    │   Web Interface │
│                 │    │   Graph DB      │    │                 │
│ • Multi-format  │    │                 │    │ • Dashboard     │
│ • Cross-platform│    │ • Relationships │    │ • Visualizations│
│ • Extensible    │    │ • Queries       │    │ • API Endpoints │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🧠 Machine Learning

### Modèles Intégrés
- **Isolation Forest**: Détection d'anomalies non supervisée
- **Random Forest**: Classification des événements
- **LSTM**: Analyse de séquences temporelles
- **Clustering**: Groupement d'événements similaires

### Scoring Intelligent
```python
# Exemple de scoring automatique
event_score = correlator.ml_engine.calculate_priority_score(
    event=suspicious_event,
    context=timeline_context,
    historical_data=past_incidents
)
# Score: 0.94 (Très haute priorité)
```

## 📊 Exemples d'Analyse

### Détection d'Intrusion
```python
# Corrélation automatique d'une intrusion
results = correlator.correlate_events([
    "auth_failure.log",      # Tentatives de brute force
    "network_traffic.pcap",  # Trafic réseau suspect
    "System.evtx"           # Événements système Windows
])

# Résultats automatiques
print(f"Attaque détectée: {results.attack_pattern}")
print(f"Vecteur d'attaque: {results.attack_vector}")
print(f"Confidence: {results.confidence_score}")
```

### Analyse de Malware
```python
# Corrélation d'activité malware
malware_analysis = correlator.analyze_malware_activity(
    process_creation_logs="./sysmon.evtx",
    network_connections="./network.log",
    file_modifications="./file_audit.log"
)

# Timeline d'infection
for event in malware_analysis.infection_timeline:
    print(f"{event.timestamp}: {event.description}")
```

## 🔧 Configuration

### Fichier de Configuration
```yaml
# config.yaml
database:
  neo4j:
    uri: "bolt://localhost:7687"
    username: "neo4j"
    password: "password"

machine_learning:
  models:
    anomaly_detection: "isolation_forest"
    priority_scoring: "random_forest"
    pattern_matching: "lstm"
  
  thresholds:
    anomaly_score: 0.8
    priority_score: 0.7
    confidence_level: 0.9

parsers:
  windows:
    - evtx
    - prefetch
    - amcache
  linux:
    - syslog
    - auth
  network:
    - dns
    - proxy
    - firewall
```

## 🤝 Contribution

1. **Fork** le repository
2. **Créer** une branche feature (`git checkout -b feature/AmazingFeature`)
3. **Commit** vos changements (`git commit -m 'Add some AmazingFeature'`)
4. **Push** vers la branche (`git push origin feature/AmazingFeature`)
5. **Ouvrir** une Pull Request

## 📝 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Examples](docs/USAGE.md)
- [API Reference](docs/API.md)
- [Contributing Guidelines](docs/CONTRIBUTING.md)

## 📄 License

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🙏 Remerciements

- [Neo4j](https://neo4j.com/) pour la base de données graphique
- [scikit-learn](https://scikit-learn.org/) pour les outils ML
- [pandas](https://pandas.pydata.org/) pour la manipulation de données
- La communauté forensique pour les retours et contributions

## 📞 Support

- 🐛 [Issues](https://github.com/servais1983/TacticalCorrelator/issues)
- 💬 [Discussions](https://github.com/servais1983/TacticalCorrelator/discussions)
- 📧 Email: support@tacticalcorrelator.com

---

**Fait avec ❤️ pour la communauté forensique**