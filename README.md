# TacticalCorrelator 🔍

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://www.docker.com/)
[![Neo4j](https://img.shields.io/badge/neo4j-5.13-blue.svg)](https://neo4j.com/)

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

### Prérequis
- Docker et Docker Compose
- Git
- 8GB RAM minimum
- 20GB d'espace disque disponible

### Installation Rapide avec Docker (Recommandé)

#### 1. Cloner le repository
```bash
git clone https://github.com/servais1983/TacticalCorrelator.git
cd TacticalCorrelator
```

#### 2. Démarrage automatique

**Sur Windows (PowerShell):**
```powershell
.\start.ps1 prod
```

**Sur Linux/macOS:**
```bash
chmod +x start.sh
./start.sh prod
```

#### 3. Accès aux services
- **API REST**: http://localhost:8000
- **Documentation API**: http://localhost:8000/docs
- **Neo4j Browser**: http://localhost:7474 (login: neo4j / password: tactical123)

### Installation Manuelle avec Docker

```bash
# Créer les répertoires nécessaires
mkdir -p evidence results config logs

# Démarrer les services
docker-compose up -d

# Vérifier le statut
docker-compose ps

# Voir les logs
docker-compose logs -f
```

### Installation pour le Développement

```bash
# Clone et installation
git clone https://github.com/servais1983/TacticalCorrelator.git
cd TacticalCorrelator

# Environnement virtuel Python
python -m venv venv
source venv/bin/activate  # Linux/macOS
# ou
.\venv\Scripts\activate  # Windows

# Installation des dépendances
pip install -r requirements.txt
pip install -e .

# Démarrage en mode développement
./start.sh dev  # Linux/macOS
# ou
.\start.ps1 dev  # Windows
```

## 📖 Usage Rapide

### API REST

#### Test de santé
```bash
curl http://localhost:8000/health
```

#### Statut du système
```bash
curl http://localhost:8000/api/v1/status
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

### Python SDK
```python
from tactical_correlator import TacticalCorrelator

# Initialisation
correlator = TacticalCorrelator(
    neo4j_uri="bolt://localhost:7687",
    neo4j_user="neo4j",
    neo4j_password="tactical123"
)

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
│ • Multi-format  │    │                 │    │ • REST API      │
│ • Cross-platform│    │ • Relationships │    │ • Dashboard     │
│ • Extensible    │    │ • Queries       │    │ • Visualizations│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Stack Technique

- **Backend**: Python 3.11, FastAPI, Uvicorn
- **Base de données**: Neo4j 5.13 Community Edition
- **ML/IA**: scikit-learn, pandas, numpy
- **Parsers**: python-evtx, pyprefetch, et parsers custom
- **API**: REST avec documentation OpenAPI
- **Containerisation**: Docker & Docker Compose

## 📁 Structure du Projet

```
TacticalCorrelator/
├── docker/                 # Fichiers Docker
│   └── Dockerfile         
├── tactical_correlator/    # Code source principal
│   ├── api/               # API REST FastAPI
│   ├── config/            # Configuration
│   ├── core/              # Logique métier
│   ├── parsers/           # Parsers multi-formats
│   └── utils/             # Utilitaires
├── evidence/              # Répertoire des preuves (local)
├── results/               # Résultats d'analyse (local)
├── config/                # Configuration personnalisée
├── logs/                  # Logs d'application
├── docker-compose.yml     # Configuration Docker
├── start.sh              # Script de démarrage Linux/macOS
├── start.ps1             # Script de démarrage Windows
└── requirements.txt       # Dépendances Python
```

## 🔧 Configuration

### Variables d'Environnement

```bash
# Neo4j
NEO4J_URI=bolt://neo4j:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=tactical123

# API
API_HOST=0.0.0.0
API_PORT=8000
API_RELOAD=true

# Paths
EVIDENCE_PATH=/app/evidence
RESULTS_PATH=/app/results
CONFIG_PATH=/app/config
```

### Configuration Personnalisée

Créez un fichier `config/settings.yaml`:

```yaml
database:
  neo4j:
    uri: "bolt://localhost:7687"
    username: "neo4j"
    password: "tactical123"

analysis:
  thresholds:
    anomaly_score: 0.8
    priority_score: 0.7
    confidence_level: 0.9
  
parsers:
  enabled:
    - evtx
    - prefetch
    - dns
    - proxy
```

## 🐳 Commandes Docker Utiles

```bash
# Voir les logs en temps réel
docker-compose logs -f

# Arrêter les services
docker-compose down

# Arrêter et supprimer les volumes
docker-compose down -v

# Reconstruire les images
docker-compose build --no-cache

# Exécuter des commandes dans un conteneur
docker-compose exec tactical-correlator-app bash
docker-compose exec neo4j cypher-shell
```

## 🧪 Tests

```bash
# Tests unitaires
pytest tests/

# Tests avec couverture
pytest --cov=tactical_correlator tests/

# Tests d'intégration
pytest tests/integration/
```

## 🤝 Contribution

1. **Fork** le repository
2. **Créer** une branche feature (`git checkout -b feature/AmazingFeature`)
3. **Commit** vos changements (`git commit -m 'Add some AmazingFeature'`)
4. **Push** vers la branche (`git push origin feature/AmazingFeature`)
5. **Ouvrir** une Pull Request

## 📝 Documentation

- [Guide d'Installation Détaillé](docs/INSTALLATION.md)
- [Exemples d'Usage](docs/USAGE.md)
- [Référence API](docs/API.md)
- [Guide de Contribution](docs/CONTRIBUTING.md)

## 🔍 Dépannage

### Problème de connexion à Neo4j
```bash
# Vérifier que Neo4j est bien démarré
docker-compose ps
docker-compose logs neo4j

# Tester la connexion
docker-compose exec neo4j cypher-shell -u neo4j -p tactical123
```

### Erreur "file not found"
```bash
# S'assurer que tous les répertoires existent
mkdir -p evidence results config logs docker
```

### Problème de permissions (Linux/macOS)
```bash
# Donner les permissions d'exécution
chmod +x start.sh
```

## 📄 License

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🙏 Remerciements

- [Neo4j](https://neo4j.com/) pour la base de données graphique
- [FastAPI](https://fastapi.tiangolo.com/) pour le framework API
- [scikit-learn](https://scikit-learn.org/) pour les outils ML
- La communauté forensique pour les retours et contributions

## 📞 Support

- 🐛 [Issues](https://github.com/servais1983/TacticalCorrelator/issues)
- 💬 [Discussions](https://github.com/servais1983/TacticalCorrelator/discussions)
- 📧 Email: stservais0409@gmail.com

---

**Fait avec ❤️ pour la communauté forensique**
