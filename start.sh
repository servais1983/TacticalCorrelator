#!/bin/bash

# Script de démarrage pour TacticalCorrelator
# Usage: ./start.sh [dev|prod]

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Mode par défaut
MODE=${1:-dev}

echo -e "${GREEN}=== TacticalCorrelator - Démarrage ===${NC}"
echo -e "Mode: ${YELLOW}$MODE${NC}"

# Vérification des prérequis
echo -e "\n${YELLOW}Vérification des prérequis...${NC}"

# Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker n'est pas installé!${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker est installé${NC}"

# Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}Docker Compose n'est pas installé!${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose est installé${NC}"

# Création des répertoires nécessaires
echo -e "\n${YELLOW}Création des répertoires...${NC}"
mkdir -p evidence results config logs
echo -e "${GREEN}✓ Répertoires créés${NC}"

# Arrêt des conteneurs existants
echo -e "\n${YELLOW}Arrêt des conteneurs existants...${NC}"
docker-compose down --volumes --remove-orphans || true

# Construction et démarrage selon le mode
if [ "$MODE" == "dev" ]; then
    echo -e "\n${YELLOW}Démarrage en mode développement...${NC}"
    docker-compose up --build
elif [ "$MODE" == "prod" ]; then
    echo -e "\n${YELLOW}Démarrage en mode production...${NC}"
    docker-compose up --build -d
    echo -e "\n${GREEN}TacticalCorrelator est démarré!${NC}"
    echo -e "API disponible sur: ${YELLOW}http://localhost:8000${NC}"
    echo -e "Neo4j disponible sur: ${YELLOW}http://localhost:7474${NC}"
    echo -e "\nPour voir les logs: ${YELLOW}docker-compose logs -f${NC}"
else
    echo -e "${RED}Mode invalide: $MODE${NC}"
    echo -e "Usage: $0 [dev|prod]"
    exit 1
fi
