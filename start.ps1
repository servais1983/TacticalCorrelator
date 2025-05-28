# Script de démarrage pour TacticalCorrelator sur Windows
# Usage: .\start.ps1 [dev|prod]

param(
    [string]$Mode = "dev"
)

# Couleurs pour l'affichage
$Host.UI.RawUI.ForegroundColor = "White"

Write-Host "=== TacticalCorrelator - Démarrage ===" -ForegroundColor Green
Write-Host "Mode: $Mode" -ForegroundColor Yellow

# Vérification des prérequis
Write-Host "`nVérification des prérequis..." -ForegroundColor Yellow

# Docker
try {
    $dockerVersion = docker --version
    Write-Host "✓ Docker est installé: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "Docker n'est pas installé!" -ForegroundColor Red
    exit 1
}

# Docker Compose
try {
    $composeVersion = docker-compose --version
    Write-Host "✓ Docker Compose est installé: $composeVersion" -ForegroundColor Green
} catch {
    try {
        $composeVersion = docker compose version
        Write-Host "✓ Docker Compose est installé: $composeVersion" -ForegroundColor Green
    } catch {
        Write-Host "Docker Compose n'est pas installé!" -ForegroundColor Red
        exit 1
    }
}

# Création des répertoires nécessaires
Write-Host "`nCréation des répertoires..." -ForegroundColor Yellow
$directories = @("evidence", "results", "config", "logs")
foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}
Write-Host "✓ Répertoires créés" -ForegroundColor Green

# Arrêt des conteneurs existants
Write-Host "`nArrêt des conteneurs existants..." -ForegroundColor Yellow
docker-compose down --volumes --remove-orphans 2>$null

# Construction et démarrage selon le mode
switch ($Mode) {
    "dev" {
        Write-Host "`nDémarrage en mode développement..." -ForegroundColor Yellow
        docker-compose up --build
    }
    "prod" {
        Write-Host "`nDémarrage en mode production..." -ForegroundColor Yellow
        docker-compose up --build -d
        Write-Host "`nTacticalCorrelator est démarré!" -ForegroundColor Green
        Write-Host "API disponible sur: http://localhost:8000" -ForegroundColor Yellow
        Write-Host "Neo4j disponible sur: http://localhost:7474" -ForegroundColor Yellow
        Write-Host "`nPour voir les logs: docker-compose logs -f" -ForegroundColor Yellow
    }
    default {
        Write-Host "Mode invalide: $Mode" -ForegroundColor Red
        Write-Host "Usage: .\start.ps1 [dev|prod]"
        exit 1
    }
}
