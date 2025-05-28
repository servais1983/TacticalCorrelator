"""
API principale pour TacticalCorrelator
"""
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import os
from typing import Dict, Any

from tactical_correlator.core.database import Neo4jDatabase
from tactical_correlator.config.settings import Settings

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Chargement de la configuration
settings = Settings()

# Gestionnaire de cycle de vie de l'application
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestion du cycle de vie de l'application"""
    # Démarrage
    logger.info("Démarrage de TacticalCorrelator API")
    try:
        # Initialisation de la base de données
        app.state.db = Neo4jDatabase(
            uri=settings.neo4j_uri,
            username=settings.neo4j_username,
            password=settings.neo4j_password
        )
        # Test de connexion
        app.state.db.test_connection()
        logger.info("Connexion à Neo4j établie avec succès")
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation: {e}")
        raise
    
    yield
    
    # Arrêt
    logger.info("Arrêt de TacticalCorrelator API")
    if hasattr(app.state, 'db'):
        app.state.db.close()

# Création de l'application FastAPI
app = FastAPI(
    title="TacticalCorrelator API",
    description="API pour l'analyse et la corrélation d'evidence numérique",
    version="1.0.0",
    lifespan=lifespan
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes de base
@app.get("/", response_model=Dict[str, str])
async def root():
    """Route racine"""
    return {
        "message": "Bienvenue sur TacticalCorrelator API",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/health", response_model=Dict[str, Any])
async def health_check():
    """Vérification de l'état de santé de l'API"""
    health_status = {
        "status": "healthy",
        "version": "1.0.0",
        "services": {}
    }
    
    # Vérification Neo4j
    try:
        if hasattr(app.state, 'db'):
            app.state.db.test_connection()
            health_status["services"]["neo4j"] = "connected"
        else:
            health_status["services"]["neo4j"] = "not initialized"
            health_status["status"] = "degraded"
    except Exception as e:
        health_status["services"]["neo4j"] = f"error: {str(e)}"
        health_status["status"] = "unhealthy"
    
    # Retour du statut approprié
    if health_status["status"] == "unhealthy":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=health_status
        )
    
    return health_status

@app.get("/api/v1/status", response_model=Dict[str, Any])
async def get_status():
    """Obtenir le statut détaillé du système"""
    return {
        "status": "operational",
        "components": {
            "api": "operational",
            "database": "operational" if hasattr(app.state, 'db') else "not_initialized",
            "parsers": "operational"
        },
        "version": "1.0.0"
    }

# Import des routes supplémentaires (à ajouter selon vos besoins)
# from tactical_correlator.api.routes import evidence, analysis, reports
# app.include_router(evidence.router, prefix="/api/v1/evidence", tags=["evidence"])
# app.include_router(analysis.router, prefix="/api/v1/analysis", tags=["analysis"])
# app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("API_PORT", "8080"))
    uvicorn.run(
        "tactical_correlator.api.main:app",
        host="0.0.0.0",
        port=port,
        reload=True
    )
