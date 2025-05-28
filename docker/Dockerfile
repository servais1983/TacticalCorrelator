FROM python:3.11-slim

# Variables d'environnement pour éviter les prompts et optimiser Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Répertoire de travail
WORKDIR /app

# Installation des dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    g++ \
    make \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copie des fichiers de requirements
COPY requirements.txt pyproject.toml ./

# Installation des dépendances Python
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copie du code source
COPY tactical_correlator/ ./tactical_correlator/
COPY setup.py ./

# Installation du package en mode développement
RUN pip install -e .

# Création des répertoires nécessaires
RUN mkdir -p /app/evidence /app/results /app/config /app/logs

# Exposition du port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Commande par défaut
CMD ["python", "-m", "uvicorn", "tactical_correlator.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
