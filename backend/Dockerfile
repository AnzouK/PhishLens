# =====================================================================
# PhishLens backend — Docker image
# =====================================================================
# Builds a self-contained image that runs `uvicorn extension_backend:app`
# on port 8000. The DistilBERT model is NOT baked in — it is mounted as
# a read-only volume at /app/model (see docker-compose.yml). Keeps the
# image small and lets you swap models without rebuilding.
# =====================================================================

FROM python:3.11-slim AS base

# System dependencies
#   - build-essential: needed by some pip packages with C extensions
#   - curl: used by the HEALTHCHECK
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# App code
COPY extension_backend.py .

# Where the unzipped DistilBERT checkpoint will be mounted
ENV MODEL_DIR=/app/model
ENV PYTHONUNBUFFERED=1
ENV TRANSFORMERS_OFFLINE=1
ENV HF_HUB_OFFLINE=1

EXPOSE 8000

# /healthz is just a GET / on the root endpoint that returns {"status":"ok"}
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -fsS http://localhost:8000/ || exit 1

CMD ["uvicorn", "extension_backend:app", "--host", "0.0.0.0", "--port", "8000"]
