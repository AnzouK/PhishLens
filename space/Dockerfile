# =====================================================================
# PhishLens backend — cloud deployment image (Oracle Cloud / any Docker host).
# =====================================================================
# Differences from the local backend Dockerfile:
#   - listens on $PORT (HF Spaces inject 7860 by default)
#   - runs as a non-root user (HF requirement)
#   - does NOT bundle the DistilBERT checkpoint into the image — it is
#     downloaded from HF Hub on first run (HF_MODEL_REPO).
# =====================================================================

FROM python:3.11-slim

# Required by HF Spaces: run as user 1000, not root.
RUN useradd -m -u 1000 user
USER user
ENV PATH=/home/user/.local/bin:$PATH
WORKDIR /home/user/app

# Caches must be writable by user 1000.
ENV HF_HOME=/home/user/.cache/huggingface \
    PYTHONUNBUFFERED=1 \
    MODEL_DIR=/home/user/app/model

# Install Python dependencies.
COPY --chown=user:user requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Application code — kept identical to the local backend so both paths
# produce the same behaviour. feature_extraction.py + url_agent.py +
# metadata_agent.py are optional at inference (the heuristic fallbacks
# still work when the trained joblibs are absent), but they let the
# runtime load the real Random Forest agents when they are.
COPY --chown=user:user extension_backend.py .
COPY --chown=user:user feature_extraction.py .
COPY --chown=user:user url_agent.py .
COPY --chown=user:user metadata_agent.py .

# HF Spaces sets PORT=7860 by default; honour it.
ENV PORT=7860
EXPOSE 7860

# Use sh -c so the shell can expand $PORT.
CMD ["sh", "-c", "uvicorn extension_backend:app --host 0.0.0.0 --port ${PORT:-7860}"]
