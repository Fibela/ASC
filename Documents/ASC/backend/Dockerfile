FROM python:3.12-slim

# Non-root user — never run production containers as root
RUN groupadd --system --gid 1001 appgroup && \
    useradd --system --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

# System deps: curl required for HEALTHCHECK; libmagic1 for python-magic
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps before copying source (layer caching)
COPY requirements-docker.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source with correct ownership (appuser cannot write to /app as root-owned)
COPY --chown=appuser:appgroup . .

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -sf http://localhost:8000/health || exit 1

CMD ["uvicorn", "asc_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
