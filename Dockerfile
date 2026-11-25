# Daggers — integrated production image (API + Police Portal/PWA on one origin).
# Build:   docker build -t daggers .
# Run:     see docker-compose.yml (adds Caddy for HTTPS) and docs/DEPLOYMENT.md
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    APP_ENV=production \
    RENDER_ENABLED=0 \
    CRT_ENABLED=0 \
    FEEDS_ENABLED=0 \
    ENRICH_ENABLED=0 \
    PORT=8000

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Optional renderer/vision stack (Playwright + Chromium); off by default.
ARG INSTALL_RENDER=0
RUN if [ "$INSTALL_RENDER" = "1" ]; then \
        pip install --no-cache-dir imagehash==4.3.2 numpy==2.1.3 opencv-python-headless==5.1.0.95 \
          playwright==1.65.2 pytesseract==0.3.13 && \
        python -m playwright install --with-deps chromium; \
    fi

# Only what the server needs (no tests, extension, ops tooling, docs).
COPY backend/__init__.py ./backend/__init__.py
COPY backend/app ./backend/app
COPY web ./web

# Non-root runtime; the SQLite database, evidence and snapshots live on a volume.
RUN useradd --system --uid 10001 --home /app daggers && \
    mkdir -p /app/backend/data/evidence /app/backend/data/gallery && \
    chown -R daggers:daggers /app/backend/data
USER daggers
VOLUME ["/app/backend/data"]

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/healthz', timeout=4).status == 200 else 1)"

# Live only: the image contains no seed, fixture or sample data.
CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips=${FORWARDED_ALLOW_IPS:-127.0.0.1}"]
