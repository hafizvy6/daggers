FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    MODE=demo \
    DEMO_MODE=1 \
    RENDER_ENABLED=0 \
    CRT_ENABLED=0 \
    FEEDS_ENABLED=0 \
    ENRICH_ENABLED=0 \
    PORT=8000

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The HF Space CPU image can skip Chromium entirely with INSTALL_RENDER=0.
ARG INSTALL_RENDER=0
RUN if [ "$INSTALL_RENDER" = "1" ]; then \
        pip install --no-cache-dir \
          imagehash==4.3.2 \
          numpy==2.1.3 \
          opencv-python-headless==4.10.0.84 \
          playwright==1.49.1 \
          pytesseract==0.3.13 && \
        python -m playwright install --with-deps chromium; \
    fi

COPY . .
RUN mkdir -p /app/backend/data/evidence /app/backend/data/gallery && \
    python -m backend.seed.seed --seed-only

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/healthz')"

CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
