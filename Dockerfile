FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    APP_ENV=production \
    PORT=8000

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Optional renderer/vision stack. Enable with --build-arg INSTALL_RENDER=1.
ARG INSTALL_RENDER=0
RUN if [ "$INSTALL_RENDER" = "1" ]; then \
        pip install --no-cache-dir \
          imagehash==4.3.2 \
          numpy==2.1.3 \
          opencv-python-headless==5.1.0.95 \
          playwright==1.65.2 \
          pytesseract==0.3.13 && \
        python -m playwright install --with-deps chromium; \
    fi

COPY . .
# Runtime directories are empty by default. No product data is seeded.
RUN mkdir -p /app/backend/data/evidence /app/backend/data/gallery

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/healthz')"

CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
