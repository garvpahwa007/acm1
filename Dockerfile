FROM python:3.12-slim

# Unprivileged runtime user. Fixed uid so bind-mounted volumes can be chowned.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin phishguard

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    PHISHGUARD_DATA_DIR=/app/data \
    PHISHGUARD_DB=/app/data/phishguard.db

WORKDIR /app

# Dependencies first: this layer is cached until requirements.txt changes.
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY . .

# The app writes SQLite under /app/data. Declare it a volume so baselines,
# vendor records, clusters and receipts survive `docker rm`.
RUN mkdir -p /app/data && chown -R phishguard:phishguard /app/data /app && \
    chmod +x /app/docker-entrypoint.sh
VOLUME ["/app/data"]

WORKDIR /app/backend

USER phishguard
EXPOSE 8000

# Python-based healthcheck: slim has no curl/wget.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python3 -c "import os,urllib.request,sys; \
p=os.environ.get('PORT','8000'); \
sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/api/health', timeout=4).status==200 else 1)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "8", \
     "--timeout", "60", "--graceful-timeout", "25", "--access-logfile", "-", \
     "--error-logfile", "-", "app:app"]
