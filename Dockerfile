# ── TiTaN Panel · production image ───────────────────────────────────────────
#  Works on Railway, Fly.io, Render and plain Docker/VPS.
#  Data lives in $DATA_DIR (default /data) — attach a volume there.
#  Listens on $PORT *and* $EXTRA_PORTS (8080) so Railway's "target port"
#  always has a matching listener.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data \
    PORT=8000 \
    EXTRA_PORTS=8080 \
    APP_USER=titan

WORKDIR /app

# tini = correct signal handling (Railway sends SIGTERM on redeploy)
# gosu  = drop root after fixing volume permissions
# curl  = container healthcheck
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates tini gosu \
 && rm -rf /var/lib/apt/lists/*

# dependencies first → better layer caching on rebuilds
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY agent ./agent
COPY scripts ./scripts
COPY static ./static
COPY deploy/entrypoint.sh /usr/local/bin/titan-entrypoint
RUN chmod +x /usr/local/bin/titan-entrypoint

# unprivileged runtime user; /data is chowned again at startup (volume mounts win)
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin titan \
 && mkdir -p /data/backups \
 && chown -R titan:titan /app /data

EXPOSE 8000 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${PORT:-8000}/healthz" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/titan-entrypoint"]
CMD ["python", "-m", "app.main"]
