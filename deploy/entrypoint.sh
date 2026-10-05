#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  TiTaN Panel · container entrypoint
#
#  Fixes the #1 Railway/Docker failure mode: a mounted Volume at /data is owned
#  by root, while the app runs as an unprivileged user. Here we make sure the
#  data directory is writable, then drop privileges and exec the app.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
DATA_DIR_FALLBACK="${DATA_DIR_FALLBACK:-/tmp/titan-data}"
APP_USER="${APP_USER:-titan}"

log() { printf '[entrypoint] %s\n' "$*"; }

ensure_data_dir() {
  mkdir -p "$DATA_DIR" 2>/dev/null || true
  mkdir -p "$DATA_DIR/backups" 2>/dev/null || true

  if [ ! -w "$DATA_DIR" ]; then
    log "data dir $DATA_DIR is not writable — attempting ownership fix"
    chown -R "$APP_USER:$APP_USER" "$DATA_DIR" 2>/dev/null || true
  fi

  if [ ! -w "$DATA_DIR" ]; then
    log "WARNING: $DATA_DIR is still not writable; falling back to $DATA_DIR_FALLBACK"
    DATA_DIR="$DATA_DIR_FALLBACK"
    mkdir -p "$DATA_DIR"
    export DATA_DIR
  fi
}

# Defensive: an empty command would make `exec "$@"` a no-op that exits 0,
# which Railway reports as "Completed" (green) instead of a crash.
if [ "$#" -eq 0 ]; then
  log "no start command received — using the default: python -m app.main"
  set -- python -m app.main
fi

if [ "$(id -u)" = "0" ]; then
  ensure_data_dir
  if command -v gosu >/dev/null 2>&1 && id "$APP_USER" >/dev/null 2>&1; then
    log "starting as user $APP_USER (DATA_DIR=$DATA_DIR, PORT=${PORT:-8000}, EXTRA_PORTS=${EXTRA_PORTS-8080})"
    exec gosu "$APP_USER" "$@"
  fi
  log "gosu unavailable — starting as root (DATA_DIR=$DATA_DIR)"
  exec "$@"
fi

# already unprivileged: make sure the directory exists, then verify writability
mkdir -p "$DATA_DIR" "$DATA_DIR/backups" 2>/dev/null || true
if [ ! -w "$DATA_DIR" ]; then
  log "WARNING: $DATA_DIR is not writable, using $DATA_DIR_FALLBACK"
  export DATA_DIR="$DATA_DIR_FALLBACK"
  mkdir -p "$DATA_DIR"
fi

log "starting as $(id -un) (DATA_DIR=$DATA_DIR, PORT=${PORT:-8000}, EXTRA_PORTS=${EXTRA_PORTS-8080})"
exec "$@"
