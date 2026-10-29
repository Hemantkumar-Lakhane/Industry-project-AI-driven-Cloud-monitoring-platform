#!/usr/bin/env bash
set -e

export PORT="${PORT:-10000}"
export HOST="${HOST:-0.0.0.0}"
export PYTHONUNBUFFERED=1

echo "[*] Starting AegisCloud Uvicorn on ${HOST}:${PORT}..."
exec uvicorn main:app --host "${HOST}" --port "${PORT}" --log-level info
