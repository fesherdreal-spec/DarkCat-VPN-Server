#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status.
# Treat unset variables as an error.
# Pipes fail if any command in the pipe fails.
set -euo pipefail

# --- Configuration ---
# Allow overriding these with environment variables
HOST="${GUNICORN_HOST:-0.0.0.0}"
PORT="${GUNICORN_PORT:-5000}"
# Calculate workers based on CPU cores, default to 3 if unavailable
CORES=$(nproc --all 2>/dev/null || echo 2)
DEFAULT_WORKERS=$((2 * CORES + 1))
WORKERS="${GUNICORN_WORKERS:-$DEFAULT_WORKERS}"

LOG_LEVEL="${GUNICORN_LOG_LEVEL:-info}"
APP_MODULE="app:app"

# --- Environment File ---
# Load environment variables from .env file if it exists
if [ -f ".env" ]; then
  echo "[INFO] Loading environment variables from .env file..."
  # Use 'export' to make them available to the gunicorn process
  export $(grep -v '^#' .env | xargs)
else
  echo "[WARN] .env file not found. Assuming environment variables are set."
fi

# --- Pre-flight Checks ---
if [ -z "${SECRET_KEY:-}" ]; then
  echo "[FATAL] SECRET_KEY is not set. The application cannot start."
  exit 1
fi

echo "[INFO] Starting Gunicorn..."
echo "[INFO] Host: ${HOST}"
echo "[INFO] Port: ${PORT}"
echo "[INFO] Workers: ${WORKERS}"
echo "[INFO] Log Level: ${LOG_LEVEL}"

# --- Execute Gunicorn ---
# --access-logfile - : Log access logs to stdout
# --error-logfile - : Log error logs to stderr
# This is standard practice for containerized environments.
exec gunicorn \
  --bind "${HOST}:${PORT}" \
  --workers "${WORKERS}" \
  --log-level "${LOG_LEVEL}" \
  --access-logfile '-' \
  --error-logfile '-' \
  "${APP_MODULE}"