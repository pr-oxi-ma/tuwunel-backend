#!/bin/bash
set -e

PORT="${PORT:-10000}"
HOST_NAME="${RENDER_EXTERNAL_HOSTNAME:-localhost}"

mkdir -p /var/lib/tuwunel /etc

sed -e "s/{{PORT}}/6167/g" \
    -e "s/{{SERVER_NAME}}/$HOST_NAME/g" \
    /app/tuwunel.toml.template > /etc/tuwunel.toml

echo "[Entrypoint] Starting Tuwunel deployment on host: $HOST_NAME, proxy port: $PORT"

python3 /app/scripts/db_sync.py --restore || echo "[Entrypoint] B2 restore note (continuing)"

python3 /app/scripts/db_sync.py --daemon &
SYNC_PID=$!

/usr/local/bin/tuwunel -c /etc/tuwunel.toml &
TUWUNEL_PID=$!

cleanup() {
    echo "[Entrypoint] Shutdown signal received, running database backup..."
    kill -TERM "$TUWUNEL_PID" 2>/dev/null || true
    kill -TERM "$SYNC_PID" 2>/dev/null || true
    python3 /app/scripts/db_sync.py --backup || true
    exit 0
}
trap cleanup SIGTERM SIGINT

exec python3 /app/backend_server.py
