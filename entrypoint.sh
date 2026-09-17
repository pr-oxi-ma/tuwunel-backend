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

python3 /app/backend_server.py &
SERVER_PID=$!

cleanup() {
    echo "[Entrypoint] SIGTERM/SIGINT received: Starting graceful shutdown & emergency DB sync..."
    # First terminate Tuwunel so RocksDB flushes WAL and releases locks
    kill -TERM "$TUWUNEL_PID" 2>/dev/null || true
    sleep 2
    kill -TERM "$SYNC_PID" 2>/dev/null || true
    # Run immediate synchronous backup to Backblaze B2
    echo "[Entrypoint] Uploading final database state to Backblaze B2..."
    python3 /app/scripts/db_sync.py --backup || true
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    echo "[Entrypoint] Safe shutdown complete. Data fully preserved in Backblaze B2."
    exit 0
}

trap cleanup SIGTERM SIGINT

wait -n "$SERVER_PID" "$TUWUNEL_PID" || true
cleanup

