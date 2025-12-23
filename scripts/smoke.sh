#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

timeout_secs=${SMOKE_TIMEOUT_SECS:-60}
loggrep() {
  docker compose logs "$@" 2>&1 | grep -E "$2" || true
}

echo "[smoke] building and starting stack..."
docker compose up -d --build

echo "[smoke] waiting for gateways to connect..."
deadline=$((SECONDS + timeout_secs))
connected_ok=false
ping_ok=false

while (( SECONDS < deadline )); do
  gw_logs=$(docker compose logs gw1 gw2 gw3 2>/dev/null || true)
  if echo "$gw_logs" | grep -q "ping response"; then
    ping_ok=true
  fi
  if echo "$gw_logs" | grep -q "ConnectionEstablished"; then
    connected_ok=true
  fi
  if $connected_ok && $ping_ok; then
    echo "[smoke] connectivity verified"
    break
  fi
  sleep 2
done

if ! $connected_ok || ! $ping_ok; then
  echo "[smoke] connectivity check FAILED"
  docker compose logs
  docker compose down -v
  exit 1
fi

echo "[smoke] tearing down..."
docker compose down -v
echo "[smoke] success"
