#!/usr/bin/env bash
# Fetch a challenge and print CH_B64 for a given peer_id.
# Usage: scripts/get_challenge.sh <peer_id>
# Requires: jq, EDGE_OPERATOR_TOKEN or default op_secret, server at EDGE_URL (default http://localhost:8080)

set -euo pipefail

PEER_ID="${1:-peer-demo}"
EDGE_URL="${EDGE_URL:-http://localhost:8080}"
OP_TOKEN="${EDGE_OPERATOR_TOKEN:-op_secret}"

resp=$(curl -s -X POST "$EDGE_URL/registry/challenge" \
  -H "Authorization: Bearer $OP_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"peer_id\":\"$PEER_ID\"}")

echo "$resp" | jq -r '.challenge'
