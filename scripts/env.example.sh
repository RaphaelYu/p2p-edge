#!/usr/bin/env bash
# Default environment for edge-bootstrap (edit values before sourcing)
# Usage: source scripts/env.example.sh

# Binding / server settings
export EDGE_BIND_ADDR="${EDGE_BIND_ADDR:-0.0.0.0:8080}"
export EDGE_CACHE_MAX_AGE_SECS="${EDGE_CACHE_MAX_AGE_SECS:-60}"
export EDGE_MANIFEST_EPOCH="${EDGE_MANIFEST_EPOCH:-1}"
export EDGE_MANIFEST_TTL_SECS="${EDGE_MANIFEST_TTL_SECS:-3600}"

# Registry
export EDGE_REGISTRY_ENABLE="${EDGE_REGISTRY_ENABLE:-true}"
export EDGE_REGISTRY_DB_PATH="${EDGE_REGISTRY_DB_PATH:-registry.db}"
export EDGE_CHALLENGE_TTL_SECS="${EDGE_CHALLENGE_TTL_SECS:-120}"

# Tokens (replace with your real secrets)
export EDGE_OPERATOR_TOKENS_JSON='[{"operator_id":"ops-1","token":"op_secret"}]'
export EDGE_ADMIN_TOKENS_JSON='[{"operator_id":"admin","token":"admin_secret"}]'

# Signing key (replace with your base64-encoded 32-byte Ed25519 private key)
export EDGE_SIGNING_KEY_B64="${EDGE_SIGNING_KEY_B64:-REPLACE_WITH_ED25519_PRIVATE_KEY_B64}"

# Optional helpers for manual enroll flows (set after generating them)
# PUB_B64: base64-encoded 32-byte Ed25519 public key for the peer
# SIG_B64: signature over the latest challenge using the above peer key
PUB_B64=$(openssl pkey -in ed25519.pem -pubout -outform DER | tail -c 32 | base64 -w0)

SIG_B64=$(openssl pkeyutl -sign -inkey ed25519.pem -rawin -in /tmp/challenge.bin | base64 -w0)

# Optional static bootstrap data (used if registry disabled)
export EDGE_BOOTSTRAP_PEERS_JSON='[{"peer_id":"peer1","addrs":["/ip4/127.0.0.1/tcp/4001"],"tags":["bootstrap"],"weight":100}]'
export EDGE_STATIC_BASE_URLS_JSON='[]'
export EDGE_REVOKED_PEER_IDS_JSON='[]'
