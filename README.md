# p2p-edge / edge-bootstrap

`edge-bootstrap` serves signed bootstrap manifests for p2p-edge clients. It exposes a minimal HTTP API, signs manifests with Ed25519, and adds cache-friendly headers (ETag/Cache-Control).

## Quick start

1) Generate an Ed25519 private key (base64, 32 bytes):

```bash
openssl genpkey -algorithm ED25519 -out ed25519.pem
openssl pkey -in ed25519.pem -outform DER | tail -c 32 | base64 -w0
```

2) Prepare required environment variables:

```bash
export EDGE_SIGNING_KEY_B64="BASE64_PRIVATE_KEY"
export EDGE_BOOTSTRAP_PEERS_JSON='[{"peer_id":"peer1","addrs":["/ip4/192.0.2.10/tcp/4001"],"tags":["bootstrap"],"weight":100}]'
export EDGE_STATIC_BASE_URLS_JSON='["https://static.example.com/bootstrap"]'
export EDGE_REVOKED_PEER_IDS_JSON='[]'
export EDGE_BIND_ADDR="0.0.0.0:8080"
export EDGE_MANIFEST_EPOCH="1"
export EDGE_MANIFEST_TTL_SECS="3600"
export EDGE_CACHE_MAX_AGE_SECS="60"
```

3) Run the service:

```bash
cargo run -p edge-bootstrap
```

4) Fetch the manifest and reuse it while fresh:

```bash
curl -i http://localhost:8080/bootstrap/manifest
# Verify the signature with the trusted verifying key before using.
```

## API

- `GET /healthz` -> `{ "status":"ok" }`
- `GET /bootstrap/manifest` -> signed manifest v1 + headers `Cache-Control: public, max-age=<secs>` and `ETag`.

Clients should send `If-None-Match` to receive `304 Not Modified` when the manifest is unchanged.

## Security notes

- Always verify the Ed25519 signature of the manifest against the trusted verifying key.
- Honor `expires_at` and `epoch` to detect stale data; rotate keys/epoch to revoke compromised manifests.
- Treat `revoked_peer_ids` as authoritative removals from the bootstrap set.
- Private keys must never be logged or exposed; only operational metadata is logged.
