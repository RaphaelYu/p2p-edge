# p2p-edge invariants and boundaries

- Scope: edge-bootstrap only serves signed bootstrap manifests. It does not inspect, alter, or proxy any user payloads.
- Isolation: no Forum Core or external platform dependencies are allowed; the service remains a small, auditable edge component.
- Safety: no unsafe Rust; logs are limited to aggregate operational facts (bind address, epoch, TTL, peer count). Never log keys or user-derived data.
- Trust model: clients must verify the Ed25519 signature of the manifest using a trusted verifying key. Manifest content is immutable for its issued epoch/TTL window; rotation is done by changing the signing key or epoch and redeploying.
- Revocation: `revoked_peer_ids` exists to rapidly withdraw untrusted bootstrap peers. Clients should reject manifests where revoked peers appear in active sets.
- Freshness: `issued_at` and `expires_at` bound the manifest lifetime; clients must treat manifests past `expires_at` as invalid even if signatures verify.
