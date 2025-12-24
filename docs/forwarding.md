# Gateway Forwarding Boundary (Frozen)

- Route strictly by `protocol`/protocol ID; no payload parsing, persistence, or mutation.
- Logging limited to: protocol_id, direction, byte counts, error codes (enumerated). No payload content.
- No business audit events (directory audit only).
- Forwarding backends are opaque transports (e.g., unix socket, TCP) and must not alter payload semantics.
- Any future protocol additions must keep this boundary intact; forwarding remains transport-only.
