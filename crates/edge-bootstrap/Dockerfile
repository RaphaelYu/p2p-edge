# syntax=docker/dockerfile:1.6

FROM rust:1-bookworm AS builder
WORKDIR /app
# Install build tooling and certificates (needed at build and runtime for TLS fetches).
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates build-essential && \
    rm -rf /var/lib/apt/lists/*

# Cache deps
COPY Cargo.toml Cargo.lock ./
COPY crates/edge-bootstrap/Cargo.toml crates/edge-bootstrap/Cargo.toml
COPY crates/edge-gateway/Cargo.toml crates/edge-gateway/Cargo.toml
RUN mkdir -p crates/edge-bootstrap/src crates/edge-gateway/src && \
    echo "fn main() {}" > crates/edge-bootstrap/src/main.rs && \
    echo "fn main() {}" > crates/edge-gateway/src/main.rs && \
    cargo build -p edge-bootstrap --release || true

# Build
COPY . .
RUN cargo build --release -p edge-bootstrap

FROM debian:bookworm-slim AS runtime
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/edge-bootstrap /app/edge-bootstrap
EXPOSE 8080
ENTRYPOINT ["/app/edge-bootstrap"]
