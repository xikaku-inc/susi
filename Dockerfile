# Stage 1: Build the Rust binary
FROM rust:1.88-bookworm AS builder

WORKDIR /app

# Copy manifests first to cache dependency builds
COPY Cargo.toml Cargo.lock ./
COPY crates/susi_core/Cargo.toml crates/susi_core/Cargo.toml
COPY crates/susi_client/Cargo.toml crates/susi_client/Cargo.toml
COPY crates/susi_admin/Cargo.toml crates/susi_admin/Cargo.toml
COPY crates/susi_server/Cargo.toml crates/susi_server/Cargo.toml

# Create dummy source files so cargo can resolve the workspace and cache deps
RUN mkdir -p crates/susi_core/src && echo "" > crates/susi_core/src/lib.rs && \
    mkdir -p crates/susi_client/src && echo "" > crates/susi_client/src/lib.rs && \
    mkdir -p crates/susi_admin/src && echo "fn main() {}" > crates/susi_admin/src/main.rs && \
    mkdir -p crates/susi_server/src && echo "fn main() {}" > crates/susi_server/src/main.rs

RUN cargo build --release --package susi_server 2>/dev/null || true

# Copy real source and rebuild
COPY crates/ crates/
RUN touch crates/susi_core/src/lib.rs crates/susi_server/src/main.rs && \
    cargo build --release --package susi_server

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash susi

WORKDIR /home/susi

COPY --from=builder /app/target/release/susi-server /usr/local/bin/susi-server

# Create data directory for DB and keys
RUN mkdir -p /data && chown susi:susi /data

USER susi

EXPOSE 3100

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3100/health || exit 1

ENTRYPOINT ["susi-server"]
CMD ["--private-key", "/data/private.pem", "--db", "/data/licenses.db", "--listen", "0.0.0.0:3100"]
