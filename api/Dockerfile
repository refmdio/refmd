# --- Build stage ---
FROM rust:latest AS build
WORKDIR /build

# Cache dependencies
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs && cargo build --release || true

# Build actual app
COPY . ./
# Ensure SQLx never tries to contact a database at build-time (future-proof if macros are introduced)
ENV SQLX_OFFLINE=true
RUN cargo build --release --bin api

# --- Runtime stage ---
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget gosu && rm -rf /var/lib/apt/lists/*
ENV RUST_LOG=api=info,axum=info,tower_http=info
ENV API_PORT=8888
WORKDIR /app
COPY --from=build /build/target/release/api /app/api

# Non-root user
RUN useradd -m -u 10001 appuser && mkdir -p /data/uploads && chown -R appuser:appuser /app /data

# Entrypoint to prepare writable directories before dropping privileges
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER root

# Default directories
ENV UPLOADS_DIR=/data/uploads

EXPOSE 8888
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:${API_PORT}/api/health | grep -q 'ok' || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/app/api"]
