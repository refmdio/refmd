# -- Builder stage -----------------------------------------------------
FROM rustlang/rust:nightly-bullseye-slim AS build
WORKDIR /build

# Build dependencies once to leverage Docker layer caching
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates binutils curl \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs && cargo build --locked --release --bin api || true

# Actual sources
COPY . ./
ENV SQLX_OFFLINE=true
RUN cargo build --locked --release --bin api --bin refmd \
    && strip target/release/api \
    && strip target/release/refmd

# -- Runtime stage -----------------------------------------------------
FROM debian:bullseye-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        gosu \
        pandoc \
        wkhtmltopdf \
        fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/*

ENV RUST_LOG=api=info,axum=info,tower_http=info \
    API_PORT=8888 \
    UPLOADS_DIR=/data/uploads
WORKDIR /app
COPY --from=build /build/target/release/api /app/api
COPY --from=build /build/target/release/refmd /app/refmd
ENV PATH="/app:${PATH}"

RUN useradd -m -u 10001 appuser \
    && mkdir -p /data/uploads \
    && chown -R appuser:appuser /app /data

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER root

EXPOSE 8888
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:${API_PORT}/api/health | grep -q 'ok' || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/app/api"]
