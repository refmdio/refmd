set dotenv-load

default:
    @just --list

# ── Services ─────────────────────────────────────

# Start all infra (postgres, garage, redis, nginx)
services-up:
    docker compose --profile ha up -d

# Stop all services
services-down:
    docker compose --profile ha --profile app down

# Stop all services and remove volumes
services-clean:
    docker compose --profile ha --profile app down -v

# ── Development ──────────────────────────────────

# API + Web (hot reload)
dev:
    @trap 'kill 0' EXIT; \
    cargo watch -x 'run -p server' & \
    cd web && pnpm dev & \
    wait

# API only (hot reload)
dev-api:
    cargo watch -x 'run -p server'

# Web only
dev-web:
    cd web && pnpm dev

# HA: nginx LB (:8000) + 3 API instances (:8001-8003)
dev-ha-api:
    @trap 'kill 0' EXIT; \
    cargo watch -s 'cargo build -p server && (trap "kill 0" EXIT; \
    CLUSTER_ENABLED=true REDIS_URL=redis://localhost:6379 SERVER_PORT=8001 ./target/debug/refmd-server & \
    sleep 1 && CLUSTER_ENABLED=true REDIS_URL=redis://localhost:6379 SERVER_PORT=8002 ./target/debug/refmd-server & \
    sleep 1 && CLUSTER_ENABLED=true REDIS_URL=redis://localhost:6379 SERVER_PORT=8003 ./target/debug/refmd-server & \
    wait)'

# HA + Web
dev-ha:
    @trap 'kill 0' EXIT; \
    just dev-ha-api & \
    sleep 3 && cd web && pnpm dev & \
    wait

# ── Test & Quality ───────────────────────────────

test:
    cargo test --workspace

test-verbose:
    cargo test --workspace -- --nocapture

test-e2e:
    cargo test -p tests

check: fmt-check lint test

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings

arch-check:
    @cargo metadata --format-version 1 --no-deps | python3 scripts/arch_check.py

# ── Database ─────────────────────────────────────

migrate:
    sqlx migrate run --source crates/infrastructure/migrations

migrate-new name:
    sqlx migrate add -r --source crates/infrastructure/migrations {{name}}

migrate-revert:
    sqlx migrate revert --source crates/infrastructure/migrations

db-reset:
    sqlx database drop -y && sqlx database create && sqlx migrate run --source crates/infrastructure/migrations

# ── Web ──────────────────────────────────────────

web-install:
    cd web && pnpm install

web-build:
    cd web && pnpm build

web-lint:
    cd web && pnpm lint

web-gen:
    cd web && pnpm api:generate

# ── Production (container build/run) ─────────────

prod-build *args:
    docker compose --profile app build {{args}}

prod-up *args:
    docker compose --profile app up -d {{args}}

prod-down:
    docker compose --profile app down

prod-logs *args:
    docker compose --profile app logs -f {{args}}

# ── Setup & Misc ─────────────────────────────────

# Initial project setup (run services-up first)
setup:
    @sleep 3
    @docker exec refmd-garage /garage node id -q | head -1 > /tmp/garage_node_id
    docker exec refmd-garage /garage layout assign -z dc1 -c 1G $(cat /tmp/garage_node_id)
    docker exec refmd-garage /garage layout apply --version 1
    docker exec refmd-garage /garage key create refmd-key
    docker exec refmd-garage /garage bucket create refmd-files
    docker exec refmd-garage /garage bucket allow --read --write refmd-files --key refmd-key
    just migrate
    cd web && pnpm install
    @echo "Done. Copy S3_ACCESS_KEY and S3_SECRET_KEY from above to .env"

build:
    cargo build

clean:
    cargo clean
    rm -rf web/node_modules web/.vinxi web/.output
