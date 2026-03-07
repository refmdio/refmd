set dotenv-load

default:
    @just --list

# ── Services ─────────────────────────────────────

# Start infra (PostgreSQL)
services-up:
    docker compose up -d

# Stop services
services-down:
    docker compose down

# Stop services and remove volumes
services-clean:
    docker compose down -v

# ── Development ──────────────────────────────────

# API + Frontend (hot reload)
dev:
    @trap 'kill 0' EXIT; \
    mix phx.server & \
    cd assets && pnpm dev & \
    wait

# API only
dev-api:
    mix phx.server

# Frontend only
dev-web:
    cd assets && pnpm dev

# ── Test & Quality ───────────────────────────────

test:
    mix test

test-verbose:
    mix test --trace

check: fmt-check lint test

fmt:
    mix format
    cd assets && pnpm exec prettier --write src/

fmt-check:
    mix format --check-formatted

lint:
    mix compile --warnings-as-errors

# ── Database ─────────────────────────────────────

migrate:
    mix ecto.migrate

migrate-new name:
    mix ecto.gen.migration {{name}}

migrate-rollback:
    mix ecto.rollback

db-reset:
    mix ecto.reset

# ── Frontend ─────────────────────────────────────

web-install:
    cd assets && pnpm install

web-build:
    cd assets && pnpm build

# ── Setup ────────────────────────────────────────

# Initial project setup
setup:
    mix setup
    cd assets && pnpm install

clean:
    rm -rf _build deps
    rm -rf assets/node_modules
