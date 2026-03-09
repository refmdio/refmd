set dotenv-load

default:
    @just --list

# ── Setup ────────────────────────────────────────

# Initial project setup
setup:
    mix setup
    cd assets && pnpm install

clean:
    rm -rf _build deps
    rm -rf assets/node_modules

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
    mix ecto.migrate --quiet
    @trap 'kill 0' EXIT; \
    mix phx.server & \
    cd assets && pnpm dev & \
    wait

# API only
dev-api:
    mix ecto.migrate --quiet
    mix phx.server

# Frontend only
dev-web:
    cd assets && pnpm dev

# ── Test & Quality ───────────────────────────────

test:
    mix test

test-verbose:
    mix test --trace

# Full verification (compile + typecheck + test)
check:
    mix compile --warnings-as-errors
    cd assets && npx tsc -p tsconfig.app.json --noEmit
    mix test

fmt:
    mix format
    cd assets && pnpm exec prettier --write src/

fmt-check:
    mix format --check-formatted

# ── Database ─────────────────────────────────────

db-migrate:
    mix ecto.migrate

db-new name:
    mix ecto.gen.migration {{name}}

db-rollback:
    mix ecto.rollback

db-reset:
    mix ecto.reset

# ── Frontend ─────────────────────────────────────

web-install:
    cd assets && pnpm install

web-build:
    cd assets && pnpm build

# Generate OpenAPI types (schema.d.ts)
web-gen:
    mix openapi.gen
    cd assets && npx openapi-typescript openapi.json -o src/shared/api/schema.d.ts
