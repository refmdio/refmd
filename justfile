set dotenv-load

default:
    @just --list

# ── Setup ────────────────────────────────────────

# Initial project setup
setup:
    mix setup
    cd assets && vp install

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
    cd assets && vp dev & \
    wait

# API only
dev-api:
    mix ecto.migrate --quiet
    mix phx.server

# Frontend only
dev-web:
    cd assets && vp dev

# ── Test & Quality ───────────────────────────────

test:
    mix test

test-verbose:
    mix test --trace

test-e2e args="":
    cd assets && vp exec playwright test -c ../test/e2e/playwright.config.ts {{args}}

# Full verification (compile + typecheck + lint + test + dialyzer)
check:
    mix compile --warnings-as-errors
    mix format --check-formatted
    cd assets && vp check
    cd assets && vp exec tsc -p tsconfig.app.json --noEmit
    mix specs.check
    mix credo --strict
    mix test
    mix dialyzer --format short

fmt:
    mix format
    cd assets && vp fmt

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
    cd assets && vp install

web-build:
    cd assets && vp build

# Production-equivalent local run (vite build + Phoenix prod)
preview:
    cd assets && vp build
    MIX_ENV=prod mix compile
    MIX_ENV=prod mix phx.server

# Generate OpenAPI types (schema.d.ts)
web-gen:
    mix openapi.gen
    cd assets && vp exec openapi-typescript openapi.json -o src/shared/api/schema.d.ts
