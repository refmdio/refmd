set dotenv-load

default:
    @just --list

# ── Setup ─────────────────────────────────────────

# Initial project setup
setup:
    just api-setup
    just web-setup

# API dependencies and database setup
api-setup:
    mix setup

# Frontend dependencies
web-setup:
    cd assets && vp install

clean:
    just api-clean
    just web-clean

# Remove API dependencies and build outputs
api-clean:
    rm -rf _build deps

# Remove frontend dependencies and untracked static build assets
web-clean:
    rm -rf assets/node_modules
    rm -rf priv/static/assets

# ── Services ──────────────────────────────────────

# Start infra (PostgreSQL + Garage)
services-up:
    docker compose up -d

# Stop services
services-down:
    docker compose down

# Stop services and remove volumes
services-clean:
    docker compose down -v

# ── Development ───────────────────────────────────

# API + Frontend (hot reload)
dev:
    #!/usr/bin/env bash
    set -euo pipefail

    mix phx.server &
    api_pid=$!

    (cd assets && vp dev) &
    web_pid=$!

    cleanup() {
      trap - INT TERM EXIT
      kill "$api_pid" "$web_pid" 2>/dev/null || true
      wait "$api_pid" "$web_pid" 2>/dev/null || true
    }

    trap cleanup INT TERM EXIT
    wait -n "$api_pid" "$web_pid"

# API only
api-dev:
    mix phx.server

# Frontend only
web-dev:
    cd assets && vp dev

# ── Build ─────────────────────────────────────────

# Backend + frontend production build
build:
    just web-build
    just api-build

# API production build
api-build:
    MIX_ENV=prod mix compile --warnings-as-errors

# Frontend production build
web-build:
    cd assets && vp build

# Production-equivalent local run (vite build + Phoenix prod)
preview:
    just web-build
    just api-build
    ERL_FLAGS="${REFMD_PREVIEW_ERL_FLAGS:-+sbwt none +sbwtdcpu none +sbwtdio none}" MIX_ENV=prod mix phx.server

# ── Quality ───────────────────────────────────────

# Full verification (API + frontend)
check:
    just api-check
    just web-check

# API verification
api-check:
    mix compile --force --warnings-as-errors
    MIX_ENV=test mix compile --force --warnings-as-errors
    mix format --check-formatted
    mix credo --strict
    just api-test

# Frontend verification
web-check:
    cd assets && vp check
    cd assets && vp exec tsc -p tsconfig.app.json --noEmit
    just web-test

fmt:
    just api-fmt
    just web-fmt

api-fmt:
    mix format

web-fmt:
    cd assets && vp fmt

fmt-check:
    just api-fmt-check
    just web-fmt-check

api-fmt-check:
    mix format --check-formatted

web-fmt-check:
    cd assets && vp fmt --check

# ── Test ──────────────────────────────────────────

test:
    just api-test
    just web-test

api-test:
    mix test

web-test:
    cd assets && vp test run

test-verbose:
    just api-test-verbose
    just web-test-verbose

api-test-verbose:
    mix test --trace

web-test-verbose:
    cd assets && vp test run --reporter=verbose

test-e2e args="":
    cd assets && vp exec playwright test -c ../test/e2e/playwright.config.ts {{args}}

# ── Database ──────────────────────────────────────

db-migrate:
    mix ecto.migrate

db-new name:
    mix ecto.gen.migration {{name}}

db-rollback:
    mix ecto.rollback

db-reset:
    mix ecto.reset

# ── Generation ────────────────────────────────────

# Add frontend UI components
ui-add +args:
    cd assets && pnpm dlx shadcn@latest add --yes {{args}}

api-gen:
    mix openapi.gen

# Generate OpenAPI types (schema.d.ts)
web-gen:
    just api-gen
    cd assets && vp exec openapi-typescript openapi.json -o src/shared/api/schema.d.ts
