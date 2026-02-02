# RefMD Development Tasks

set dotenv-load

# Default task
default:
    @just --list

# ============ Build & Run ============

# Build all Rust crates
build:
    cargo build

# Build for release
build-release:
    cargo build --release

# Run the backend server
run:
    cargo run -p presentation

# Run the backend server in watch mode
watch:
    cargo watch -x 'run -p presentation'

# Run the frontend dev server
dev-web:
    cd web && pnpm dev

# ============ Testing ============

# Run all tests
test:
    cargo test --workspace

# Run tests with output
test-verbose:
    cargo test --workspace -- --nocapture

# Run integration tests only
test-integration:
    cargo test -p tests

# ============ Code Quality ============

# Run all checks (format, lint, test)
check: fmt-check lint test

# Format all code
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Run clippy
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# ============ Database ============

# Start development services
services-up:
    docker compose up -d

# Stop development services
services-down:
    docker compose down

# Stop and remove all data
services-clean:
    docker compose down -v

# Run database migrations
migrate:
    sqlx migrate run --source crates/infrastructure/migrations

# Create a new migration
migrate-new name:
    sqlx migrate add -r --source crates/infrastructure/migrations {{name}}

# Revert last migration
migrate-revert:
    sqlx migrate revert --source crates/infrastructure/migrations

# ============ Garage (S3) ============

# Initialize Garage cluster layout (run once after first start)
garage-init:
    @echo "Initializing Garage cluster..."
    docker exec refmd-garage /garage status
    @echo "Getting node ID..."
    docker exec refmd-garage /garage node id -q | head -1 > /tmp/garage_node_id
    @echo "Assigning node to zone..."
    docker exec refmd-garage /garage layout assign -z dc1 -c 1G $(cat /tmp/garage_node_id)
    docker exec refmd-garage /garage layout apply --version 1
    @echo "Garage layout initialized!"

# Create Garage access key
garage-key-create:
    docker exec refmd-garage /garage key create refmd-key
    @echo "Add the key ID and secret to .env as S3_ACCESS_KEY and S3_SECRET_KEY"

# Create S3 bucket
garage-bucket-create:
    docker exec refmd-garage /garage bucket create refmd-files
    docker exec refmd-garage /garage bucket allow --read --write refmd-files --key refmd-key
    @echo "Bucket 'refmd-files' created and linked to 'refmd-key'"

# Show Garage status
garage-status:
    docker exec refmd-garage /garage status

# ============ Frontend ============

# Install frontend dependencies
web-install:
    cd web && pnpm install

# Build frontend
web-build:
    cd web && pnpm build

# Lint frontend
web-lint:
    cd web && pnpm lint

# ============ Development Setup ============

# Initial project setup
setup: services-up
    @echo "Waiting for services to be ready..."
    @sleep 5
    just garage-init
    just garage-key-create
    just garage-bucket-create
    just migrate
    just web-install
    @echo "Setup complete!"
    @echo "Don't forget to copy S3_ACCESS_KEY and S3_SECRET_KEY from the output above to your .env file"

# Clean all build artifacts
clean:
    cargo clean
    rm -rf web/node_modules web/.vinxi
