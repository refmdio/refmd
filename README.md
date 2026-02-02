# RefMD

End-to-end encrypted collaborative Markdown editor.

## Features

- **E2EE**: Client-side encryption with zero-knowledge design
- **Real-time collaboration**: CRDT-based sync using Yjs
- **Offline support**: Local-first with IndexedDB storage
- **Workspaces**: Organize documents with team collaboration
- **Anonymous sharing**: Password-protected share links without account
- **Git sync**: Bidirectional sync with Git repositories
- **Plugin system**: Extend functionality with custom plugins

## Architecture

### Backend (Rust)

DDD + Clean Architecture with crate-based layer separation:

```
crates/
├── domain/          # Core business logic (no dependencies)
├── application/     # Use cases (→ domain)
├── infrastructure/  # External integrations (→ application, domain)
├── presentation/    # HTTP/WebSocket interface (→ application)
└── tests/           # Integration tests
```

### Frontend (TypeScript)

TanStack Start + Feature-Sliced Design:

```
web/src/
├── routes/      # TanStack Start routing
├── widgets/     # Composite UI blocks
├── features/    # User interactions
├── entities/    # Business entities
└── shared/      # Shared utilities, UI components
```

## Prerequisites

- Rust (latest stable)
- Node.js 20+
- pnpm
- Docker & Docker Compose
- just (task runner)

## Quick Start

```bash
# Clone and setup
cp .env.example .env
just setup

# Run development servers
just run      # Backend (port 3001)
just dev-web  # Frontend (port 3000)
```

## Development Commands

```bash
just              # List all commands
just build        # Build backend
just test         # Run tests
just check        # Format, lint, test
just services-up  # Start PostgreSQL & Garage
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Rust, Axum, SQLx, PostgreSQL |
| Frontend | TanStack Start, React, Tailwind CSS |
| Storage | Garage (S3-compatible) |
| Encryption | XChaCha20-Poly1305 |
| Collaboration | Yjs/Yrs (CRDT) |

## License

MIT
