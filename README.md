# RefMD

RefMD is a real-time Markdown collaboration platform that lets teams co-author documents, publish anonymous share links, sync changes to Git, and extend the workspace through Extism-powered ESM plugins.

[refmd-demo.webm](https://github.com/user-attachments/assets/493ade04-109d-4551-be81-c23c49c23167)

## Key Features
- **Real-time co-editing** with presence indicators and a Monaco-based editor.
- **Anonymous sharing** through one-off links and public publish flows.
- **Git Sync** so documents stay in step with your repositories.
- **Plugin extensibility** powered by the RefMD Plugin SDK, enabling community-built integrations that can be toggled per user.

## Quick Start
1. Pull the latest images and start the stack:
   ```bash
   docker compose up -d
   ```
2. Wait for the health checks to pass (`docker compose ps`) and open `http://localhost:3000` for the web app (`api` is exposed on `http://localhost:8888`).
3. Sign up for a new account (email + password) and start editing. Update `JWT_SECRET` / `ENCRYPTION_KEY` in the compose file or an `.env` file before running in production.

For local development or when you need to rebuild the images, use `docker compose -f docker-compose.dev.yml up --build` instead.

## Documentation
Looking for guides and API docs? Head over to https://refmdio.github.io/docs/ for the full documentation site.

## Tech Stack
- **Backend:** Rust + Axum, SQLx, Tokio, PostgreSQL
- **Frontend:** React (Vite), TanStack Router/Query, Monaco editor, Tailwind CSS
- **Realtime:** Yjs collaborative engine with WebSocket bridge
- **Plugins:** RefMD Plugin SDK atop Extism runtimes with ESM-compatible plugin bundles

## License
Distributed under the GPL-3.0 License. See `LICENSE` for details.
