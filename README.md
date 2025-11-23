# Revlm Monorepo

Self-hosted alternative to MongoDB Realm App Services. This monorepo contains:

- `@kedaruma/revlm-server` – Express-based gateway that manages auth and proxies MongoDB actions
- `@kedaruma/revlm-client` – TypeScript SDK that talks to the server from web/mobile apps
- `@kedaruma/revlm-shared` – Shared types and utilities

## Getting Started

```bash
pnpm install
pnpm run build    # tsc at the workspace root
pnpm test
```

## Scripts

- `pnpm clean` – clean all packages then remove root artifacts
- `pnpm run pack:all` – run `pnpm pack` inside every workspace package

See each package’s README for package-specific instructions.
