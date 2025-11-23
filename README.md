# Revlm Monorepo

English documentation | [日本語ドキュメントはこちら](README-ja.md)

Self-hosted alternative to MongoDB Realm App Services. This monorepo contains:

- `@kedaruma/revlm-server` – Express-based gateway that manages authentication and proxies MongoDB actions
- `@kedaruma/revlm-client` – TypeScript SDK for apps migrating from Realm to the Revlm server
- `@kedaruma/revlm-shared` – Shared types, auth helpers, and utilities

## Background

MongoDB Atlas is retiring App Services, so this project provides a drop-in, self-hosted replacement. It exposes:

- MongoDB connectivity (Atlas or self-managed)
- User authentication (password + provisional login)
- Realm-compatible client APIs to smooth migrations

## Getting Started

```bash
pnpm install
pnpm build
pnpm test
```

## Scripts

- `pnpm clean` – run each package’s clean script, then remove root-level `dist` / `node_modules`
- `pnpm install` – restore workspace dependencies
- `pnpm build` – build the entire monorepo
- `pnpm test` – run Jest suites package by package
- `pnpm pack:all` – run `pnpm pack` inside every workspace package to produce `.tgz` artifacts

See each package README for detailed instructions.
