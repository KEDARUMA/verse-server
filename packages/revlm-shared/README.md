# @kedaruma/revlm-shared

English documentation | [日本語ドキュメントはこちら](README-ja.md)

Shared TypeScript declarations, BSON helpers, and auth utilities consumed by both the Revlm server and client packages.

## Contents

- `models/` – user and MongoDB document types
- `auth-token` – HKDF + AES-GCM token utilities used for provisional login
- `utils/asserts` – runtime `ensureDefined` and related helpers

## Build

```bash
pnpm install
pnpm run build
```

Running `pnpm run build` compiles `src` to `dist` with `.d.ts` outputs so the other packages can consume them via project references.
