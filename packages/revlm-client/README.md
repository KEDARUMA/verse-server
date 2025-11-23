# @kedaruma/revlm-client

TypeScript/JavaScript SDK for apps that migrate from MongoDB Realm to the self-hosted Revlm server. It exposes helpers to authenticate users, call `/revlm-gate`, and manage collections.

## Installation

```bash
pnpm add @kedaruma/revlm-client
```

The package ships both CJS and ESM bundles plus typings (`types` and `exports` already configured).

## Usage

```ts
import { Revlm } from '@kedaruma/revlm-client';

const client = new Revlm({ baseUrl: 'https://your-server.example.com' });
const login = await client.login({ authId: 'user', password: 'secret' });
```

## Scripts

- `pnpm run build` – bundle with `tsup`.
- `pnpm test` – run Jest integration suites (requires the server package running in test mode).
- `pnpm run clean` – remove build artifacts and `node_modules`.
