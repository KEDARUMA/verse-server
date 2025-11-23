# @kedaruma/revlm-client

English documentation | [日本語ドキュメントはこちら](README-ja.md)

TypeScript/JavaScript SDK for apps migrating from MongoDB Realm to the self-hosted Revlm server. It exposes helpers to authenticate users, call `/revlm-gate`, and manage collections.

## Installation

```bash
pnpm add @kedaruma/revlm-client
```

The package ships both CJS and ESM bundles plus typings (`types` and `exports` are configured).

## Usage

```ts
import { Revlm } from '@kedaruma/revlm-client';

const revlm = new Revlm({ baseUrl: 'https://your-server.example.com' });
const login = await revlm.login({ authId: 'user', password: 'secret' });
const db = revlm.db('db_name');
const coll = db.collection<any>('collection_name');
const all = await coll.find({});
```

## Scripts

- `pnpm run build` – bundle with `tsup`
- `pnpm test` – run Jest suites (server package must be running in test mode)
- `pnpm run clean` – remove build artifacts and `node_modules`
