# @kedaruma/revlm-client

[English README](README.md)

MongoDB Realm から Revlm サーバーへ移行するアプリ向けの TypeScript/JavaScript SDK です。ユーザー認証や `/revlm-gate` 呼び出し、コレクション操作のヘルパーを提供します。

## インストール

```bash
pnpm add @kedaruma/revlm-client
```

CJS/ESM 両対応のバンドルと型定義が同梱されています。

## 使用例

```ts
import { Revlm } from '@kedaruma/revlm-client';

const revlm = new Revlm({ baseUrl: 'https://your-server.example.com' });
const login = await revlm.login({ authId: 'user', password: 'secret' });
const db = revlm.db('db_name');
const coll = db.collection<any>('collection_name');
const all = await coll.find({});

```

## スクリプト

- `pnpm run build` – `tsup` でビルドします。
- `pnpm test` – Jest の統合テストを実行します（テスト用サーバーが必要）。
- `pnpm run clean` – ビルド成果物と `node_modules` を削除します。
