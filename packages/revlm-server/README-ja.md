# @kedaruma/revlm-server

[English README](README.md)

MongoDB Realm App Services の挙動を再現する自己ホスト型ゲートウェイです。パスワード認証／仮ログインの双方を扱い、MongoDB への CRUD をプロキシします。

## セットアップ

```bash
pnpm install
pnpm run build
pnpm start   # dist/start.js を起動
```

起動前に以下の環境変数（または `.env`）を設定してください。

- `MONGO_URI` / `mongoUri`
- `USERS_DB_NAME` / `usersDbName`
- `USERS_COLLECTION_NAME` / `usersCollectionName`
- `JWT_SECRET` / `jwtSecret`
- `REFRESH_SECRET_SIGNING_KEY` / `refreshSecretSigningKey`（5分TTLのリフレッシュ用シークレットを署名するHMAC鍵）
- 仮ログイン関連 (`provisionalLoginEnabled`, `provisionalAuthId` など)

## スクリプト

- `pnpm run build` – `src` を `dist` へビルドします。
- `pnpm test` – Jest テスト（MongoMemoryServer を使用）を実行します。
- `pnpm run clean` – `dist` とローカル依存を削除します。

## 公開手順

```bash
pnpm run build
pnpm pack
```
