# @kedaruma/revlm-server

Self-hosted HTTP gateway that reproduces the MongoDB Realm App Services experience. It handles user authentication (password + provisional login) and proxied CRUD operations against MongoDB.
MongoDB Realm App Services の挙動を再現するセルフホスト型ゲートウェイで、ユーザー認証と MongoDB への CRUD 中継を担います。
MongoDB Realm App Services をセルフホストで再現する HTTP ゲートウェイで、パスワード/暫定ログイン認証と MongoDB CRUD の仲介を行います。
MongoDB Realm App Services の体験を再現するセルフホスト型の HTTP ゲートウェイで、パスワード/仮ログインの両方を扱う認証と MongoDB への CRUD 代理実行を提供します。
MongoDB Realm App Services の体験を再現するセルフホスト型のHTTPゲートウェイです。ユーザ認証（パスワード／仮ログイン）と MongoDB への CRUD プロキシ処理を提供します。
MongoDB Realm App Services の挙動を再現するセルフホスト型 HTTP ゲートウェイで、パスワード/仮ログイン認証と MongoDB への CRUD プロキシを提供します。

## Getting Started

```bash
pnpm install
pnpm run build
pnpm start   # runs dist/start.js
```

Set the following environment variables or values in a `.env` file before starting:  
起動前に以下の環境変数 (または `.env` の設定) を用意してください。

- `MONGO_URI` / `mongoUri`
- `USERS_DB_NAME` / `usersDbName`
- `USERS_COLLECTION_NAME` / `usersCollectionName`
- `JWT_SECRET` / `jwtSecret`
- Optional provisional auth settings (`provisionalLoginEnabled`, `provisionalAuthId`, etc.)

## Scripts  
スクリプト

- `pnpm run build` – compile `src` to `dist`.
- `pnpm test` – run the Jest suites (uses MongoMemoryServer).
- `pnpm run clean` – remove `dist` and local dependencies.

## Publishing  
公開手順

Build the package and create a tarball before releasing:

```bash
pnpm run build
pnpm pack
```
