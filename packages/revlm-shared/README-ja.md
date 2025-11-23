# @kedaruma/revlm-shared

[English README](README.md)

revlm-server と revlm-client が共用する TypeScript 型定義、BSON ヘルパー、認証ユーティリティをまとめたパッケージです。

## 内容

- `models/` – ユーザーや MongoDB ドキュメントの型定義
- `auth-token` – 仮ログインで使う HKDF + AES-GCM のトークンユーティリティ
- `utils/asserts` – `ensureDefined` などのランタイムアサーション

## ビルド

```bash
pnpm install
pnpm run build
```

`pnpm run build` を実行すると `src` が `dist` にコンパイルされ、他パッケージが参照できる `.d.ts` が出力されます。
