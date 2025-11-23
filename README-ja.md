# Revlm モノレポ概要

[English README](README.md)

このプロジェクトは、MongoDB Atlas が App Services を廃止する流れを受け、セルフホストで代替手段を提供することを目的としています。次の 3 パッケージで構成されます。

- `@kedaruma/revlm-server`：Express ベースのゲートウェイで、ユーザー認証と MongoDB CRUD の仲介を担います。
- `@kedaruma/revlm-client`：Web/モバイルアプリからサーバーへ接続する TypeScript SDK です。
- `@kedaruma/revlm-shared`：サーバー/クライアントが共用する型定義やユーティリティ群です。

## 背景と目的

MongoDB Atlas や自前の MongoDB インスタンスと安全に接続しつつ、Realm SDK を使ったアプリを最小限のコード変更で移行できることを目指しています。パスワード認証・仮ログインの両方に対応し、Realm 互換の API を提供します。

## セットアップ

```bash
pnpm install
pnpm build
pnpm test
```

## 主要スクリプト

- `pnpm clean`：ワークスペース内の各パッケージで `clean` を実行し、最後にルートの `dist` / `node_modules` を削除します。
- `pnpm install`：ルートと各パッケージの依存関係を復元します。
- `pnpm build`：プロジェクト全体の TypeScript ビルドを実行します。
- `pnpm test`：全パッケージの Jest テストを順番に実行します。
- `pnpm pack:all`：ワークスペース内の全パッケージで `pnpm pack` を実行し、`.tgz` を生成します。

詳細手順は各パッケージの README を参照してください。
