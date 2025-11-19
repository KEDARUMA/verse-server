// Jest test file for testing token verification and refresh functionality
// - Test /verify-token endpoint with valid, expired, and malformed tokens
// - Test /refresh-token endpoint with various token states
// - Verify token expiration and refresh window behavior
// JWTトークンの検証とリフレッシュ機能をテストする Jest テストファイル
// - 有効・期限切れ・不正なトークンで /verify-token エンドポイントをテスト
// - 様々なトークン状態で /refresh-token エンドポイントをテスト
// - トークンの有効期限とリフレッシュウィンドウの動作を検証

import request from 'supertest';
const jwt = require('jsonwebtoken');
import dotenv from 'dotenv';
import { SetupTestEnvironmentResult, setupTestEnvironment, cleanupTestEnvironment } from './setupTestMongo';
import { ensureDefined } from '@kedaruma/revlm-shared/utils/asserts';
import path from 'path';

// Load environment variables (refer to .env) so that the necessary settings for the test are stored in process.env.
// 環境変数を読み込む（.env を参照）テスト内で必要な設定が process.env に入る。
dotenv.config({ path: path.join(__dirname, 'test.env') });

// Extend Jest hook timeout to allow mongodb-memory-server to download/start
// Jest フックのタイムアウトを延長して mongodb-memory-server のダウンロード/起動を許可する
jest.setTimeout(120000);

const JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
const REFRESH_WINDOW_SEC = Number(process.env.REFRESH_WINDOW_SEC ?? '300');

let testEnv: SetupTestEnvironmentResult;
let SERVER_URL: string;

beforeAll(async () => {
  console.log('beforeAll: start');

  // Setup test environment (MongoDB + Server) using the utility function
  // ユーティリティ関数を使用してテスト環境（MongoDB + サーバー）をセットアップ
  testEnv = await setupTestEnvironment({
    serverConfig: {
      mongoUri: process.env.MONGO_URI as string,
      usersDbName: ensureDefined(process.env.USERS_DB_NAME || 'testdb', 'USERS_DB_NAME is required'),
      usersCollectionName: ensureDefined(process.env.USERS_COLLECTION_NAME || 'users', 'USERS_COLLECTION_NAME is required'),
      jwtSecret: JWT_SECRET,
      provisionalLoginEnabled: false,
      port: Number(process.env.PORT),
    }
  });

  SERVER_URL = testEnv.serverUrl;
  console.log('beforeAll: server started at', SERVER_URL);
  console.log('beforeAll: end');
});

afterAll(async () => {
  console.log('afterAll: start');

  // Clean up test environment (stop server and MongoDB) using the utility function
  // ユーティリティ関数を使用してテスト環境をクリーンアップ（サーバーと MongoDB を停止）
  await cleanupTestEnvironment(testEnv);

  console.log('afterAll: done');
});

describe('/verify-token', () => {
  // 有効なトークンに対してペイロードを返す
  it('returns payload for valid token', async () => {
    const token = jwt.sign({ foo: 'bar' }, JWT_SECRET, { expiresIn: '1h' });
    const res = await request(SERVER_URL).post('/verify-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.payload).toBeDefined();
    expect(res.body.payload.foo).toBe('bar');
  });

  // 期限切れトークンに対して token_expired を返す
  it('returns token_expired for expired token', async () => {
    const payload = { foo: 'baz', exp: Math.floor(Date.now() / 1000) - 10 };
    const token = jwt.sign(payload as any, JWT_SECRET);
    const res = await request(SERVER_URL).post('/verify-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
    expect(res.body.ok).toBe(false);
    expect(res.body.reason).toBe('token_expired');
  });

  // 不正なトークンに対して invalid_token を返す
  it('returns invalid_token for malformed token', async () => {
    const res = await request(SERVER_URL).post('/verify-token').set('Authorization', `Bearer invalid.token.here`);
    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.reason).toBe('invalid_token');
  });
});

describe('/refresh-token', () => {
  // リフレッシュウィンドウ内の期限切れ非仮認証トークンを更新する
  it('refreshes an expired non-provisional token within window', async () => {
    const payload = { userId: 'u1', roles: ['a'], exp: Math.floor(Date.now() / 1000) - 10 };
    const token = jwt.sign(payload as any, JWT_SECRET);
    const res = await request(SERVER_URL).post('/refresh-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.token).toBeDefined();
    // new token should be valid
    const verify = await request(SERVER_URL).post('/verify-token').set('Authorization', `Bearer ${res.body.token}`);
    expect(verify.status).toBe(200);
    expect(verify.body.ok).toBe(true);
  });

  // トークンが期限切れでない場合はリフレッシュを拒否する
  it('rejects refresh when token is not expired', async () => {
    const token = jwt.sign({ foo: 'x' }, JWT_SECRET, { expiresIn: '1h' });
    const res = await request(SERVER_URL).post('/refresh-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
    expect(res.body.reason).toBe('not_expired');
  });

  // 期限切れでも仮認証トークンはリフレッシュを拒否する
  it('rejects provisional tokens even if expired', async () => {
    const payload = { userType: 'provisional', exp: Math.floor(Date.now() / 1000) - 10 };
    const token = jwt.sign(payload as any, JWT_SECRET);
    const res = await request(SERVER_URL).post('/refresh-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.reason).toBe('provisional_forbidden');
  });

  // 猶予期間を超えたリフレッシュを拒否する
  it('rejects refresh beyond grace window', async () => {
    const old = Math.floor(Date.now() / 1000) - (REFRESH_WINDOW_SEC + 10);
    const payload = { userId: 'u2', exp: old };
    const token = jwt.sign(payload as any, JWT_SECRET);
    const res = await request(SERVER_URL).post('/refresh-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.reason).toBe('refresh_window_exceeded');
  });
});
