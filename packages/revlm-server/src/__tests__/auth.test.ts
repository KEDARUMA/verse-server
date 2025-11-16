// このファイルは認証関連APIの統合テストを行うための Jest テストファイルです。
// - mongodb-memory-server を使ってインメモリのMongoDBを立ち上げ
// - サーバを起動して実際のHTTPエンドポイントを supertest で叩くことで E2E に近い統合テストを実行
// - provisional（仮）ログインの挙動や registerUser/deleteUser の権限チェックを検証します

import request from 'supertest';
import { ObjectId } from 'bson';
import dotenv from 'dotenv';
import { User } from '@kedaruma/revlm-shared/models/user-types';
import { registerUserRaw, deleteUserRaw, startServer, stopServer } from '@kedaruma/revlm-server/server';
import { AuthClient } from '@kedaruma/revlm-shared/auth-token';
import { ensureDefined } from '@kedaruma/revlm-shared/utils/asserts';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import path from 'path';

// 環境変数を読み込む（.env を参照）テスト内で必要な設定が process.env に入る。
dotenv.config({ path: path.join(__dirname, 'auth.test.env') });

// mongodb-memory-server は起動に時間がかかる場合があるためタイムアウトを延長
jest.setTimeout(120000);

const MONGO_URI = ensureDefined(process.env.MONGO_URI);
const USERS_DB_NAME = ensureDefined(process.env.USERS_DB_NAME, 'USERS_DB_NAME is required');
const USERS_COLLECTION_NAME = ensureDefined(process.env.USERS_COLLECTION_NAME, 'USERS_COLLECTION_NAME is required');

// テストで利用するダミー認証情報
const testAuthId: string = 'testuser_' + Date.now();
const testPassword = 'testpass123';
const testUser: User = {
  authId: testAuthId,
  userType: 'staff',
  roles: ['test'],
  merchantId: new ObjectId(),
};

let server;
let serverUrl: string;
let provisionalPassword: string;
let mongod: MongoMemoryServer | undefined;

// beforeAll: テスト開始前のセットアップ
// - インメモリMongoDB起動
// - サーバ起動
// - provisional password の生成（必要に応じて provisional ログインを試すため）
// - テスト用ユーザの登録（registerUserRaw を使って直接DBへ登録）
beforeAll(async () => {
  console.log('beforeAll: start');

  // MongoMemoryServerを起動
  let parsedHost: string | undefined;
  let parsedPort: number | undefined;
  const normalized = MONGO_URI.replace(/^mongodb\+srv:\/\//, 'http://').replace(/^mongodb:\/\//, 'http://');
  const u = new URL(normalized);
  parsedHost = u.hostname;
  parsedPort = u.port ? Number(u.port) : undefined;
  mongod = await MongoMemoryServer.create({ instance: { port: parsedPort, ip: parsedHost, dbName: 'testdb' } as any });

  // サーバ起動（startServer はアプリケーションの express または類似の HTTP サーバを返す）
  server = await startServer({
    mongoUri: MONGO_URI,
    usersDbName: ensureDefined(process.env.USERS_DB_NAME, 'USERS_DB_NAME is required'),
    usersCollectionName: ensureDefined(process.env.USERS_COLLECTION_NAME, 'USERS_COLLECTION_NAME is required'),
    jwtSecret: ensureDefined(process.env.JWT_SECRET, 'JWT_SECRET is required'),
    provisionalLoginEnabled: process.env.PROVISIONAL_LOGIN_ENABLED === 'true' || process.env.PROVISIONAL_LOGIN_ENABLED === '1',
    provisionalAuthId: ensureDefined(process.env.PROVISIONAL_AUTH_ID, 'PROVISIONAL_AUTH_ID is required'),
    provisionalAuthSecretMaster: ensureDefined(process.env.PROVISIONAL_AUTH_SECRET_MASTER, 'PROVISIONAL_AUTH_SECRET_MASTER is required'),
    provisionalAuthDomain: ensureDefined(process.env.PROVISIONAL_AUTH_DOMAIN, 'PROVISIONAL_AUTH_DOMAIN is required'),
    port: Number(ensureDefined(process.env.PORT, 'PORT is required')),
  });
  // set serverUrl from actual listening port
  try {
    const addr: any = server && server.address ? server.address() : undefined;
    const port = addr && typeof addr === 'object' ? addr.port : (process.env.PORT ? Number(process.env.PORT) : 3000);
    serverUrl = `http://localhost:${port}`;
  } catch (_e) {
    serverUrl = `http://localhost:${process.env.PORT || 3000}`;
  }
  console.log('beforeAll: server started at', serverUrl);

  // provisional 認証情報関連（テストでは provisionalPassword を生成するが、registerUserRaw を使うため API フローを必須にはしていない）
  const authDomain = process.env.PROVISIONAL_AUTH_DOMAIN;
  const secretMaster = process.env.PROVISIONAL_AUTH_SECRET_MASTER;
  const provisionalAuthId = process.env.PROVISIONAL_AUTH_ID;
  if (!authDomain || !secretMaster || !provisionalAuthId) throw new Error('provisional login env missing');
  const provisionalClient = new AuthClient({ secretMaster, authDomain });
  // producePassword は provisional 認証で使う一時的なパスワードを生成するユーティリティ
  provisionalPassword = await provisionalClient.producePassword(provisionalAuthId);
  console.log('beforeAll: provisional password generated');

  try {
    // Use provisional login to obtain a token, then register test user via API
    const provisionalLoginRes = await request(serverUrl)
      .post('/provisional-login')
      .send({ authId: provisionalAuthId, password: provisionalPassword });
    if (!provisionalLoginRes.body || !provisionalLoginRes.body.ok) throw new Error('provisional-login failed');
    const provisionalToken = provisionalLoginRes.body.token as string;

    const regRes = await request(serverUrl)
      .post('/registerUser')
      .set('Authorization', `Bearer ${provisionalToken}`)
      .send({ user: testUser, password: testPassword });
    if (!regRes.body || !regRes.body.ok) throw new Error('registerUser via API failed');
    console.log('beforeAll: test user registered via API');
  } catch (error) {
    console.error('Failed to register test account in beforeAll:', error);
  }
  console.log('beforeAll: end');
});

// afterAll: テスト終了時のクリーンアップ処理
// - テストで作成したユーザの削除（deleteUserRaw）
// - サーバ停止
// - mongodb-memory-server の停止
afterAll(async () => {
  console.log('afterAll: start');
  try {
    if (testAuthId) {
      // deleteUserRaw は内部で DB を操作して該当ユーザを削除するユーティリティ
      await deleteUserRaw(undefined, testAuthId);
      console.log('afterAll: test user deleted');
    }
  } catch (error) {
    console.error('Failed to delete test account in afterAll:', error);
  }

  console.log('afterAll: stopping server and server-side resources');
  await stopServer();
  console.log('afterAll: stopServer done');

  // Stop the in-memory mongo server we started in beforeAll
  if (mongod) {
    try {
      await mongod.stop();
      mongod = undefined;
      console.log('afterAll: mongod stopped');
    } catch (e) {
      console.warn('Failed to stop mongodb-memory-server in afterAll:', e);
    }
  }

  console.log('afterAll: done');
});

// --- テストケース群 ---
// Auth API の統合テスト（registerUser / deleteUser）
describe('Auth API Integration', () => {
  it('registerUser API: should register a new user with valid token', async () => {
    // このテストではまず /login でテストユーザでログインし JWT を取得
    const loginRes = await request(serverUrl)
      .post('/login')
      .send({ authId: testAuthId as string, password: testPassword });
    const token = loginRes.body.token;

    // 登録対象ユーザのペイロード
    const newUser = {
      authId: 'api_test_user',
      userType: 'staff',
      roles: ['test'],
      merchantId: new ObjectId(),
    };

    // /registerUser を叩き、期待通りユーザが作成されることを確認
    const res = await request(serverUrl)
      .post('/registerUser')
      .set('Authorization', `Bearer ${token}`)
      .send({ user: newUser, password: 'api_test_pass' });

    // 期待値: ok: true, user.authId が渡した値であること
    expect(res.body.ok).toBe(true);
    expect(res.body.user.authId).toBe('api_test_user');
  });

  it('deleteUser API: should delete user with valid token', async () => {
    // /login して JWT を取得
    const loginRes = await request(serverUrl)
      .post('/login')
      .send({ authId: testAuthId as string, password: testPassword });
    const token = loginRes.body.token;

    // 先ほど作成した api_test_user を削除する API を呼ぶ
    const res = await request(serverUrl)
      .post('/deleteUser')
      .set('Authorization', `Bearer ${token}`)
      .send({ authId: 'api_test_user' });

    // 期待値: ok: true, deletedCount が 1
    expect(res.body.ok).toBe(true);
    expect(res.body.deletedCount).toBe(1);
  });
});

// Provisional Login 関連のテスト群
describe('Provisional Login API', () => {
  it('should return a token for valid provisional credentials', async () => {
    // generate a fresh provisional password (nonce replay is rejected)
    const provisionalClient = new AuthClient({ secretMaster: process.env.PROVISIONAL_AUTH_SECRET_MASTER!, authDomain: process.env.PROVISIONAL_AUTH_DOMAIN! });
    const freshPassword = await provisionalClient.producePassword(process.env.PROVISIONAL_AUTH_ID!);
    const res = await request(serverUrl)
      .post('/provisional-login')
      .send({
        authId: process.env.PROVISIONAL_AUTH_ID,
        password: freshPassword
      });
    expect(res.body.ok).toBe(true);
    expect(res.body.token).toBeDefined();
    expect(res.body.user).toBeDefined();
  });

  it('should fail for invalid provisional credentials', async () => {
    // 不正な資格情報では ok: false が返ることを確認
    const res = await request(serverUrl)
      .post('/provisional-login')
      .send({ authId: 'wrong_id', password: 'wrong_password' });
    expect(res.body.ok).toBe(false);
    expect(res.body.token).toBeUndefined();
  });

  it('provisional token should be forbidden from accessing protected endpoints', async () => {
    // provisional トークンは限定的な権限を持つため、/revlm-gate など保護されたエンドポイントにアクセスしても 403 になることを確認
    const provisionalClient = new AuthClient({ secretMaster: process.env.PROVISIONAL_AUTH_SECRET_MASTER!, authDomain: process.env.PROVISIONAL_AUTH_DOMAIN! });
    const freshPassword = await provisionalClient.producePassword(process.env.PROVISIONAL_AUTH_ID!);
    const loginRes = await request(serverUrl)
      .post('/provisional-login')
      .send({ authId: process.env.PROVISIONAL_AUTH_ID, password: freshPassword });
    expect(loginRes.body.ok).toBe(true);
    const token = loginRes.body.token;

    const res = await request(serverUrl)
      .post('/revlm-gate')
      .set('Authorization', `Bearer ${token}`)
      .send({ db: USERS_DB_NAME, collection: USERS_COLLECTION_NAME, method: 'find', filter: {} });

    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toBeDefined();
  });
});
