// Jest test file for integration testing of revlm-server.
// - Launch an in-memory MongoDB using mongodb-memory-server
// - Start the server and hit real HTTP endpoints with supertest to run near end-to-end integration tests
// - Verify the behavior of provisional login
// - Validate the main authentication APIs of revlm-server
// revlm-serverの統合テストを行うための Jest テストファイルです。
// - mongodb-memory-server を使ってインメモリのMongoDBを立ち上げ
// - サーバを起動して実際のHTTPエンドポイントを supertest で叩くことで E2E に近い統合テストを実行
// - provisional のログインの挙動
// - revlm-server の主要な認証APIの動作確認
import request from 'supertest';
import { ObjectId } from 'bson';
import dotenv from 'dotenv';
import { User } from '@kedaruma/revlm-shared/models/user-types';
import { deleteUserRaw, startServer, stopServer } from '@kedaruma/revlm-server/server';
import { AuthClient } from '@kedaruma/revlm-shared/auth-token';
import { ensureDefined } from '@kedaruma/revlm-shared/utils/asserts';
import { MongoMemoryServer } from 'mongodb-memory-server';
import path from 'path';

// Load environment variables (refer to .env) so that the necessary settings for the test are stored in process.env.
// 環境変数を読み込む（.env を参照）テスト内で必要な設定が process.env に入る。
dotenv.config({ path: path.join(__dirname, 'test.env') });

// Extend the timeout as mongodb-memory-server may take time to start
// mongodb-memory-server は起動に時間がかかる場合があるためタイムアウトを延長
jest.setTimeout(120000);

let MONGO_URI = process.env.MONGO_URI
const USERS_DB_NAME = ensureDefined(process.env.USERS_DB_NAME, 'USERS_DB_NAME is required');
const USERS_COLLECTION_NAME = ensureDefined(process.env.USERS_COLLECTION_NAME, 'USERS_COLLECTION_NAME is required');
const PROVISIONAL_AUTH_DOMAIN = ensureDefined(process.env.PROVISIONAL_AUTH_DOMAIN);
const PROVISIONAL_AUTH_SECRET_MASTER = ensureDefined(process.env.PROVISIONAL_AUTH_SECRET_MASTER);
const PROVISIONAL_AUTH_ID = ensureDefined(process.env.PROVISIONAL_AUTH_ID);

// Dummy authentication information used in the test
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

// beforeAll: Test setup
// - If MONGO_URI is not set, start MongoMemoryServer
// - Start revlm-server
// - Register a test user via provisional login
// beforeAll: テスト開始前のセットアップ
// - MONGO_URI の指定が無い場合は MongoMemoryServer を起動
// - revlm-server を起動
// - provisional login でテスト用ユーザの登録
beforeAll(async () => {
  console.log('beforeAll: start');

  // If MONGO_URI is not specified, start an in-memory MongoDB using mongodb-memory-server
  // MONGO_URI の指定が無い場合は mongodb-memory-server を起動
  if (!MONGO_URI) {
    // Start an in-memory MongoDB server
    try {
      mongod = await MongoMemoryServer.create({ instance: { dbName: 'testdb' } });
      if (!mongod) {
        throw new Error('MongoMemoryServer.create() returned null/undefined');
      }
    } catch (err) {
      console.error('Failed to start MongoMemoryServer:', err);
      throw err; // stop the test run
    }
    MONGO_URI = mongod.getUri();
  }

  // start the revlm-server
  server = await startServer({
    mongoUri: MONGO_URI!,
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

  // Obtain a token via provisional login and use it to register the test user through the API
  // provisional login でトークンを取得し、そのトークンを用いてテストユーザを API 経由で登録する
  try {
    // Generate a password for provisional login
    // provisional login のパスワードを生成
    if (!PROVISIONAL_AUTH_DOMAIN || !PROVISIONAL_AUTH_SECRET_MASTER || !PROVISIONAL_AUTH_ID) throw new Error('provisional login env missing');
    const provisionalClient = new AuthClient({secretMaster: PROVISIONAL_AUTH_SECRET_MASTER, authDomain: PROVISIONAL_AUTH_DOMAIN});
    provisionalPassword = await provisionalClient.producePassword(PROVISIONAL_AUTH_ID);

    // Perform provisional login to obtain a token
    // provisional login で仮認証を行いトークンを取得
    const provisionalLoginRes = await request(serverUrl)
      .post('/provisional-login')
      .send({ authId: PROVISIONAL_AUTH_ID, password: provisionalPassword });
    if (!provisionalLoginRes.body || !provisionalLoginRes.body.ok) throw new Error('provisional-login failed');
    const provisionalToken = provisionalLoginRes.body.token as string;

    // Register the test user
    // テストユーザを登録
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

// afterAll: post-processing after test completion
// - Delete the user created during the test (deleteUserRaw)
// - Stop the server
// - Stop the mongodb-memory-server
// afterAll: テスト終了時の後処理
// - テストで作成したユーザの削除（deleteUserRaw）
// - サーバ停止
// - mongodb-memory-server の停止
afterAll(async () => {
  console.log('afterAll: start');

  // Delete the user used in the test
  // テストで使用したユーザを削除
  try {
    if (testAuthId) {
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

// Integration tests for Auth API
// Auth API の統合テスト
describe('Auth API Integration', () => {
  it('registerUser API: should register a new user with valid token', async () => {
    // Log in with the test user and obtain a JWT
    // テストユーザでログインし JWT を取得
    const loginRes = await request(serverUrl)
      .post('/login')
      .send({ authId: testAuthId as string, password: testPassword });
    const token = loginRes.body.token;

    // Payload for the user to be registered
    // 登録対象ユーザのペイロード
    const newUser = {
      authId: 'api_test_user',
      userType: 'staff',
      roles: ['test'],
      merchantId: new ObjectId(),
    };

    // Call /registerUser and verify that the user is created as expected
    // /registerUser を呼び、期待通りユーザが作成されることを確認
    const res = await request(serverUrl)
      .post('/registerUser')
      .set('Authorization', `Bearer ${token}`)
      .send({ user: newUser, password: 'api_test_pass' });

    // 期待値: ok: true, user.authId が渡した値であること
    expect(res.body.ok).toBe(true);
    expect(res.body.user.authId).toBe('api_test_user');
  });

  it('deleteUser API: should delete user with valid token', async () => {
    // Log in with the test user and obtain a JWT
    // テストユーザでログインし JWT を取得
    const loginRes = await request(serverUrl)
      .post('/login')
      .send({ authId: testAuthId as string, password: testPassword });
    const token = loginRes.body.token;

    // Call /deleteUser to delete the dummy user created earlier
    // /deleteUser を呼び先ほど作成したダミーユーザを削除する
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

  // /provisional-login でログインする
  it('log in via provisional-login', async () => {
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

  // 不正な情報で /provisional-login を呼び出しても失敗することを確認
  it('verify that calling /provisional-login with invalid credentials fails', async () => {
    // 不正な資格情報では ok: false が返ることを確認
    const res = await request(serverUrl)
      .post('/provisional-login')
      .send({ authId: 'wrong_id', password: 'wrong_password' });
    expect(res.body.ok).toBe(false);
    expect(res.body.token).toBeUndefined();
  });

  // provisional login のトークンで /revlm-gate 使うと 403 になることを確認
  it('verify that using a provisional login token with revlm-gate results in a 403 status', async () => {
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
