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
import { AuthClient } from '@kedaruma/revlm-shared/auth-token';
import { ensureDefined } from '@kedaruma/revlm-shared/utils/asserts';
import { SetupTestEnvironmentResult, setupTestEnvironment, createTestUser, cleanupTestUser, cleanupTestEnvironment } from '@kedaruma/revlm-server/__tests__/setupTestMongo';
import path from 'path';

// Load environment variables (refer to .env) so that the necessary settings for the test are stored in process.env.
// 環境変数を読み込む（.env を参照）テスト内で必要な設定が process.env に入る。
dotenv.config({ path: path.join(__dirname, 'test.env') });

// Extend the timeout as mongodb-memory-server may take time to start
// mongodb-memory-server は起動に時間がかかる場合があるためタイムアウトを延長
jest.setTimeout(120000);

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

let testEnv: SetupTestEnvironmentResult;
let serverUrl: string;

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

  // Setup test environment (MongoDB + Server) using the utility function
  // ユーティリティ関数を使用してテスト環境（MongoDB + サーバー）をセットアップ
  testEnv = await setupTestEnvironment({
    serverConfig: {
      mongoUri: process.env.MONGO_URI as string,
      usersDbName: USERS_DB_NAME,
      usersCollectionName: USERS_COLLECTION_NAME,
      jwtSecret: ensureDefined(process.env.JWT_SECRET, 'JWT_SECRET is required'),
      provisionalLoginEnabled: process.env.PROVISIONAL_LOGIN_ENABLED === 'true' || process.env.PROVISIONAL_LOGIN_ENABLED === '1',
      provisionalAuthId: PROVISIONAL_AUTH_ID,
      provisionalAuthSecretMaster: PROVISIONAL_AUTH_SECRET_MASTER,
      provisionalAuthDomain: PROVISIONAL_AUTH_DOMAIN,
      port: Number(process.env.PORT),
    }
  });

  serverUrl = testEnv.serverUrl;
  console.log('beforeAll: server started at', serverUrl);

  // Create test user using the utility function
  // ユーティリティ関数を使用してテストユーザを作成
  await createTestUser({
    serverUrl,
    user: testUser,
    password: testPassword,
    provisionalAuthId: PROVISIONAL_AUTH_ID,
    provisionalAuthSecretMaster: PROVISIONAL_AUTH_SECRET_MASTER,
    provisionalAuthDomain: PROVISIONAL_AUTH_DOMAIN,
  });

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

  // Delete the user used in the test using the utility function
  // ユーティリティ関数を使用してテストで使用したユーザを削除
  try {
    await cleanupTestUser(testAuthId);
  } catch (error) {
    console.error('Failed to cleanup test user in afterAll:', error);
  }

  // Clean up test environment (stop server and MongoDB) using the utility function
  // ユーティリティ関数を使用してテスト環境をクリーンアップ（サーバーと MongoDB を停止）
  await cleanupTestEnvironment(testEnv);

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
