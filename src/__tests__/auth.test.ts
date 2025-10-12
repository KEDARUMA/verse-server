import request from 'supertest';
import { ObjectId, EJSON } from 'bson';
import dotenv from 'dotenv';
import { User } from "../models/user-types";
import { registerUserRaw, deleteUserRaw } from '../server';
import { MongoClient } from 'mongodb'; // clientをインポート
import { AuthClient } from '../auth-token';
import { startServer, client as serverClient, stopServer } from '../server';
dotenv.config();
const why = require('why-is-node-running');

const SHOW_WHY_DIAGNOSTIC = false;
const SERVER_URL = 'http://localhost:' + (process.env.PORT || 3000);
const USERS_COLLECTION = process.env.USERS_COLLECTION_NAME || 'user-info';

// テスト用authIdを一意化
const testAuthId: string = 'testuser_' + Date.now();
const testPassword = 'testpass123';
const testUser: User = {
  authId: testAuthId,
  userType: 'staff', // 'staff' or 'customer'
  roles: ['test'],
  merchantId: new ObjectId(),
};

let createdUserId: string | undefined;
const client = new MongoClient(process.env.MONGO_URI || '');
let provisionalPassword: string;
let server: any;

beforeAll(async () => {
  console.log('beforeAll: start');
  server = await startServer();
  console.log('beforeAll: server started');
  await client.connect(); // MongoDBクライアントを接続
  console.log('beforeAll: MongoDB connected');

  // provisional password生成
  const authDomain = process.env.PROVISIONAL_AUTH_DOMAIN;
  const secretMaster = process.env.PROVISIONAL_AUTH_SECRET_MASTER;
  const provisionalAuthId = process.env.PROVISIONAL_AUTH_ID;
  if (!authDomain || !secretMaster || !provisionalAuthId) throw new Error('provisional login env missing');
  const provisionalClient = new AuthClient({ secretMaster, authDomain });
  provisionalPassword = await provisionalClient.producePassword(provisionalAuthId);
  console.log('beforeAll: provisional password generated');

  // テスト用アカウントを登録
  try {
    await registerUserRaw(testUser, testPassword);
    console.log('beforeAll: test user registered');
  } catch (error) {
    console.error('Failed to register test account in beforeAll:', error);
  }
  console.log('beforeAll: end');
});

afterAll(async () => {
  console.log('afterAll: start');
  // テストで作成したユーザーを削除
  try {
    if (testAuthId) {
      await deleteUserRaw(undefined, testAuthId);
      console.log('afterAll: test user deleted');
    } else {
      console.error('testAuthId is undefined, skipping deletion.');
    }
  } catch (error) {
    console.error('Failed to delete test account in afterAll:', error);
  }

  // MongoDBクライアントを明示的にクローズ
  console.log('afterAll: MongoDB close start');
  // Force-close the client to ensure sockets and monitor timers are terminated
  await client.close(true);
  console.log('afterAll: local MongoDB close done');
  console.log('afterAll: stopping server and server-side resources');
  await stopServer();
  console.log('afterAll: stopServer done');

  console.log('afterAll: done');
});

describe('Auth API Integration', () => {
  it('registerUser API: should register a new user with valid token', async () => {
    console.log('test: registerUser start');
    const loginRes = await request(SERVER_URL)
      .post('/login')
      .send({ authId: testAuthId as string, password: testPassword });
    const token = loginRes.body.token;

    const newUser = {
      authId: 'api_test_user',
      userType: 'staff',
      roles: ['test'],
      merchantId: new ObjectId(),
    };

    const res = await request(SERVER_URL)
      .post('/registerUser')
      .set('Authorization', `Bearer ${token}`)
      .send({ user: newUser, password: 'api_test_pass' });

    expect(res.body.ok).toBe(true);
    expect(res.body.user.authId).toBe('api_test_user');
    console.log('test: registerUser end');
  });

  it('deleteUser API: should delete user with valid token', async () => {
    console.log('test: deleteUser start');
    const loginRes = await request(SERVER_URL)
      .post('/login')
      .send({ authId: testAuthId as string, password: testPassword });
    const token = loginRes.body.token;

    const res = await request(SERVER_URL)
      .post('/deleteUser')
      .set('Authorization', `Bearer ${token}`)
      .send({ authId: 'api_test_user' });

    expect(res.body.ok).toBe(true);
    expect(res.body.deletedCount).toBe(1);
    console.log('test: deleteUser end');
  });
});

describe('Provisional Login API', () => {
  it('should return a token for valid provisional credentials', async () => {
    console.log('test: provisional-login valid start');
    const res = await request(SERVER_URL)
      .post('/provisional-login')
      .send({
        authId: process.env.PROVISIONAL_AUTH_ID,
        password: provisionalPassword
      });
    expect(res.body.ok).toBe(true);
    expect(res.body.token).toBeDefined();
    expect(res.body.user).toBeDefined();
    console.log('test: provisional-login valid end');
  });

  it('should fail for invalid provisional credentials', async () => {
    console.log('test: provisional-login invalid start');
    const res = await request(SERVER_URL)
      .post('/provisional-login')
      .send({
        authId: 'wrong_id',
        password: 'wrong_password'
      });
    expect(res.body.ok).toBe(false);
    expect(res.body.token).toBeUndefined();
    console.log('test: provisional-login invalid end');
  });

  it('provisional token should be forbidden from accessing protected endpoints', async () => {
    console.log('test: provisional access forbidden start');
    // obtain a fresh provisional password and token (passwords may be one-time use)
    const provisionalClient = new AuthClient({ secretMaster: process.env.PROVISIONAL_AUTH_SECRET_MASTER!, authDomain: process.env.PROVISIONAL_AUTH_DOMAIN! });
    const freshPassword = await provisionalClient.producePassword(process.env.PROVISIONAL_AUTH_ID!);
    const loginRes = await request(SERVER_URL)
      .post('/provisional-login')
      .send({ authId: process.env.PROVISIONAL_AUTH_ID, password: freshPassword });
    expect(loginRes.body.ok).toBe(true);
    const token = loginRes.body.token;

    // attempt to call a protected endpoint (/verse-gate)
    const res = await request(SERVER_URL)
      .post('/verse-gate')
      .set('Authorization', `Bearer ${token}`)
      .send({ collection: 'user-info', method: 'find', filter: {} });

    // should be rejected by verifyToken middleware
    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    // error message should indicate provisional restriction
    expect(res.body.error).toBeDefined();
    console.log('test: provisional access forbidden end');
  });
});
