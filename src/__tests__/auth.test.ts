import request from 'supertest';
import { ObjectId, EJSON } from 'bson';
import dotenv from 'dotenv';
import { User } from "../models/user-types";
import { registerUserRaw, deleteUserRaw } from '../server';
import { MongoClient } from 'mongodb'; // clientをインポート
dotenv.config();

const SERVER_URL = 'http://localhost:' + (process.env.PORT || 3000);
const USERS_COLLECTION = process.env.USERS_COLLECTION_NAME || 'user-info';

// テスト用authIdを一意化
const testAuthId: string = 'testuser_' + Date.now();
const testPassword = 'testpass123';
const testUser: User = {
  version: '1',
  collectionType: USERS_COLLECTION,
  isRemove: false,
  authId: testAuthId,
  userType: 'staff', // 'staff' or 'customer'
  roles: ['test'],
  merchantId: new ObjectId(),
};

let createdUserId: string | undefined;
const client = new MongoClient(process.env.MONGO_URI || '');

beforeAll(async () => {
  await client.connect(); // MongoDBクライアントを接続

  // テスト用アカウントを登録
  try {
    await registerUserRaw(testUser, testPassword);
  } catch (error) {
    console.error('Failed to register test account in beforeAll:', error);
  }
});

afterAll(async () => {
  // テストで作成したユーザーを削除
  try {
    if (testAuthId) {
      await deleteUserRaw(undefined, testAuthId);
    } else {
      console.error('testAuthId is undefined, skipping deletion.');
    }
  } catch (error) {
    console.error('Failed to delete test account in afterAll:', error);
  }

  // MongoDBクライアントを明示的にクローズ
  await client.close();
});

describe('Auth API Integration', () => {
  it('registerUser API: should register a new user with valid token', async () => {
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
  });

  it('deleteUser API: should delete user with valid token', async () => {
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
  });
});
