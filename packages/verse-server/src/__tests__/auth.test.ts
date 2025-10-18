import request from 'supertest';
import { ObjectId } from 'bson';
import dotenv from 'dotenv';
import { User } from 'verse-shared/models/user-types';
import { registerUserRaw, deleteUserRaw, startServer, stopServer } from 'verse-server/server';
import { MongoClient } from 'mongodb';
import { AuthClient } from 'verse-shared/auth-token';

dotenv.config();

const SERVER_URL = 'http://localhost:' + (process.env.PORT || 3000);

const client = new MongoClient(process.env.MONGO_URI || '');

const testAuthId: string = 'testuser_' + Date.now();
const testPassword = 'testpass123';
const testUser: User = {
  authId: testAuthId,
  userType: 'staff',
  roles: ['test'],
  merchantId: new ObjectId(),
};

let provisionalPassword: string;
let server: any;

beforeAll(async () => {
  console.log('beforeAll: start');
  server = await startServer();
  console.log('beforeAll: server started');
  await client.connect();
  console.log('beforeAll: MongoDB connected');

  const authDomain = process.env.PROVISIONAL_AUTH_DOMAIN;
  const secretMaster = process.env.PROVISIONAL_AUTH_SECRET_MASTER;
  const provisionalAuthId = process.env.PROVISIONAL_AUTH_ID;
  if (!authDomain || !secretMaster || !provisionalAuthId) throw new Error('provisional login env missing');
  const provisionalClient = new AuthClient({ secretMaster, authDomain });
  provisionalPassword = await provisionalClient.producePassword(provisionalAuthId);
  console.log('beforeAll: provisional password generated');

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
  try {
    if (testAuthId) {
      await deleteUserRaw(undefined, testAuthId);
      console.log('afterAll: test user deleted');
    }
  } catch (error) {
    console.error('Failed to delete test account in afterAll:', error);
  }

  console.log('afterAll: MongoDB close start');
  await client.close(true);
  console.log('afterAll: local MongoDB close done');
  console.log('afterAll: stopping server and server-side resources');
  await stopServer();
  console.log('afterAll: stopServer done');

  console.log('afterAll: done');
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

describe('Provisional Login API', () => {
  it('should return a token for valid provisional credentials', async () => {
    const res = await request(SERVER_URL)
      .post('/provisional-login')
      .send({
        authId: process.env.PROVISIONAL_AUTH_ID,
        password: provisionalPassword
      });
    expect(res.body.ok).toBe(true);
    expect(res.body.token).toBeDefined();
    expect(res.body.user).toBeDefined();
  });

  it('should fail for invalid provisional credentials', async () => {
    const res = await request(SERVER_URL)
      .post('/provisional-login')
      .send({ authId: 'wrong_id', password: 'wrong_password' });
    expect(res.body.ok).toBe(false);
    expect(res.body.token).toBeUndefined();
  });

  it('provisional token should be forbidden from accessing protected endpoints', async () => {
    const provisionalClient = new AuthClient({ secretMaster: process.env.PROVISIONAL_AUTH_SECRET_MASTER!, authDomain: process.env.PROVISIONAL_AUTH_DOMAIN! });
    const freshPassword = await provisionalClient.producePassword(process.env.PROVISIONAL_AUTH_ID!);
    const loginRes = await request(SERVER_URL)
      .post('/provisional-login')
      .send({ authId: process.env.PROVISIONAL_AUTH_ID, password: freshPassword });
    expect(loginRes.body.ok).toBe(true);
    const token = loginRes.body.token;

    const res = await request(SERVER_URL)
      .post('/verse-gate')
      .set('Authorization', `Bearer ${token}`)
      .send({ collection: 'user-info', method: 'find', filter: {} });

    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toBeDefined();
  });
});
