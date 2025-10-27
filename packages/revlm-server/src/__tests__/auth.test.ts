import request from 'supertest';
import { ObjectId } from 'bson';
import dotenv from 'dotenv';
import { User } from '@kedaruma/revlm-shared/models/user-types';
import { registerUserRaw, deleteUserRaw, startServer, stopServer } from '@kedaruma/revlm-server/server';
import { AuthClient } from '@kedaruma/revlm-shared/auth-token';
import { ensureDefined } from '@kedaruma/revlm-shared/utils/asserts';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';

dotenv.config();
// Extend Jest hook timeout to allow mongodb-memory-server to download/start
jest.setTimeout(120000);

const MONGO_URI = ensureDefined(process.env.MONGO_URI);
const USERS_DB_NAME = ensureDefined(process.env.USERS_DB_NAME);
const USERS_COLLECTION_NAME = ensureDefined(process.env.USERS_COLLECTION_NAME);

const SERVER_URL = 'http://localhost:' + (process.env.PORT || 3000);

const testAuthId: string = 'testuser_' + Date.now();
const testPassword = 'testpass123';
const testUser: User = {
  authId: testAuthId,
  userType: 'staff',
  roles: ['test'],
  merchantId: new ObjectId(),
};

let server;
let provisionalPassword: string;
let mongod: MongoMemoryServer | undefined;

beforeAll(async () => {
  console.log('beforeAll: start');
  // Start an in-memory MongoDB for this test and set MONGO_URI at runtime
  console.log('### 1 - beforeAll: starting mongod');

  let parsedHost: string | undefined;
  let parsedPort: number | undefined;
  const normalized = MONGO_URI.replace(/^mongodb\+srv:\/\//, 'http://').replace(/^mongodb:\/\//, 'http://');
  const u = new URL(normalized);
  parsedHost = u.hostname;
  parsedPort = u.port ? Number(u.port) : undefined;
  mongod = await MongoMemoryServer.create({ instance: { port: parsedPort, ip: parsedHost, dbName: 'testdb' } as any });

  console.log('### 2 - beforeAll: mongod started');
  console.log('### 3 - beforeAll: MONGO_URI set to mongod uri', process.env.MONGO_URI, mongod.getUri());
  process.env.MONGO_URI = mongod.getUri();

  // Ensure the in-memory mongod is reachable before starting the server
  const tmpUri = process.env.MONGO_URI;
  const maxAttempts = 10;
  let lastErr: any = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const tmpClient = new MongoClient(tmpUri);
    try {
      await tmpClient.connect();
      await tmpClient.db().admin().ping();
      console.log('MongoMemoryServer is running (ping OK)');
      await tmpClient.close();
      lastErr = null;
      break;
    } catch (e: any) {
      lastErr = e;
      console.log(`MongoMemoryServer ping attempt ${attempt} failed - Error name:`, e && e.name, 'Error message:', e && e.message);
      try {
        await tmpClient.close();
      } catch (_closeErr) {
        // ignore
      }
      if (attempt < maxAttempts) {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
  }
  if (lastErr) {
    // If we couldn't reach mongod, throw to fail the test setup early with clear info
    throw lastErr;
  }

  server = await startServer();
  console.log('beforeAll: server started');
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
      .post('/revlm-gate')
      .set('Authorization', `Bearer ${token}`)
      .send({ dn: USERS_DB_NAME, collection: USERS_COLLECTION_NAME, method: 'find', filter: {} });

    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toBeDefined();
  });
});
