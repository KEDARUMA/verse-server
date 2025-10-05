import request from 'supertest';
import { ObjectId, EJSON } from 'bson';
import dotenv from 'dotenv';
import {User} from "../models/user-types";
dotenv.config();

const SERVER_URL = 'http://localhost:' + (process.env.PORT || 3000);
const USERS_COLLECTION = process.env.USERS_COLLECTION_NAME || 'user-info';

// テスト用authIdを一意化
const testAuthId = 'testuser_' + Date.now();
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

function parseEjsonResponse(res: any) {
  const ct = res.headers['content-type'] || '';
  if (ct.includes('application/ejson')) {
    return EJSON.parse(res.text);
  }
  return res.body;
}

describe('Auth API Integration', () => {
  it('registerUser: should register a new user', async () => {
    const payload = EJSON.stringify({ user: testUser, password: testPassword });
    const res = await request(SERVER_URL)
      .post('/registerUser')
      .set('Content-Type', 'application/ejson')
      .set('Accept', 'application/ejson')
      .send(payload);
    const body = parseEjsonResponse(res);
    expect(body.ok).toBe(true);
    expect(body.user.authId).toBe(testAuthId);
    expect(body.user.passwordHash).toBeDefined();
    expect(body.user._id).toBeDefined();
    createdUserId = typeof body.user._id === 'string' ? body.user._id : body.user._id.$oid || body.user._id.toHexString();
  });

  it('registerUser: should fail on duplicate authId', async () => {
    const payload = EJSON.stringify({ user: testUser, password: testPassword });
    const res = await request(SERVER_URL)
      .post('/registerUser')
      .set('Content-Type', 'application/ejson')
      .set('Accept', 'application/ejson')
      .send(payload);
    const body = parseEjsonResponse(res);
    expect(body.ok).toBe(false);
    expect(body.error).toMatch(/authId already exists/);
  });

  it('registerUser: should fail if authId is missing', async () => {
    const user = { ...testUser } as any;
    delete user.authId;
    const payload = EJSON.stringify({ user, password: testPassword });
    const res = await request(SERVER_URL)
      .post('/registerUser')
      .set('Content-Type', 'application/ejson')
      .set('Accept', 'application/ejson')
      .send(payload);
    const body = parseEjsonResponse(res);
    expect(body.ok).toBe(false);
    expect(body.error).toMatch(/authId is required/);
  });

  it('registerUser: should fail if password is missing', async () => {
    const payload = EJSON.stringify({ user: testUser });
    const res = await request(SERVER_URL)
      .post('/registerUser')
      .set('Content-Type', 'application/ejson')
      .set('Accept', 'application/ejson')
      .send(payload);
    const body = parseEjsonResponse(res);
    expect(body.ok).toBe(false);
    expect(body.error).toMatch(/Password is required/);
  });

  it('login: should login with correct password', async () => {
    const payload = EJSON.stringify({ authId: testAuthId, password: testPassword });
    const res = await request(SERVER_URL)
      .post('/login')
      .set('Content-Type', 'application/ejson')
      .set('Accept', 'application/ejson')
      .send(payload);
    const body = parseEjsonResponse(res);
    expect(body.ok).toBe(true);
    expect(body.token).toBeDefined();
    expect(body.user.authId).toBe(testAuthId);
  });

  it('login: should fail with wrong password', async () => {
    const payload = EJSON.stringify({ authId: testAuthId, password: 'wrongpass' });
    const res = await request(SERVER_URL)
      .post('/login')
      .set('Content-Type', 'application/ejson')
      .set('Accept', 'application/ejson')
      .send(payload);
    const body = parseEjsonResponse(res);
    expect(body.ok).toBe(false);
    expect(body.error).toMatch(/Authentication failed/);
  });

  it('login: should fail with unknown authId', async () => {
    const payload = EJSON.stringify({ authId: 'unknown_' + Date.now(), password: testPassword });
    const res = await request(SERVER_URL)
      .post('/login')
      .set('Content-Type', 'application/ejson')
      .set('Accept', 'application/ejson')
      .send(payload);
    const body = parseEjsonResponse(res);
    expect(body.ok).toBe(false);
    expect(body.error).toMatch(/Authentication failed/);
  });

  it('deleteUser: should delete by _id', async () => {
    expect(createdUserId).toBeDefined();
    const delPayload = EJSON.stringify({ _id: { $oid: createdUserId } });
    const res = await request(SERVER_URL)
      .post('/deleteUser')
      .set('Content-Type', 'application/ejson')
      .set('Accept', 'application/ejson')
      .send(delPayload);
    const body = parseEjsonResponse(res);
    expect(body.ok).toBe(true);
    expect(body.deletedCount).toBe(1);
  });

  it('deleteUser: should delete by authId', async () => {
    // register another user
    const secondAuthId = 'testuser2_' + Date.now();
    const secondUser: User = {
      version: '1',
      collectionType: USERS_COLLECTION,
      isRemove: false,
      authId: secondAuthId,
      userType: 'staff',
      roles: ['test'],
      merchantId: new ObjectId(),
    };
    const regPayload = EJSON.stringify({ user: secondUser, password: testPassword });
    const regRes = await request(SERVER_URL)
      .post('/registerUser')
      .set('Content-Type', 'application/ejson')
      .set('Accept', 'application/ejson')
      .send(regPayload);
    const regBody = parseEjsonResponse(regRes);
    expect(regBody.ok).toBe(true);

    const delPayload = EJSON.stringify({ authId: secondAuthId });
    const del = await request(SERVER_URL)
      .post('/deleteUser')
      .set('Content-Type', 'application/ejson')
      .set('Accept', 'application/ejson')
      .send(delPayload);
    const delBody = parseEjsonResponse(del);
    expect(delBody.ok).toBe(true);
    expect(delBody.deletedCount).toBe(1);
  });

  afterAll(async () => {
    // テストで作成したユーザーを削除
    const payload = EJSON.stringify({ collection: USERS_COLLECTION, method: 'deleteOne', query: { authId: testAuthId } });
    await request(SERVER_URL)
      .post('/mongo')
      .set('Content-Type', 'application/ejson')
      .set('Accept', 'application/ejson')
      .send(payload);
  });
});
