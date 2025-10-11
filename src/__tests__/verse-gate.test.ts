import request from 'supertest';
import { ObjectId } from 'bson';
import dotenv from 'dotenv';
import { registerUserRaw, startServer, stopServer, client } from '../server';
import fs from 'fs';
import { EJSON } from 'bson';

dotenv.config();

const SERVER_URL = 'http://localhost:' + (process.env.PORT || 3000);
const TEST_COLLECTION = 'test-collection';

const testDocument = { name: 'Test Document', value: 42 };
const testDocuments = [
  { name: 'Document 1', value: 1 },
  { name: 'Document 2', value: 2 },
];

let insertedId: ObjectId;
let authToken: string;

// テスト用ユーザーの登録と認証トークン取得
beforeAll(async () => {
  // Start server so `client` is initialized and endpoints are available
  await startServer();

  // Register test user directly using the function (client is now available)
  await registerUserRaw(
    { authId: 'test-user', userType: 'staff', roles: [], merchantId: new ObjectId(), version: '0.0.0', collectionType: 'users', isRemove: false },
    'test-password'
  );

  // サーバーが起動していることとテストコレクションの初期化
  const loginRes = await request(SERVER_URL)
    .post('/login')
    .send({ authId: 'test-user', password: 'test-password' });

  expect(loginRes.body.ok).toBe(true);
  authToken = loginRes.body.token;

  // テストコレクションのデータを削除
  await request(SERVER_URL)
    .post('/verse-gate')
    .set('Authorization', `Bearer ${authToken}`)
    .send({
      collection: TEST_COLLECTION,
      method: 'deleteMany',
      filter: {},
    });
});

// テスト終了後のクリーンアップ処理
afterAll(async () => {
  // テストコレクションのデータ削除
  await request(SERVER_URL)
    .post('/verse-gate')
    .set('Authorization', `Bearer ${authToken}`)
    .send({
      collection: TEST_COLLECTION,
      method: 'deleteMany',
      filter: {},
    });

  // テストコレクション自体をドロップ
  await request(SERVER_URL)
    .post('/verse-gate')
    .set('Authorization', `Bearer ${authToken}`)
    .send({
      collection: TEST_COLLECTION,
      method: 'drop',
    });

  // テスト用ユーザーの削除
  await request(SERVER_URL)
    .post('/deleteUser')
    .set('Authorization', `Bearer ${authToken}`)
    .send({ authId: 'test-user' });

  // Stop server and close client
  try { await stopServer(); } catch (e) { /* ignore */ }
});

describe('/verse-gate API', () => {
  it('should insert a document', async () => {
    const res = await request(SERVER_URL)
      .post('/verse-gate')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        collection: TEST_COLLECTION,
        method: 'insertOne',
        document: testDocument,
      });

    expect(res.body.ok).toBe(true);
    expect(res.body.result.insertedId).toBeDefined();
    insertedId = res.body.result.insertedId;
  });

  it('should find documents', async () => {
    const res = await request(SERVER_URL)
      .post('/verse-gate')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        collection: TEST_COLLECTION,
        method: 'find',
        filter: {},
      });

    expect(res.body.ok).toBe(true);
    expect(res.body.result.length).toBeGreaterThan(0);
  });

  it('should find one document', async () => {
    const payload = {
      collection: TEST_COLLECTION,
      method: 'findOne',
      filter: { _id: { $oid: insertedId.toString() } },
    };
    const res = await request(SERVER_URL)
      .post('/verse-gate')
      .set('Authorization', `Bearer ${authToken}`)
      .set('Content-Type', 'application/ejson')
      .send(EJSON.stringify(payload));
    const body = EJSON.parse(res.text);
    if (!body.ok) {
      console.log('findOne error:', body);
      fs.appendFileSync('error.log', `findOne error: ${JSON.stringify(body)}\n`);
    }
    expect(body.ok).toBe(true);
    expect(body.result).not.toBeNull();
    expect(body.result).toMatchObject(testDocument);
  });

  it('should update a document', async () => {
    const payload = {
      collection: TEST_COLLECTION,
      method: 'updateOne',
      filter: { _id: { $oid: insertedId.toString() } },
      update: { $set: { value: 100 } },
    };
    const res = await request(SERVER_URL)
      .post('/verse-gate')
      .set('Authorization', `Bearer ${authToken}`)
      .set('Content-Type', 'application/ejson')
      .send(EJSON.stringify(payload));
    const body = EJSON.parse(res.text);
    if (!body.ok) {
      console.log('updateOne error:', body);
      fs.appendFileSync('error.log', `updateOne error: ${JSON.stringify(body)}\n`);
    }
    expect(body.ok).toBe(true);
    expect(body.result.matchedCount).toBeGreaterThanOrEqual(1);
    expect(body.result.modifiedCount).toBeGreaterThanOrEqual(1);
  });

  it('should delete a document', async () => {
    const payload = {
      collection: TEST_COLLECTION,
      method: 'deleteOne',
      filter: { _id: { $oid: insertedId.toString() } },
    };
    const res = await request(SERVER_URL)
      .post('/verse-gate')
      .set('Authorization', `Bearer ${authToken}`)
      .set('Content-Type', 'application/ejson')
      .send(EJSON.stringify(payload));
    const body = EJSON.parse(res.text);
    if (!body.ok) {
      console.log('deleteOne error:', body);
      fs.appendFileSync('error.log', `deleteOne error: ${JSON.stringify(body)}\n`);
    }
    expect(body.ok).toBe(true);
    expect(body.result.deletedCount).toBeGreaterThanOrEqual(1);
  });

  it('should insert multiple documents', async () => {
    const payload = {
      collection: TEST_COLLECTION,
      method: 'insertMany',
      documents: testDocuments,
    };
    const res = await request(SERVER_URL)
      .post('/verse-gate')
      .set('Authorization', `Bearer ${authToken}`)
      .set('Content-Type', 'application/ejson')
      .send(EJSON.stringify(payload));
    const body = EJSON.parse(res.text);
    if (!body.ok) {
      console.log('insertMany error:', body);
      fs.appendFileSync('error.log', `insertMany error: ${JSON.stringify(body)}\n`);
    }
    expect(body.ok).toBe(true);
    // insertedIds may be an object (EJSON) or array, so normalize to array
    const insertedIdsArr = Array.isArray(body.result.insertedIds)
      ? body.result.insertedIds
      : Object.values(body.result.insertedIds);
    expect(insertedIdsArr).toBeDefined();
    expect(Array.isArray(insertedIdsArr)).toBe(true);
    expect(insertedIdsArr.length).toBe(testDocuments.length);
  });

  it('should aggregate documents', async () => {
    const res = await request(SERVER_URL)
      .post('/verse-gate')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        collection: TEST_COLLECTION,
        method: 'aggregate',
        pipeline: [
          { $match: {} },
          { $group: { _id: null, total: { $sum: '$value' } } },
        ],
      });

    expect(res.body.ok).toBe(true);
    expect(res.body.result.length).toBeGreaterThan(0);
  });

  it('should count documents', async () => {
    const res = await request(SERVER_URL)
      .post('/verse-gate')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        collection: TEST_COLLECTION,
        method: 'count',
        filter: {},
      });

    expect(res.body.ok).toBe(true);
    expect(res.body.result).toBeGreaterThan(0);
  });
});
