// .envからMongoDBの接続情報を読み込む
require('dotenv').config();

import { MongoClient, Collection } from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';

const DATABASE_NAME = 'revlm'

describe('MongoDB CRUD Test', () => {
  let client: MongoClient;
  let db: any;
  let col: Collection;
  const tempCollection = `temp_test_collection_${Date.now()}`;
  let mongod: MongoMemoryServer | undefined;

  beforeAll(async () => {
    // mongodb-memory-server を起動してテスト用の MONGO_URI を設定
    mongod = await MongoMemoryServer.create();
    process.env.MONGO_URI = mongod.getUri();

    client = new MongoClient(process.env.MONGO_URI!);
    await client.connect();
    db = client.db(DATABASE_NAME);
    col = db.collection(tempCollection);
  });

  afterAll(async () => {
    try {
      await col.drop();
      console.log(`Collection ${tempCollection} dropped successfully.`);
    } catch (err) {
      console.warn(`Collection ${tempCollection} drop failed:`, err);
    } finally {
      await client.close();
      if (mongod) {
        try {
          await mongod.stop();
        } catch (e) {
          console.warn('Failed to stop mongodb-memory-server:', e);
        }
      }
    }
  });

  it('should insert a document', async () => {
    const result = await col.insertOne({ name: 'test', value: 123 });
    expect(result.insertedId).toBeDefined();
  });

  it('should find the inserted document', async () => {
    const docs = await col.find({ name: 'test' }).toArray();
    expect(docs.length).toBe(1);
    expect(docs[0] && docs[0].value).toBe(123);
  });

  it('should update the document', async () => {
    const result = await col.updateOne({ name: 'test' }, { $set: { value: 456 } });
    expect(result.modifiedCount).toBe(1);
    const updated = await col.findOne({ name: 'test' });
    expect(updated && updated.value).toBe(456);
  });

  it('should delete the document', async () => {
    const result = await col.deleteOne({ name: 'test' });
    expect(result.deletedCount).toBe(1);
    const docs = await col.find({ name: 'test' }).toArray();
    expect(docs.length).toBe(0);
  });
});
