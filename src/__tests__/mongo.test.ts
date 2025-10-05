// .envからMongoDBの接続情報を読み込む
require('dotenv').config();

// MongoDBクライアント・コレクション型をインポート
import { MongoClient, Collection } from 'mongodb';

const DATABASE_NAME = 'verse'

// MongoDBのCRUDテストスイート
describe('MongoDB CRUD Test', () => {
  // クライアント・DB・コレクションの変数宣言
  let client: MongoClient;
  let db: any;
  let col: Collection;
  // 一時コレクション名（タイムスタンプで一意化）
  const tempCollection = `temp_test_collection_${Date.now()}`;

  // テスト前にMongoDBへ接続し、一時コレクションを取得
  beforeAll(async () => {
    client = new MongoClient(process.env.MONGO_URI!);
    await client.connect();
    db = client.db(DATABASE_NAME);
    col = db.collection(tempCollection);
  });

  // テスト後に一時コレクション削除＆接続クローズ
  afterAll(async () => {
    try {
      await col.drop();
      console.log(`Collection ${tempCollection} dropped successfully.`);
    } catch (err) {
      console.warn(`Collection ${tempCollection} drop failed:`, err);
    } finally {
      await client.close();
    }
  });

  // ドキュメント追加テスト
  it('should insert a document', async () => {
    const result = await col.insertOne({ name: 'test', value: 123 });
    expect(result.insertedId).toBeDefined(); // 追加IDが定義されていること
  });

  // ドキュメント検索テスト
  it('should find the inserted document', async () => {
    const docs = await col.find({ name: 'test' }).toArray();
    expect(docs.length).toBe(1); // 1件ヒット
    expect(docs[0] && docs[0].value).toBe(123); // 値が一致
  });

  // ドキュメント更新テスト
  it('should update the document', async () => {
    const result = await col.updateOne({ name: 'test' }, { $set: { value: 456 } });
    expect(result.modifiedCount).toBe(1); // 1件更新
    const updated = await col.findOne({ name: 'test' });
    expect(updated && updated.value).toBe(456); // 値が更新されていること
  });

  // ドキュメント削除テスト
  it('should delete the document', async () => {
    const result = await col.deleteOne({ name: 'test' });
    expect(result.deletedCount).toBe(1); // 1件削除
    const docs = await col.find({ name: 'test' }).toArray();
    expect(docs.length).toBe(0); // 検索結果が0件
  });
});
