/*
Test overview: Integration test for RevlmCollection methods (insert/find/update/delete/aggregate/count).
Start revlm-server, perform provisional login, register user, then exercise all collection methods.
Verify CRUD operations work correctly via /revlm-gate endpoint.
Settings are loaded from __tests__/test.env.
テスト概要: RevlmCollection の各メソッド（insert/find/update/delete/aggregate/count）を統合テスト。
revlm-server を起動、仮ログイン→ユーザ登録→全コレクションメソッドを実行。
/revlm-gate 経由で CRUD 操作が正しく動作するか検証。設定は __tests__/test.env を使用。
*/

import dotenv from 'dotenv';
import path from 'path';
import {
  setupTestEnvironment,
  cleanupTestEnvironment,
  SetupTestEnvironmentResult
} from '@kedaruma/revlm-server/__tests__/setupTestMongo';
import Revlm from '../Revlm';

dotenv.config({ path: path.join(__dirname, 'test.env') });

let testEnv: SetupTestEnvironmentResult;

// Allow longer timeout for integration tests that wait for token expiry
jest.setTimeout(120000);

const TEST_DB = 'testdb';
const COLL_NAME = 'testcoll';

describe('RevlmCollection (integration)', () => {
  let v: Revlm;
  let provisionalToken: string | undefined;

  beforeAll(async () => {
    // Setup test environment (MongoDB + Server)
    // テスト環境をセットアップ（MongoDB + サーバー）
    testEnv = await setupTestEnvironment({
      serverConfig: {
        mongoUri: process.env.MONGO_URI as string,
        usersDbName: process.env.USERS_DB_NAME as string,
        usersCollectionName: process.env.USERS_COLLECTION_NAME as string,
        jwtSecret: process.env.JWT_SECRET as string,
        provisionalLoginEnabled: true,
        provisionalAuthId: process.env.PROVISIONAL_AUTH_ID as string,
        provisionalAuthSecretMaster: process.env.PROVISIONAL_AUTH_SECRET_MASTER as string,
        provisionalAuthDomain: process.env.PROVISIONAL_AUTH_DOMAIN as string,
        refreshSecretSigningKey: process.env.REFRESH_SECRET_SIGNING_KEY as string,
        port: Number(process.env.PORT),
      }
    });

    v = new Revlm(testEnv.serverUrl, {
      provisionalEnabled: true,
      provisionalAuthSecretMaster: process.env.PROVISIONAL_AUTH_SECRET_MASTER as string,
      provisionalAuthDomain: process.env.PROVISIONAL_AUTH_DOMAIN as string,
    });
    // Perform provisional login to obtain token for test setup
    // 仮ログインを実行してテストセットアップ用のトークンを取得
    const res = await v.provisionalLogin(process.env.PROVISIONAL_AUTH_ID as string);
    if (!res.ok || !res.token) throw new Error('Failed to obtain provisional token in beforeAll: ' + JSON.stringify(res));
    provisionalToken = res.token as string;
  });

  afterAll(async () => {
    // attempt to drop the test collection before shutting down
    // シャットダウン前にテストコレクションの削除を試みる
    if (typeof v !== 'undefined' && v) {
      try { await v.revlmGate({ db: TEST_DB, collection: COLL_NAME, method: 'drop' }); } catch (e) { }
    }

    await cleanupTestEnvironment(testEnv);
  });

  // 仮アカウントでユーザー登録→ログイン→RevlmCollection の全メソッドを実行
  it('provisional account can register a user, login, and exercise RevlmCollection methods', async () => {
    // reuse v and provisionalToken from beforeAll
    // beforeAll で取得した v と provisionalToken を再利用
    expect(provisionalToken).toBeDefined();

    // register a test user
    // テストユーザーを登録
    const newAuthId = `client-test-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    const newPassword = `pw-${Math.random().toString(36).slice(2, 10)}`;
    const userDoc = { authId: newAuthId, userType: 'user', roles: [] };

    const regRes = await v.registerUser(userDoc, newPassword);
    expect(regRes.ok).toBe(true);
    expect(regRes.user).toBeDefined();
    expect(regRes.user.authId).toBe(newAuthId);

    // verify provisional token
    // 仮トークンの検証
    const verifyRes = await v.verifyToken();
    expect(verifyRes.ok).toBe(true);

    // refresh should fail for provisional
    // 仮トークンのリフレッシュは失敗するはず
    const refreshRes = await v.refreshToken();
    expect(refreshRes.ok).toBe(false);

    // wait for provisional token expiry
    // 仮トークンの有効期限切れを待つ
    await new Promise((r) => setTimeout(r, 6000));
    const verifyAfterRes = await v.verifyToken();
    expect(verifyAfterRes.ok).toBe(false);

    // login as created user
    // 作成したユーザーでログイン
    const loginRes = await v.login(newAuthId, newPassword);
    expect(loginRes.ok).toBe(true);
    if (loginRes.ok) {
      expect(loginRes.token).toBeDefined();
    }

    // Use a test-specific DB to avoid colliding with other data
    // 他のデータと衝突しないようテスト専用 DB を使用
    const db = v.db(TEST_DB);
    const coll = db.collection<any>(COLL_NAME);

    // insertOne
    // 単一ドキュメントの挿入
    const a = { name: 'a', value: 1 } as any;
    const r1 = await coll.insertOne(a);
    expect(r1).toBeDefined();
    expect((r1 as any).insertedId).toBeDefined();

    // insertMany
    // 複数ドキュメントの挿入
    const manyDocs = [{ name: 'b', value: 2 }, { name: 'c', value: 3 }];
    const im = await coll.insertMany(manyDocs);
    expect(im).toBeDefined();
    const insertedIds = (im as any).insertedIds;
    if (Array.isArray(insertedIds)) {
      expect(insertedIds.length).toBe(manyDocs.length);
    } else if (insertedIds && typeof insertedIds === 'object') {
      expect(Object.keys(insertedIds).length).toBe(manyDocs.length);
    } else {
      throw new Error('insertMany returned unexpected shape for insertedIds: ' + String(insertedIds));
    }

    // find
    // 全ドキュメントの検索
    const all = await coll.find({});
    expect(Array.isArray(all)).toBe(true);
    expect(all.length).toBeGreaterThanOrEqual(1);

    // findOne
    // 単一ドキュメントの検索
    const fo = await coll.findOne({ name: 'a' });
    expect(fo).not.toBeNull();
    expect((fo as any).name).toBe('a');

    // findOneAndUpdate
    // 検索して更新
    await coll.findOneAndUpdate({ name: 'a' }, { $set: { value: 10 } });
    const foAfterUpdate = await coll.findOne({ name: 'a' });
    expect((foAfterUpdate as any).value).toBe(10);

    // findOneAndReplace
    // 検索して置換
    await coll.findOneAndReplace({ name: 'a' }, { name: 'a', value: 100, replaced: true });
    const foAfterReplace = await coll.findOne({ name: 'a' });
    expect((foAfterReplace as any).replaced === true || (foAfterReplace as any).value === 100).toBeTruthy();

    // findOneAndDelete
    // 検索して削除
    await coll.findOneAndDelete({ name: 'b' });
    const checkB = await coll.findOne({ name: 'b' });
    expect(checkB === null || checkB === undefined).toBeTruthy();

    // aggregate
    // 集計クエリ
    const agg = await coll.aggregate([{ $match: {} }, { $group: { _id: null, total: { $sum: '$value' } } }]);
    expect(Array.isArray(agg)).toBe(true);

    // count
    // ドキュメント数のカウント
    const cnt = await coll.count({});
    expect(typeof cnt === 'number').toBeTruthy();

    // updateOne / updateMany
    // 単一／複数ドキュメントの更新
    await coll.insertMany([{ name: 'u1', value: 1 }, { name: 'u2', value: 1 }]);
    const u1 = await coll.updateOne({ name: 'u1' }, { $set: { value: 42 } });
    expect(u1).toBeDefined();
    const um = await coll.updateMany({ value: 1 }, { $set: { value: 2 } });
    expect(um).toBeDefined();

    // deleteOne
    // 単一ドキュメントの削除
    const delOne = await coll.deleteOne({ name: 'u1' });
    expect(delOne).toBeDefined();

    // deleteMany
    // 複数ドキュメントの削除
    const delMany = await coll.deleteMany({});
    expect(delMany).toBeDefined();

    // watch: iterate any available events (server may return empty)
    // watch: 利用可能なイベントを取得（サーバーが空を返す場合あり）
    // const events: any[] = [];
    // for await (const ev of coll.watch()) {
    //   events.push(ev);
    //   if (events.length > 10) break;
    // }
    // expect(Array.isArray(events)).toBe(true);

    // Delete the test user
    // テストユーザーを削除
    const delRes = await v.deleteUser({ authId: newAuthId });
    expect(delRes.ok).toBe(true);
  });
});
