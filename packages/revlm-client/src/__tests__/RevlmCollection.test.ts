// Use .env for configuration
require('dotenv').config();

import { startServer, stopServer } from 'revlm-server/server';
import Revlm from '../Revlm';

// Allow longer timeout for integration tests that wait for token expiry
jest.setTimeout(120000);

const TEST_DB = 'testdb';
const COLL_NAME = 'testcoll';

describe('RevlmCollection (integration)', () => {
  let v: Revlm;
  let provisionalToken: string | undefined;

  beforeAll(async () => {
    await startServer();
    v = new Revlm(`http://localhost:${process.env.PORT || 3000}`, {
      provisionalEnabled: true,
      provisionalAuthSecretMaster: process.env.PROVISIONAL_AUTH_SECRET_MASTER as string,
      provisionalAuthDomain: process.env.PROVISIONAL_AUTH_DOMAIN as string,
    });
    const res = await v.provisionalLogin(process.env.PROVISIONAL_AUTH_ID as string);
    if (!res.ok || !res.token) throw new Error('Failed to obtain provisional token in beforeAll: ' + JSON.stringify(res));
    provisionalToken = res.token as string;
  });

  afterAll(async () => {
    // attempt to drop the test collection before shutting down
    if (typeof v !== 'undefined' && v) {
      try { await v.revlmGate({ db: TEST_DB, collection: COLL_NAME, method: 'drop' }); } catch (e) { }
    }

    try { await stopServer(); } catch (e) { }
  });

  it('provisional account can register a user, login, and exercise RevlmCollection methods', async () => {
    // reuse v and provisionalToken from beforeAll
    expect(provisionalToken).toBeDefined();

    // register a test user
    const newAuthId = `client-test-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    const newPassword = `pw-${Math.random().toString(36).slice(2, 10)}`;
    const userDoc = { authId: newAuthId, userType: 'user', roles: [] };

    const regRes = await v.registerUser(userDoc, newPassword);
    expect(regRes.ok).toBe(true);
    expect(regRes.user).toBeDefined();
    expect(regRes.user.authId).toBe(newAuthId);

    // verify provisional token
    const verifyRes = await v.verifyToken();
    expect(verifyRes.ok).toBe(true);

    // refresh should fail for provisional
    const refreshRes = await v.refreshToken();
    expect(refreshRes.ok).toBe(false);

    // wait for provisional token expiry
    await new Promise((r) => setTimeout(r, 6000));
    const verifyAfterRes = await v.verifyToken();
    expect(verifyAfterRes.ok).toBe(false);

    // login as created user
    const loginRes = await v.login(newAuthId, newPassword);
    expect(loginRes.ok).toBe(true);
    expect(loginRes.token).toBeDefined();

    // Use a test-specific DB to avoid colliding with other data
    const db = v.db(TEST_DB);
    const coll = db.collection<any>(COLL_NAME);

    // insertOne
    const a = { name: 'a', value: 1 } as any;
    const r1 = await coll.insertOne(a);
    expect(r1).toBeDefined();
    expect((r1 as any).insertedId).toBeDefined();

    // insertMany
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
    const all = await coll.find({});
    expect(Array.isArray(all)).toBe(true);
    expect(all.length).toBeGreaterThanOrEqual(1);

    // findOne
    const fo = await coll.findOne({ name: 'a' });
    expect(fo).not.toBeNull();
    expect((fo as any).name).toBe('a');

    // findOneAndUpdate
    await coll.findOneAndUpdate({ name: 'a' }, { $set: { value: 10 } });
    const foAfterUpdate = await coll.findOne({ name: 'a' });
    expect((foAfterUpdate as any).value).toBe(10);

    // findOneAndReplace
    await coll.findOneAndReplace({ name: 'a' }, { name: 'a', value: 100, replaced: true });
    const foAfterReplace = await coll.findOne({ name: 'a' });
    expect((foAfterReplace as any).replaced === true || (foAfterReplace as any).value === 100).toBeTruthy();

    // findOneAndDelete
    await coll.findOneAndDelete({ name: 'b' });
    const checkB = await coll.findOne({ name: 'b' });
    expect(checkB === null || checkB === undefined).toBeTruthy();

    // aggregate
    const agg = await coll.aggregate([{ $match: {} }, { $group: { _id: null, total: { $sum: '$value' } } }]);
    expect(Array.isArray(agg)).toBe(true);

    // count
    const cnt = await coll.count({});
    expect(typeof cnt === 'number').toBeTruthy();

    // updateOne / updateMany
    await coll.insertMany([{ name: 'u1', value: 1 }, { name: 'u2', value: 1 }]);
    const u1 = await coll.updateOne({ name: 'u1' }, { $set: { value: 42 } });
    expect(u1).toBeDefined();
    const um = await coll.updateMany({ value: 1 }, { $set: { value: 2 } });
    expect(um).toBeDefined();

    // deleteOne
    const delOne = await coll.deleteOne({ name: 'u1' });
    expect(delOne).toBeDefined();

    // deleteMany
    const delMany = await coll.deleteMany({});
    expect(delMany).toBeDefined();

    // watch: iterate any available events (server may return empty)
    // const events: any[] = [];
    // for await (const ev of coll.watch()) {
    //   events.push(ev);
    //   if (events.length > 10) break;
    // }
    // expect(Array.isArray(events)).toBe(true);

    const delRes = await v.deleteUser({ authId: newAuthId });
    expect(delRes.ok).toBe(true);
  });
});
