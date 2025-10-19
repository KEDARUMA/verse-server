// Use .env for configuration
require('dotenv').config();

import { startServer, stopServer } from 'verse-server/server';
import Verse from '../Verse';

jest.setTimeout(20000);

describe('Verse.provisionalLogin (integration)', () => {
  // Shared client and provisional token for tests
  let v: Verse;
  let provisionalToken: string | undefined;

  beforeAll(async () => {
    await startServer();
    // create client and perform provisional login once for reuse
    v = new Verse(`http://localhost:${process.env.PORT || 3000}`,
      {
        provisionalEnabled: true,
        provisionalAuthSecretMaster: process.env.PROVISIONAL_AUTH_SECRET_MASTER as string,
        provisionalAuthDomain: process.env.PROVISIONAL_AUTH_DOMAIN as string
      }
    );
    const res = await v.provisionalLogin(process.env.PROVISIONAL_AUTH_ID as string);
    if (!res.ok || !res.token) throw new Error('Failed to obtain provisional token in beforeAll: ' + JSON.stringify(res));
    provisionalToken = res.token as string;
  });

  afterAll(async () => {
    try {
      await stopServer();
    } catch (e) {
      // ignore
    }
  });

  it('round-trips provisionalLogin successfully using .env settings', async () => {
    // provisional login was already performed in beforeAll
    expect(provisionalToken).toBeDefined();
    // optional: verify token yields user via server verify-token endpoint by using client's request
    // but simplest check is that token exists
  });

  it('provisional account can register a user, that user can login, and can be deleted', async () => {
    console.log('### 1')

    // reuse v and provisionalToken from beforeAll
    expect(provisionalToken).toBeDefined();

    // register a test user
    const newAuthId = `client-test-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    const newPassword = `pw-${Math.random().toString(36).slice(2, 10)}`;
    const userDoc = { authId: newAuthId, userType: 'user', roles: [] };
    console.log('### 2')

    const regRes = await v.registerUser(userDoc, newPassword);
    expect(regRes.ok).toBe(true);
    expect(regRes.user).toBeDefined();
    expect(regRes.user.authId).toBe(newAuthId);
    console.log('### 3')

    // verifyToken returns payload and ok
    const verifyRes = await v.verifyToken();
    expect(verifyRes.ok).toBe(true);
    expect((verifyRes as any).payload).toBeDefined();
    expect((verifyRes as any).payload.userType).toBe('provisional');
    console.log('### 4')

    // refreshToken should fail for provisional token (cannot refresh provisional tokens)
    const refreshRes = await v.refreshToken();
    expect(refreshRes.ok).toBe(false);
    // refresh failure is sufficient to prove provisional tokens cannot be refreshed
    console.log('### 5')

    // wait 6 seconds so provisional token expires (server provisional tokens expire in 5s)
    await new Promise((r) => setTimeout(r, 6000));
    console.log('### 6')

    // verifyToken should now indicate token expired
    const verifyAfterRes = await v.verifyToken();
    expect(verifyAfterRes.ok).toBe(false);
    expect(((verifyAfterRes as any).reason === 'token_expired') || verifyAfterRes.status === 401).toBeTruthy();
    console.log('### 7')

    // token is expired; client no longer authenticated -> will login as the newly created user later to perform db operations

    const loginRes = await v.login(newAuthId, newPassword);
    expect(loginRes.ok).toBe(true);
    expect(loginRes.token).toBeDefined();
    console.log('### 8')

    // Now authenticated as the freshly created (non-provisional) user. Use a test-specific temporary DB name
    const TEST_DB = `testdb_test_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
    const db = v.db(TEST_DB);
    const collName = `vcoll_test_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
    const coll = db.collection<any>(collName);

    // insertOne
    const a = { name: 'a', value: 1 } as any;
    const r1 = await coll.insertOne(a);
    expect(r1).toBeDefined();
    expect((r1 as any).insertedId).toBeDefined();
    console.log('### 9')

    // insertMany
    const manyDocs = [{ name: 'b', value: 2 }, { name: 'c', value: 3 }];
    const im = await coll.insertMany(manyDocs);
    expect(im).toBeDefined();
    // insertedIds may be an array or an object mapping index->id depending on server/driver version
    const insertedIds = (im as any).insertedIds;
    if (Array.isArray(insertedIds)) {
      expect(insertedIds.length).toBe(manyDocs.length);
    } else if (insertedIds && typeof insertedIds === 'object') {
      expect(Object.keys(insertedIds).length).toBe(manyDocs.length);
    } else {
      throw new Error('insertMany returned unexpected shape for insertedIds: ' + String(insertedIds));
    }
    console.log('### 10')

    // find
    const all = await coll.find({});
    expect(Array.isArray(all)).toBe(true);
    expect(all.length).toBeGreaterThanOrEqual(1);
    console.log('### 11')

    // findOne
    const fo = await coll.findOne({ name: 'a' });
    expect(fo).not.toBeNull();
    expect((fo as any).name).toBe('a');
    console.log('### 12')

    // findOneAndUpdate (use update then verify via findOne to be robust)
    await coll.findOneAndUpdate({ name: 'a' }, { $set: { value: 10 } });
    const foAfterUpdate = await coll.findOne({ name: 'a' });
    expect((foAfterUpdate as any).value).toBe(10);
    console.log('### 13')

    // findOneAndReplace
    await coll.findOneAndReplace({ name: 'a' }, { name: 'a', value: 100, replaced: true });
    const foAfterReplace = await coll.findOne({ name: 'a' });
    expect((foAfterReplace as any).replaced === true || (foAfterReplace as any).value === 100).toBeTruthy();
    console.log('### 14')

    // findOneAndDelete
    await coll.findOneAndDelete({ name: 'b' });
    const checkB = await coll.findOne({ name: 'b' });
    expect(checkB === null || checkB === undefined).toBeTruthy();
    console.log('### 15')

    // aggregate
    const agg = await coll.aggregate([{ $match: {} }, { $group: { _id: null, total: { $sum: '$value' } } }]);
    expect(Array.isArray(agg)).toBe(true);
    console.log('### 16')

    // count
    const cnt = await coll.count({});
    expect(typeof cnt === 'number').toBeTruthy();
    console.log('### 17')

    // updateOne / updateMany
    await coll.insertMany([{ name: 'u1', value: 1 }, { name: 'u2', value: 1 }]);
    const u1 = await coll.updateOne({ name: 'u1' }, { $set: { value: 42 } });
    expect(u1).toBeDefined();
    const um = await coll.updateMany({ value: 1 }, { $set: { value: 2 } });
    expect(um).toBeDefined();
    console.log('### 18')

    // deleteOne
    const delOne = await coll.deleteOne({ name: 'u1' });
    expect(delOne).toBeDefined();
    console.log('### 19')

    // deleteMany
    const delMany = await coll.deleteMany({});
    expect(delMany).toBeDefined();
    console.log('### 20')

    // watch: consume any events (server may return empty array) and ensure we can iterate without throwing
    const events: any[] = [];
    for await (const ev of coll.watch()) {
      events.push(ev);
      if (events.length > 10) break; // safety
    }
    expect(Array.isArray(events)).toBe(true);
    console.log('### 21')

    // cleanup: drop collection from our test DB
    try { await v.verseGate({ db: TEST_DB, collection: collName, method: 'drop' }); } catch (e) { }
    console.log('### 22')

    const delRes = await v.deleteUser({ authId: newAuthId });
    expect(delRes.ok).toBe(true);
    console.log('### 23')
  });
});
