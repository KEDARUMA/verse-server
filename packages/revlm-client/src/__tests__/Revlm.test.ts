/*
Test overview: An integration test covering the flow from provisionalLogin through register → login → delete.
Start revlm-server and validate by calling real HTTP endpoints from the client.
Confirm verifyToken succeeds, refreshToken fails for a provisional token, and the provisional token expires as expected.
Settings are loaded from tests/test.env.
テスト概要: provisionalLogin を起点に、登録→ログイン→削除までの一連を統合テスト。
revlm-server を立ち上げ、client で実エンドポイントを叩いて検証。
verifyToken で有効を確認、仮アカウントのトークン refreshToken が失敗する事を確認、仮アカウントのトークン期限切れ確認。
設定は __tests__/test.env を使用。
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

jest.setTimeout(20000);

// provisionalLogin の結合テスト
describe('Revlm.provisionalLogin (integration)', () => {
  // Shared client and provisional token for tests
  let v: Revlm;
  let provisionalToken: string | undefined;

  beforeAll(async () => {
    // テスト環境をセットアップ (MongoDB + サーバー)
    // Setup test environment (MongoDB + Server)
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
        port: Number(process.env.PORT),
      }
    });

    // create client and perform provisional login once for reuse
    v = new Revlm(testEnv.serverUrl,
      {
        provisionalEnabled: true,
        provisionalAuthSecretMaster: process.env.PROVISIONAL_AUTH_SECRET_MASTER as string,
        provisionalAuthDomain: process.env.PROVISIONAL_AUTH_DOMAIN as string,
        autoRefreshOn401: process.env.AUTO_REFRESH_ON_401 === 'true'
      }
    );
    const res = await v.provisionalLogin(process.env.PROVISIONAL_AUTH_ID as string);
    if (!res.ok || !res.token) throw new Error('Failed to obtain provisional token in beforeAll: ' + JSON.stringify(res));
    provisionalToken = res.token as string;
  });

  afterAll(async () => {
    await cleanupTestEnvironment(testEnv);
  });

  // provisionalLogin の結合テストが成功するか確認する
  it('round-trips provisionalLogin successfully using .env settings', async () => {
    // provisional login was already performed in beforeAll
    // provisional login はすでに beforeAll で実行済み
    expect(provisionalToken).toBeDefined();
  });

  // 仮アカウントはユーザー登録ができ、そのユーザーはログインでき、削除もできる。
  it('provisional account can register a user, that user can login, and can be deleted', async () => {
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

    // verifyToken returns payload and ok
    const verifyRes = await v.verifyToken();
    expect(verifyRes.ok).toBe(true);
    expect((verifyRes as any).payload).toBeDefined();
    expect((verifyRes as any).payload.userType).toBe('provisional');

    // refreshToken should fail for provisional token (cannot refresh provisional tokens)
    // refreshToken は仮トークンでは失敗するはず（仮トークンは更新できない）
    const refreshRes = await v.refreshToken();
    expect(refreshRes.ok).toBe(false);
    // refresh failure is sufficient to prove provisional tokens cannot be refreshed
    // リフレッシュ失敗は、仮トークンが更新できないことを証明するのに十分

    // wait 6 seconds so provisional token expires (server provisional tokens expire in 5s)
    // 6秒待って、仮トークンの有効期限切れを待つ（サーバー側の仮トークン有効期限は5秒）
    await new Promise((r) => setTimeout(r, 6000));

    // verifyToken should now indicate token expired
    // verifyToken は、トークンの有効期限切れを示すべき
    const verifyAfterRes = await v.verifyToken();
    expect(verifyAfterRes.ok).toBe(false);
    expect(((verifyAfterRes as any).reason === 'token_expired') || verifyAfterRes.status === 401).toBeTruthy();

    const loginRes = await v.login(newAuthId, newPassword);
    expect(loginRes.ok).toBe(true);
    if (loginRes.ok) {
      expect(loginRes.token).toBeDefined();
    }

    const delRes = await v.deleteUser({ authId: newAuthId });
    expect(delRes.ok).toBe(true);
  });
});
