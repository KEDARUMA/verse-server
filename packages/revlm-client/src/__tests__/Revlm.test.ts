// Use .env for configuration
require('dotenv').config();

import { startServer, stopServer } from 'revlm-server/server';
import Revlm from '../Revlm';

jest.setTimeout(20000);

describe('Revlm.provisionalLogin (integration)', () => {
  // Shared client and provisional token for tests
  let v: Revlm;
  let provisionalToken: string | undefined;

  beforeAll(async () => {
    await startServer();
    // create client and perform provisional login once for reuse
    v = new Revlm(`http://localhost:${process.env.PORT || 3000}`,
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
    const refreshRes = await v.refreshToken();
    expect(refreshRes.ok).toBe(false);
    // refresh failure is sufficient to prove provisional tokens cannot be refreshed

    // wait 6 seconds so provisional token expires (server provisional tokens expire in 5s)
    await new Promise((r) => setTimeout(r, 6000));

    // verifyToken should now indicate token expired
    const verifyAfterRes = await v.verifyToken();
    expect(verifyAfterRes.ok).toBe(false);
    expect(((verifyAfterRes as any).reason === 'token_expired') || verifyAfterRes.status === 401).toBeTruthy();

    const loginRes = await v.login(newAuthId, newPassword);
    expect(loginRes.ok).toBe(true);
    expect(loginRes.token).toBeDefined();

    const delRes = await v.deleteUser({ authId: newAuthId });
    expect(delRes.ok).toBe(true);
  });
});
