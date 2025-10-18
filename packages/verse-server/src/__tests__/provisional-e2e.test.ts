// E2E-style test: use /provisional-login to obtain a provisional token, wait for it to expire,
// then call /refresh-token and ensure the server rejects refresh with provisional_forbidden.

import request from 'supertest';

// Set environment variables BEFORE requiring the server so module-level constants in server.ts
// (which read process.env at import time) pick them up.
process.env.PROVISIONAL_LOGIN_ENABLED = '1';
process.env.PROVISIONAL_AUTH_ID = process.env.PROVISIONAL_AUTH_ID || 'prov-id-test';
process.env.PROVISIONAL_AUTH_SECRET_MASTER = process.env.PROVISIONAL_AUTH_SECRET_MASTER || 'prov-secret-test';
process.env.PROVISIONAL_AUTH_DOMAIN = process.env.PROVISIONAL_AUTH_DOMAIN || 'prov-domain-test';
process.env.DATA_BASE_NAME = process.env.DATA_BASE_NAME || 'testdb';
process.env.USERS_COLLECTION_NAME = process.env.USERS_COLLECTION_NAME || 'users';
process.env.JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '5s';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
process.env.REFRESH_WINDOW_SEC = process.env.REFRESH_WINDOW_SEC || '300';

// Now require server after envs are set
const { startServer, stopServer } = require('../server');
const { AuthClient } = require('verse-shared/auth-token');

const SERVER_URL = 'http://localhost:' + (process.env.PORT || 3000);

// Allow extra time for waiting token expiry
jest.setTimeout(20000);

let server: any;

beforeAll(async () => {
  server = await startServer();
});

afterAll(async () => {
  await stopServer();
});

describe('/provisional-login -> /refresh-token (E2E)', () => {
  it('provisional token obtained from /provisional-login is not refreshable (provisional_forbidden)', async () => {
    // Produce a PLPA-style password using the shared AuthClient so the server will accept it
    const authClient = new AuthClient({ secretMaster: process.env.PROVISIONAL_AUTH_SECRET_MASTER, authDomain: process.env.PROVISIONAL_AUTH_DOMAIN });
    const password = await authClient.producePassword();

    // Call provisional-login
    const resLogin = await request(SERVER_URL)
      .post('/provisional-login')
      .send({ authId: process.env.PROVISIONAL_AUTH_ID, password });

    expect(resLogin.status).toBe(200);
    expect(resLogin.body).toBeDefined();
    expect(resLogin.body.ok).toBe(true);
    const token = resLogin.body.token;
    expect(token).toBeDefined();

    // Wait for token to expire. server.provisional-login issues token with expiresIn '5s'.
    await new Promise((r) => setTimeout(r, 6000));

    // Attempt to refresh the provisional token
    const resRefresh = await request(SERVER_URL)
      .post('/refresh-token')
      .set('Authorization', `Bearer ${token}`);

    expect(resRefresh.status).toBe(403);
    expect(resRefresh.body).toBeDefined();
    expect(resRefresh.body.ok).toBe(false);
    expect(resRefresh.body.reason).toBe('provisional_forbidden');
  });
});

