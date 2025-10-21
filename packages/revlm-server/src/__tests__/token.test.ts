import request from 'supertest';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { startServer, stopServer } from '../server';

dotenv.config();

const SERVER_URL = 'http://localhost:' + (process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
const REFRESH_WINDOW_SEC = Number(process.env.REFRESH_WINDOW_SEC ?? '300');

let server: any;

beforeAll(async () => {
  server = await startServer();
});

afterAll(async () => {
  await stopServer();
});

describe('/verify-token', () => {
  it('returns payload for valid token', async () => {
    const token = jwt.sign({ foo: 'bar' }, JWT_SECRET, { expiresIn: '1h' });
    const res = await request(SERVER_URL).post('/verify-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.payload).toBeDefined();
    expect(res.body.payload.foo).toBe('bar');
  });

  it('returns token_expired for expired token', async () => {
    const payload = { foo: 'baz', exp: Math.floor(Date.now() / 1000) - 10 };
    const token = jwt.sign(payload as any, JWT_SECRET);
    const res = await request(SERVER_URL).post('/verify-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
    expect(res.body.ok).toBe(false);
    expect(res.body.reason).toBe('token_expired');
  });

  it('returns invalid_token for malformed token', async () => {
    const res = await request(SERVER_URL).post('/verify-token').set('Authorization', `Bearer invalid.token.here`);
    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.reason).toBe('invalid_token');
  });
});

describe('/refresh-token', () => {
  it('refreshes an expired non-provisional token within window', async () => {
    const payload = { userId: 'u1', roles: ['a'], exp: Math.floor(Date.now() / 1000) - 10 };
    const token = jwt.sign(payload as any, JWT_SECRET);
    const res = await request(SERVER_URL).post('/refresh-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.token).toBeDefined();
    // new token should be valid
    const verify = await request(SERVER_URL).post('/verify-token').set('Authorization', `Bearer ${res.body.token}`);
    expect(verify.status).toBe(200);
    expect(verify.body.ok).toBe(true);
  });

  it('rejects refresh when token is not expired', async () => {
    const token = jwt.sign({ foo: 'x' }, JWT_SECRET, { expiresIn: '1h' });
    const res = await request(SERVER_URL).post('/refresh-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
    expect(res.body.reason).toBe('not_expired');
  });

  it('rejects provisional tokens even if expired', async () => {
    const payload = { userType: 'provisional', exp: Math.floor(Date.now() / 1000) - 10 };
    const token = jwt.sign(payload as any, JWT_SECRET);
    const res = await request(SERVER_URL).post('/refresh-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.reason).toBe('provisional_forbidden');
  });

  it('rejects refresh beyond grace window', async () => {
    const old = Math.floor(Date.now() / 1000) - (REFRESH_WINDOW_SEC + 10);
    const payload = { userId: 'u2', exp: old };
    const token = jwt.sign(payload as any, JWT_SECRET);
    const res = await request(SERVER_URL).post('/refresh-token').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.reason).toBe('refresh_window_exceeded');
  });
});

