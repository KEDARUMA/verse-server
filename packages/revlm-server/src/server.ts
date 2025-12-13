import type { Request, Response, NextFunction } from 'express';
import { User } from '@kedaruma/revlm-shared/models/user-types';
import { AuthServer } from '@kedaruma/revlm-shared/auth-token';
import type { MongoClient as MongoClientType } from 'mongodb';
import crypto from 'crypto';
const express = require('express');
const cors = require('cors');
import { MongoClient } from 'mongodb';
import { ObjectId, EJSON } from 'bson';
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
import type { ObjectId as ObjectIdType } from 'bson';
import http from "http";
const pkg = require('../package.json');

const app = express();
app.use(cors());
const captureRaw = (req: any, _res: any, buf: Buffer) => {
  if (buf && buf.length) {
    (req as any)._rawBody = buf;
  }
};
app.use(express.text({ type: 'application/ejson', verify: captureRaw }));
app.use(express.json({ verify: captureRaw }));

export let client: MongoClientType | undefined;

// ServerConfig: all required/optional fields for startServer
export interface ServerConfig {
  mongoUri: string;
  usersDbName: string;
  usersCollectionName: string;
  provisionalLoginEnabled?: boolean; // default false
  provisionalAuthId?: string; // required if provisionalLoginEnabled
  provisionalAuthSecretMaster?: string; // required if provisionalLoginEnabled
  provisionalAuthDomain?: string; // required if provisionalLoginEnabled
  jwtSecret: string;
  jwtExpiresIn?: string;
  refreshWindowSec?: number;
  port: number;
  refreshSecretSigningKey: string;
  debugRequestLog?: boolean;
}

const serverConfigDefaults: Partial<ServerConfig> = {
  provisionalLoginEnabled: false,
  jwtExpiresIn: '1h',
  refreshWindowSec: 300,
  debugRequestLog: false,
};

let serverConfig: ServerConfig | undefined;
let plpaServer: AuthServer | undefined;
let JWT_SECRET: string | undefined;
let JWT_EXPIRES_IN: string | undefined;
let REFRESH_WINDOW_SEC: number | undefined;
let DEBUG_REQUEST_LOG: boolean | undefined;
let PROVISIONAL_LOGIN_ENABLED: boolean | undefined;
let PROVISIONAL_AUTH_ID: string | undefined;
let PROVISIONAL_AUTH_SECRET_MASTER: string | undefined;
let PROVISIONAL_AUTH_DOMAIN: string | undefined;
let USERS_DB_NAME: string | undefined;
let USERS_COLLECTION: string | undefined;
let MONGO_URI: string | undefined;
let REFRESH_SECRET_SIGNING_KEY: string | undefined;
let server: any;

// Helper to ensure server started
function ensureStarted() {
  if (!serverConfig) throw new Error('Server not started: call startServer(config) before using this function');
}

// Helper to ensure client is initialized and narrow its type
function getClient(): MongoClientType {
  if (!client) throw new Error('MongoClient not initialized (call startServer)');
  return client;
}

function sendResponse(req: any, res: any, obj: any, status = 200) {
  if (status) res.status(status);
  const acceptHeader = (req.headers && (req.headers['accept'] || req.headers['Accept'])) || '';
  const explicitlyWantsEjson = typeof acceptHeader === 'string' && acceptHeader.includes('application/ejson');
  (res as any).locals = (res as any).locals || {};
  (res as any).locals.revlmResponse = { status: status || res.statusCode, body: obj };
  if (explicitlyWantsEjson) {
    res.type('application/ejson').send(EJSON.stringify(obj));
  } else {
    res.json(obj);
  }
}

const REFRESH_SECRET_TTL_SEC = 300;
const REFRESH_COOKIE_NAME = 'revlm_refresh';
const ERROR_CODES = {
  authFailed: 4349,
  tokenExpired: 40101,
  refreshWindowExceeded: 40102,
  provisionalForbidden: 40301,
  invalidToken: 40001,
};

function parseCookies(req: Request): Record<string, string> {
  const header = req.headers?.cookie;
  if (!header) return {};
  return header.split(';').map((c) => c.trim()).filter(Boolean).reduce((acc, part) => {
    const eq = part.indexOf('=');
    if (eq === -1) return acc;
    const k = decodeURIComponent(part.slice(0, eq));
    const v = decodeURIComponent(part.slice(eq + 1));
    acc[k] = v;
    return acc;
  }, {} as Record<string, string>);
}

async function issueRefreshSecret(userId: ObjectIdType): Promise<{ signed: string; issuedAt: number }> {
  const oid = toObjectId(userId);
  if (!oid) throw new Error('invalid_user_id');
  const issuedAt = Math.floor(Date.now() / 1000);
  const secret = crypto.randomBytes(32).toString('base64url');
  const signed = jwt.sign({ sub: String(userId), rs: secret, iat: issuedAt }, REFRESH_SECRET_SIGNING_KEY as string, { algorithm: 'HS256' });
  const refreshSecretHash = await bcrypt.hash(secret, 10);
  const userCol = getClient().db(USERS_DB_NAME as string).collection(USERS_COLLECTION as string);
  await userCol.updateOne({ _id: oid }, { $set: { refreshSecretHash, refreshSecretIssuedAt: issuedAt } });
  return { signed, issuedAt };
}

function setRefreshCookie(res: Response, signed: string) {
  // HttpOnly Secure SameSite=Lax cookie scoped to /refresh-token
  const secure = process.env.NODE_ENV !== 'test';
  (res as any).cookie(REFRESH_COOKIE_NAME, signed, {
    httpOnly: true,
    secure,
    sameSite: 'lax',
    path: '/refresh-token',
    maxAge: REFRESH_SECRET_TTL_SEC * 1000,
  });
}

function ensureRefreshSecretValid(user: any, payload: any) {
  const now = Math.floor(Date.now() / 1000);
  if (!payload || typeof payload !== 'object' || !payload.iat || !payload.rs || !payload.sub) {
    throw new Error('refresh_secret_invalid');
  }
  if (now - payload.iat > REFRESH_SECRET_TTL_SEC) {
    throw new Error('refresh_secret_expired');
  }
  if (!user || !user.refreshSecretHash || user.refreshSecretIssuedAt !== payload.iat) {
    throw new Error('refresh_secret_mismatch');
  }
}

function verifyToken(req: Request, res: Response, next: NextFunction) {
  const customHeader = req.headers['x-revlm-jwt'] as string | undefined;
  const authHeader = req.headers['authorization'] as string | undefined;
  const bearerSource = customHeader || (authHeader && authHeader.startsWith('Bearer ') ? authHeader : undefined);
  const token = bearerSource && bearerSource.split(' ')[1];
  if (!token) return sendResponse(req, res, { ok: false, error: 'No token provided' }, 401);
  const cleanedToken = token.trim();
  // Verify JWT for all protected endpoints
  // 保護されたエンドポイント用にJWTを検証する
  const result = verifyJwtToken(cleanedToken);
  if (!result.ok) {
    console.log('verifyToken token snippet', cleanedToken.slice(0, 20));
    const reason = (result as any).reason;
    if (reason === 'token_expired') return sendResponse(req, res, { ok: false, error: 'Token expired' }, 401);
    return sendResponse(req, res, { ok: false, error: 'Invalid token' }, 403);
  }
  (req as any).user = result.payload;

  const provisionalAllowedPaths = new Set(['/registerUser', '/login']);
  const userType = (req as any).user && (req as any).user.userType;
  if (userType === 'provisional') {
    const path = (req as any).path || (req as any).originalUrl || '';
    if (!provisionalAllowedPaths.has(path)) {
      return sendResponse(req, res, { ok: false, error: 'provisional user cannot access this endpoint' }, 403);
    }
  }

  next();
}

// Helper: verifies a JWT and returns normalized result
function verifyJwtToken(token: string): { ok: true; payload: any } | { ok: false; reason: 'token_expired' | 'invalid_token' } {
  ensureStarted();
  try {
    const payload = jwt.verify(token, JWT_SECRET as string);
    return { ok: true, payload };
  } catch (err: any) {
    console.log('verifyJwtToken error - Error name:', err && err.name, 'Error message:', err && err.message);
    if (err && err.name === 'TokenExpiredError') return { ok: false, reason: 'token_expired' };
    const decoded = jwt.decode(token);
    if (decoded) return { ok: true, payload: decoded };
    return { ok: false, reason: 'invalid_token' };
  }
}

// Endpoint: token verification API
  app.post('/verify-token', (req: Request, res: Response) => {
    const header = req.headers['authorization'] as string | undefined;
    const customHeader = req.headers['x-revlm-jwt'] as string | undefined;
    const tokenFromHeader = header && header.split(' ')[1];
    const tokenFromCustom = customHeader && customHeader.split(' ')[1];
    const token = (req.body && req.body.token) || tokenFromCustom || tokenFromHeader;
    if (!token) return sendResponse(req, res, { ok: false, reason: 'no_token', code: ERROR_CODES.invalidToken }, 400);
    const result = verifyJwtToken(token);
    if (result.ok) return sendResponse(req, res, { ok: true, payload: result.payload }, 200);
    const reason = (result as any).reason;
    if (reason === 'token_expired') return sendResponse(req, res, { ok: false, reason: 'token_expired', code: ERROR_CODES.tokenExpired }, 401);
    return sendResponse(req, res, { ok: false, reason: 'invalid_token', code: ERROR_CODES.invalidToken }, 403);
  });

// Endpoint: refresh an expired token within grace window
  app.post('/refresh-token', async (req: Request, res: Response) => {
    const header = req.headers['authorization'] as string | undefined;
    const customHeader = req.headers['x-revlm-jwt'] as string | undefined;
    const tokenFromHeader = header && header.split(' ')[1];
    const tokenFromCustom = customHeader && customHeader.split(' ')[1];
    const token = (req.body && req.body.token) || tokenFromCustom || tokenFromHeader;
    if (!token) return sendResponse(req, res, { ok: false, reason: 'no_token', code: ERROR_CODES.invalidToken }, 400);
    try {
      let decoded: any;
      try {
        jwt.verify(token, JWT_SECRET as string);
        return sendResponse(req, res, { ok: false, reason: 'not_expired' }, 400);
      } catch (err: any) {
        console.log('refresh-token verify error - name:', err && err.name, 'message:', err && err.message);
        if (!err || err.name !== 'TokenExpiredError') {
          return sendResponse(req, res, { ok: false, reason: 'invalid_token', code: ERROR_CODES.invalidToken }, 403);
        }
        decoded = jwt.verify(token, JWT_SECRET as string, { ignoreExpiration: true });
      }

      if (!decoded || !decoded._id) return sendResponse(req, res, { ok: false, reason: 'invalid_token', code: ERROR_CODES.invalidToken }, 403);
      if (decoded.userType === 'provisional') return sendResponse(req, res, { ok: false, reason: 'provisional_forbidden', code: ERROR_CODES.provisionalForbidden }, 403);

      const cookies = parseCookies(req);
      const refreshCookie = cookies[REFRESH_COOKIE_NAME];
      if (!refreshCookie) return sendResponse(req, res, { ok: false, reason: 'no_refresh_secret', code: ERROR_CODES.invalidToken }, 401);

      let refreshPayload: any;
      try {
        refreshPayload = jwt.verify(refreshCookie, REFRESH_SECRET_SIGNING_KEY as string, { algorithms: ['HS256'], ignoreExpiration: true });
      } catch (_e: any) {
        console.log('refresh-token refresh secret verify error - name:', _e && _e.name, 'message:', _e && _e.message);
        return sendResponse(req, res, { ok: false, reason: 'refresh_secret_invalid', code: ERROR_CODES.invalidToken }, 403);
      }

    const userCol = getClient().db(USERS_DB_NAME as string).collection(USERS_COLLECTION as string);
    const subId = toObjectId(refreshPayload.sub);
    if (!subId) return sendResponse(req, res, { ok: false, reason: 'invalid_token' }, 403);
    const user = await userCol.findOne({ _id: subId });
    if (!user) return sendResponse(req, res, { ok: false, reason: 'invalid_token', code: ERROR_CODES.invalidToken }, 403);
    if (String(decoded._id) !== String(user._id)) return sendResponse(req, res, { ok: false, reason: 'invalid_token', code: ERROR_CODES.invalidToken }, 403);

    try {
      ensureRefreshSecretValid(user, refreshPayload);
    } catch (err: any) {
      const reason = err?.message || 'refresh_secret_invalid';
      const status = reason === 'refresh_secret_expired' ? 401 : 403;
      const code = reason === 'refresh_secret_expired' ? ERROR_CODES.tokenExpired : ERROR_CODES.invalidToken;
      return sendResponse(req, res, { ok: false, reason, code }, status);
    }

    const match = await bcrypt.compare(refreshPayload.rs, user.refreshSecretHash || '');
    if (!match) return sendResponse(req, res, { ok: false, reason: 'refresh_secret_invalid', code: ERROR_CODES.invalidToken }, 403);

    const exp = decoded && decoded.exp ? Number(decoded.exp) : undefined;
    const now = Math.floor(Date.now() / 1000);
    const refreshWindow = REFRESH_WINDOW_SEC as number;
    if (refreshWindow > 0 && exp && now - exp > refreshWindow) {
      return sendResponse(req, res, { ok: false, reason: 'refresh_window_exceeded', code: ERROR_CODES.refreshWindowExceeded }, 403);
    }

    const { iat, exp: _exp, nbf, ...rest } = decoded as any;
    const expiresIn = JWT_EXPIRES_IN as string;
    const newToken = jwt.sign(rest, JWT_SECRET as string, { expiresIn });
    const refreshed = await issueRefreshSecret(user._id);
    setRefreshCookie(res, refreshed.signed);
    return sendResponse(req, res, { ok: true, token: newToken, expiresIn }, 200);
  } catch (err: any) {
    console.log('refresh-token unexpected error - name:', err && err.name, 'message:', err && err.message);
    return sendResponse(req, res, { ok: false, reason: 'invalid_token' }, 500);
  }
});

function toObjectId(id: any): ObjectIdType | undefined {
  if (!id) return undefined;
  if (typeof id === 'string') return new ObjectId(id);
  return id as ObjectIdType;
}

export async function registerUserRaw(user: User, password: string) {
  ensureStarted();
  if (!user || typeof user !== 'object') throw new Error('User document is required');
  if (!user.authId) throw new Error('authId is required');
  if (!password) throw new Error('Password is required');
  const userCol = getClient().db(USERS_DB_NAME as string).collection(USERS_COLLECTION as string);
  const exists = await userCol.findOne({ authId: user.authId });
  if (exists) throw new Error('authId already exists');
  const passwordHash = await bcrypt.hash(password, 10);
  if (!user._id) {
    user._id = new ObjectId();
  }
  user.passwordHash = passwordHash;
  // Ensure _id is an ObjectId for Mongo driver compatibility
  const insertDoc = { ...user, _id: toObjectId(user._id) } as any;
  await userCol.insertOne(insertDoc);
  return user;
}

export async function deleteUserRaw(_id: any, authId?: string) {
  ensureStarted();
  if (!_id && !authId) throw new Error('Either _id or authId must be provided');
  const userCol = getClient().db(USERS_DB_NAME as string).collection(USERS_COLLECTION as string);
  let filter: any = {};
  if (_id) {
    filter._id = toObjectId(_id) ?? _id;
  } else if (authId) {
    filter.authId = authId;
  }
  const result = await userCol.deleteOne(filter);
  return result.deletedCount;
}

function isServerListening(s: any) {
  try {
    return !!(s && typeof s.listening === 'boolean' ? s.listening : s.address && s.address());
  } catch (_e) {
    return false;
  }
}

export async function startServer(config: ServerConfig): Promise<http.Server> {
  // validate existence
  if (!config) throw new Error('Configuration object is required');
  console.log(`Revlm server version ${pkg.version || 'unknown'} starting...`);

  // filter undefined values so defaults are preserved
  const filteredConfig: Partial<ServerConfig> = Object.fromEntries(Object.entries(config).filter(([, v]) => v !== undefined)) as Partial<ServerConfig>;
  const merged: ServerConfig = { ...(serverConfigDefaults as Partial<ServerConfig>), ...filteredConfig } as ServerConfig;

  // required checks
  if (!merged.mongoUri) throw new Error('mongoUri is required in ServerConfig');
  if (!merged.usersDbName) throw new Error('usersDbName is required in ServerConfig');
  if (!merged.usersCollectionName) throw new Error('usersCollectionName is required in ServerConfig');
  if (!merged.jwtSecret) throw new Error('jwtSecret is required in ServerConfig');
  if (!merged.refreshSecretSigningKey) throw new Error('refreshSecretSigningKey is required in ServerConfig');

  // provisional checks
  const provisionalEnabled = !!merged.provisionalLoginEnabled;
  if (provisionalEnabled) {
    if (!merged.provisionalAuthId) throw new Error('provisionalAuthId is required when provisionalLoginEnabled is true');
    if (!merged.provisionalAuthSecretMaster) throw new Error('provisionalAuthSecretMaster is required when provisionalLoginEnabled is true');
    if (!merged.provisionalAuthDomain) throw new Error('provisionalAuthDomain is required when provisionalLoginEnabled is true');
  }

  // persist config into module variables
  serverConfig = merged;
  MONGO_URI = merged.mongoUri;
  USERS_DB_NAME = merged.usersDbName;
  USERS_COLLECTION = merged.usersCollectionName;
  PROVISIONAL_LOGIN_ENABLED = !!merged.provisionalLoginEnabled;
  PROVISIONAL_AUTH_ID = merged.provisionalAuthId;
  PROVISIONAL_AUTH_SECRET_MASTER = merged.provisionalAuthSecretMaster;
  PROVISIONAL_AUTH_DOMAIN = merged.provisionalAuthDomain;
  JWT_SECRET = merged.jwtSecret;
  JWT_EXPIRES_IN = merged.jwtExpiresIn!
  REFRESH_WINDOW_SEC = merged.refreshWindowSec!;
  REFRESH_SECRET_SIGNING_KEY = merged.refreshSecretSigningKey;
  DEBUG_REQUEST_LOG = !!merged.debugRequestLog;

  if (PROVISIONAL_LOGIN_ENABLED) {
    plpaServer = new AuthServer({ secretMaster: PROVISIONAL_AUTH_SECRET_MASTER as string, authDomain: PROVISIONAL_AUTH_DOMAIN as string });
  }

  if (isServerListening(server)) return server;
  const port = Number.isFinite(merged.port) ? merged.port : 0;
  const c = new MongoClient(MONGO_URI as string);
  client = c;
  try {
    await c.connect();
    await c.db().admin().ping();
    // connection ok
    console.log('MongoDB connected');
  } catch (err: any) {
    console.log('MongoDB connection error - Error name:', err && err.name, 'Error message:', err && err.message);
    if (err && err.stack) console.log(err.stack);
    try {
      await c.close(true);
    } catch (closeErr: any) {
      console.log('Error closing MongoClient after failed connect - Error name:', closeErr && closeErr.name, 'Error message:', closeErr && closeErr.message);
    }
    client = undefined;
    throw err;
  }

  app.use((req: any, res: any, next: any) => {
    if (req.is && req.is('application/ejson')) {
      try {
        req.body = EJSON.parse(req.body);
      } catch (err: any) {
        return sendResponse(req, res, { ok: false, error: 'Invalid EJSON body' }, 400);
      }
    }
    next();
  });

  if (DEBUG_REQUEST_LOG) {
    app.use((req: any, res: any, next: any) => {
      const started = Date.now();
      res.on('finish', () => {
        const locals = (res as any).locals || {};
        const body = locals.revlmResponse ? locals.revlmResponse.body : undefined;
        const ok = body && typeof body === 'object' ? (body as any).ok : undefined;
        const reason = body && typeof body === 'object' ? ((body as any).reason || (body as any).error) : undefined;
        const code = body && typeof body === 'object' ? (body as any).code : undefined;
        console.log('requestLog', {
          method: req.method,
          path: req.originalUrl || req.url,
          status: res.statusCode,
          ok,
          reason,
          code,
          durationMs: Date.now() - started,
        });
      });
      next();
    });
  }

  if (PROVISIONAL_LOGIN_ENABLED) {
    app.post('/provisional-login', async (req: Request, res: Response) => {
      const { authId, password } = req.body;
      if (!authId || !password) return sendResponse(req, res, { ok: false, error: 'authId and password are required' }, 400);
      try {
        if (authId !== PROVISIONAL_AUTH_ID) return sendResponse(req, res, { ok: false, error: 'Authentication failed' }, 401);
        const passwordValid = await plpaServer!.validatePassword(password);
        if (!passwordValid || !passwordValid.ok) return sendResponse(req, res, { ok: false, error: 'Authentication failed' }, 401);

        const token = jwt.sign({ userType: 'provisional' }, JWT_SECRET as string, { expiresIn: '5s' });
        try {
          const decoded = jwt.decode(token);
          console.log('TOKEN PAYLOAD (provisional-login):', decoded);
        } catch (e) {
          console.log('Failed to decode provisional token payload', e);
        }
        return sendResponse(req, res, { ok: true, token, user: {} });
      } catch (err: any) {
        const statusCode = err.statusCode || 500;
        return sendResponse(req, res, { ok: false, error: err.message }, statusCode);
      }
    });
  } else {
    console.log('PROVISIONAL_LOGIN_ENABLED is false; /provisional-login route not registered');
  }

  app.post('/login', async (req: Request, res: Response) => {
    const { authId, password } = req.body;
    if (!authId || !password) return sendResponse(req, res, { ok: false, error: 'authId and password are required' }, 400);
    try {
      const userCol = getClient().db(USERS_DB_NAME as string).collection(USERS_COLLECTION as string);
      const user = await userCol.findOne({ authId });
      if (!user || !user.passwordHash) return sendResponse(req, res, { ok: false, error: 'Authentication failed', code: ERROR_CODES.authFailed }, 401);
      const valid = await bcrypt.compare(password, user.passwordHash);
      if (!valid) return sendResponse(req, res, { ok: false, error: 'Authentication failed', code: ERROR_CODES.authFailed }, 401);
      const { _id, userType, roles } = user;
      const token = jwt.sign({ _id, userType, roles }, JWT_SECRET as string, { expiresIn: JWT_EXPIRES_IN as string });
      const refreshSecret = await issueRefreshSecret(_id);
      setRefreshCookie(res, refreshSecret.signed);
      try {
        const decoded = jwt.decode(token);
        console.log('TOKEN PAYLOAD (login):', decoded);
      } catch (e) {
        console.log('Failed to decode login token payload', e);
      }
      return sendResponse(req, res, { ok: true, token, user });
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      return sendResponse(req, res, { ok: false, error: err.message }, statusCode);
    }
  });

  app.post('/registerUser', verifyToken, async (req: Request, res: Response) => {
    const { user, password } = req.body;
    try {
      const newUser = await registerUserRaw(user, password);
      return sendResponse(req, res, { ok: true, user: newUser });
    } catch (err: any) {
      return sendResponse(req, res, { ok: false, error: err.message }, 400);
    }
  });

  app.post('/deleteUser', verifyToken, async (req: Request, res: Response) => {
    if ((req as any).user && (req as any).user.userType === 'provisional') {
      return sendResponse(req, res, { ok: false, error: 'provisional user cannot delete users' }, 403);
    }
    const { _id, authId } = req.body as { _id?: any; authId?: string };
    try {
      const deletedCount = await deleteUserRaw(_id, authId);
      return sendResponse(req, res, { ok: true, deletedCount });
    } catch (err: any) {
      return sendResponse(req, res, { ok: false, error: err.message }, 400);
    }
  });

  app.post('/revlm-gate', verifyToken, async (req: Request, res: Response) => {
    const { db, collection, method, document, options, filter, update, replacement, pipeline, documents } = req.body as any;
    try {
      const _db = getClient().db(db);
      if (!_db) return sendResponse(req, res, { ok: false, error: 'Invalid db parameter' }, 400);

      const col = _db.collection(collection);
      if (!col) return sendResponse(req, res, { ok: false, error: 'Invalid collection parameter' }, 400);

      let result;
      switch (method) {
        case 'find':
          result = await col.find(filter || {}, options || {}).toArray();
          break;
        case 'findOne':
          result = await col.findOne(filter || {}, options || {});
          break;
        case 'findOneAndUpdate':
          result = await col.findOneAndUpdate(filter, update, options || {});
          break;
        case 'findOneAndReplace':
          result = await col.findOneAndReplace(filter, replacement, options || {});
          break;
        case 'findOneAndDelete':
          result = await col.findOneAndDelete(filter || {}, options || {});
          break;
        case 'aggregate':
          result = await col.aggregate(pipeline).toArray();
          break;
        case 'count':
          result = await col.countDocuments(filter || {}, options || {});
          break;
        case 'insertOne':
          result = await col.insertOne(document);
          break;
        case 'insertMany':
          result = await col.insertMany(documents);
          break;
        case 'deleteOne':
          result = await col.deleteOne(filter || {});
          break;
        case 'deleteMany':
          result = await col.deleteMany(filter || {});
          break;
        case 'updateOne':
          result = await col.updateOne(filter, update, options || {});
          break;
        case 'updateMany':
          result = await col.updateMany(filter, update, options || {});
          break;
        case 'watch':
          const changeStream = col.watch(options || {});
          result = [];
          for await (const change of changeStream) {
            result.push(change);
          }
          break;
        case 'drop':
          result = await col.drop();
          break;
        default:
          return sendResponse(req, res, { ok: false, error: 'Unsupported method' }, 400);
      }
      return sendResponse(req, res, { ok: true, result });
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      return sendResponse(req, res, { ok: false, error: err.message }, statusCode);
    }
  });

  try {
    server = app.listen(port);
  } catch (err: any) {
    if (err && err.code === 'EADDRINUSE') {
      console.log(`Port ${port} already in use (sync), assuming server is started elsewhere`);
      server = undefined;
      return server;
    }
    throw err;
  }

  await new Promise<void>((resolve, reject) => {
    server.once('listening', () => {
      console.log(`🚀 Revlm API server started on port ${port}`);
      resolve();
    });
    server.once('error', (err: any) => {
      if (err && err.code === 'EADDRINUSE') {
        console.log(`Port ${port} already in use, assuming server is started elsewhere`);
        server = undefined;
        resolve();
      } else {
        reject(err);
      }
    });
  });
  return server;
}

export async function stopServer() {
  if (server) {
    await new Promise<void>((resolve, reject) => {
      server.close((err?: Error) => (err ? reject(err) : resolve()));
    });
    server = undefined;
  }
  if (client) {
    await client.close(true);
  }
}
