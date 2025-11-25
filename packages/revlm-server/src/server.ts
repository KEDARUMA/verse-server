import type { Request, Response, NextFunction } from 'express';
import { User } from '@kedaruma/revlm-shared/models/user-types';
import { AuthServer } from '@kedaruma/revlm-shared/auth-token';
import type { MongoClient as MongoClientType } from 'mongodb';
const express = require('express');
const cors = require('cors');
import { MongoClient } from 'mongodb';
import { ObjectId, EJSON } from 'bson';
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
import type { ObjectId as ObjectIdType } from 'bson';
import http from "http";
import { ensureDefined } from '@kedaruma/revlm-shared/utils/asserts';

const app = express();
app.use(cors());
app.use(express.text({ type: 'application/ejson' }));
app.use(express.json());

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
}

const serverConfigDefaults: Partial<ServerConfig> = {
  provisionalLoginEnabled: false,
  jwtExpiresIn: '1h',
  refreshWindowSec: 300
};

let serverConfig: ServerConfig | undefined;
let plpaServer: AuthServer | undefined;
let JWT_SECRET: string | undefined;
let JWT_EXPIRES_IN: string | undefined;
let REFRESH_WINDOW_SEC: number | undefined;
let PROVISIONAL_LOGIN_ENABLED: boolean | undefined;
let PROVISIONAL_AUTH_ID: string | undefined;
let PROVISIONAL_AUTH_SECRET_MASTER: string | undefined;
let PROVISIONAL_AUTH_DOMAIN: string | undefined;
let USERS_DB_NAME: string | undefined;
let USERS_COLLECTION: string | undefined;
let MONGO_URI: string | undefined;
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
  if (explicitlyWantsEjson) {
    res.type('application/ejson').send(EJSON.stringify(obj));
  } else {
    res.json(obj);
  }
}

function verifyToken(req: Request, res: Response, next: NextFunction) {
  const header = req.headers['authorization'] as string | undefined;
  const token = header && header.split(' ')[1];
  if (!token) return sendResponse(req, res, { ok: false, error: 'No token provided' }, 401);
  const result = verifyJwtToken(token);
  if (!result.ok) {
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
    return { ok: false, reason: 'invalid_token' };
  }
}

// Helper: refresh an expired JWT within a grace window. Does not refresh provisional tokens.
function refreshJwtToken(token: string): { ok: true; token: string; expiresIn: string } | { ok: false, reason: 'not_expired' | 'invalid_token' | 'provisional_forbidden' | 'refresh_window_exceeded' } {
  ensureStarted();
  // If token is still valid, don't refresh
  try {
    jwt.verify(token, JWT_SECRET as string);
    return { ok: false, reason: 'not_expired' };
  } catch (err: any) {
    console.log('refreshJwtToken verify error - Error name:', err && err.name, 'Error message:', err && err.message);
    if (!err || err.name !== 'TokenExpiredError') return { ok: false, reason: 'invalid_token' };
    // Token expired — verify signature ignoring expiration
    let payload: any;
    try {
      payload = jwt.verify(token, JWT_SECRET as string, { ignoreExpiration: true });
    } catch (_e: any) {
      console.log('refreshJwtToken ignoreExpiration verify error - Error name:', _e && _e.name, 'Error message:', _e && _e.message);
      return { ok: false, reason: 'invalid_token' };
    }
    // Do not refresh provisional tokens
    if (payload && payload.userType === 'provisional') return { ok: false, reason: 'provisional_forbidden' };
    // Check expiry field and grace window
    const exp = payload && payload.exp ? Number(payload.exp) : undefined;
    if (!exp) return { ok: false, reason: 'invalid_token' };
    const now = Math.floor(Date.now() / 1000);
    const refreshWindow = REFRESH_WINDOW_SEC as number;
    if (now - exp > refreshWindow) return { ok: false, reason: 'refresh_window_exceeded' };
    // Remove iat/exp/nbf before signing new token
    const { iat, exp: _exp, nbf, ...rest } = payload as any;
    const expiresIn = JWT_EXPIRES_IN as string;
    const newToken = jwt.sign(rest, JWT_SECRET as string, { expiresIn });
    return { ok: true, token: newToken, expiresIn };
  }
}

// Endpoint: token verification API
app.post('/verify-token', (req: Request, res: Response) => {
  const header = req.headers['authorization'] as string | undefined;
  const tokenFromHeader = header && header.split(' ')[1];
  const token = (req.body && req.body.token) || tokenFromHeader;
  if (!token) return sendResponse(req, res, { ok: false, reason: 'no_token' }, 400);
  const result = verifyJwtToken(token);
  if (result.ok) return sendResponse(req, res, { ok: true, payload: result.payload }, 200);
  const reason = (result as any).reason;
  if (reason === 'token_expired') return sendResponse(req, res, { ok: false, reason: 'token_expired' }, 401);
  return sendResponse(req, res, { ok: false, reason: 'invalid_token' }, 403);
});

// Endpoint: refresh an expired token within grace window
app.post('/refresh-token', (req: Request, res: Response) => {
  const header = req.headers['authorization'] as string | undefined;
  const tokenFromHeader = header && header.split(' ')[1];
  const token = (req.body && req.body.token) || tokenFromHeader;
  if (!token) return sendResponse(req, res, { ok: false, reason: 'no_token' }, 400);
  const result = refreshJwtToken(token);
  if (result.ok) return sendResponse(req, res, { ok: true, token: result.token, expiresIn: result.expiresIn }, 200);
  // Map reasons to status
  switch ((result as any).reason) {
    case 'not_expired':
      return sendResponse(req, res, { ok: false, reason: 'not_expired' }, 400);
    case 'provisional_forbidden':
      return sendResponse(req, res, { ok: false, reason: 'provisional_forbidden' }, 403);
    case 'refresh_window_exceeded':
      return sendResponse(req, res, { ok: false, reason: 'refresh_window_exceeded' }, 403);
    default:
      return sendResponse(req, res, { ok: false, reason: 'invalid_token' }, 403);
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

  // filter undefined values so defaults are preserved
  const filteredConfig: Partial<ServerConfig> = Object.fromEntries(Object.entries(config).filter(([, v]) => v !== undefined)) as Partial<ServerConfig>;
  const merged: ServerConfig = { ...(serverConfigDefaults as Partial<ServerConfig>), ...filteredConfig } as ServerConfig;

  // required checks
  if (!merged.mongoUri) throw new Error('mongoUri is required in ServerConfig');
  if (!merged.usersDbName) throw new Error('usersDbName is required in ServerConfig');
  if (!merged.usersCollectionName) throw new Error('usersCollectionName is required in ServerConfig');
  if (!merged.jwtSecret) throw new Error('jwtSecret is required in ServerConfig');

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
      if (!user || !user.passwordHash) return sendResponse(req, res, { ok: false, error: 'Authentication failed' }, 401);
      const valid = await bcrypt.compare(password, user.passwordHash);
      if (!valid) return sendResponse(req, res, { ok: false, error: 'Authentication failed' }, 401);
      const { _id, userType, roles, merchantId } = user;
      const token = jwt.sign({ _id, userType, roles, merchantId }, JWT_SECRET as string, { expiresIn: JWT_EXPIRES_IN as string });
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
