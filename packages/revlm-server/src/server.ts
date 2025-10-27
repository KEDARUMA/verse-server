import type { Request, Response, NextFunction } from 'express';
import { User } from '@kedaruma/revlm-shared/models/user-types';
import { AuthServer } from '@kedaruma/revlm-shared/auth-token';
import type { MongoClient as MongoClientType } from 'mongodb';
const express = require('express');
const dotenv = require('dotenv');
const { MongoClient } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
import type { ObjectId as ObjectIdType } from 'bson';
const { ObjectId, EJSON } = require('bson');
import { ensureDefined } from '@kedaruma/revlm-shared/utils/asserts';

dotenv.config();

const app = express();
app.use(express.text({ type: 'application/ejson' }));
app.use(express.json());

export let client: MongoClientType | undefined;

const MONGO_URI = ensureDefined(process.env.MONGO_URI, 'Environment variable MONGO_URI is required but was not set');
const USERS_DB_NAME = ensureDefined(process.env.USERS_DB_NAME, 'Environment variable USERS_DB_NAME is required but was not set');
const USERS_COLLECTION = ensureDefined(process.env.USERS_COLLECTION_NAME, 'Environment variable USERS_COLLECTION_NAME is required but was not set');
const PROVISIONAL_LOGIN_ENABLED =
  process.env.PROVISIONAL_LOGIN_ENABLED === 'true' ||
  process.env.PROVISIONAL_LOGIN_ENABLED === '1';
const PROVISIONAL_AUTH_ID = ensureDefined(process.env.PROVISIONAL_AUTH_ID, 'Environment variable PROVISIONAL_AUTH_ID is required but was not set');
const PROVISIONAL_AUTH_SECRET_MASTER = ensureDefined(process.env.PROVISIONAL_AUTH_SECRET_MASTER, 'Environment variable PROVISIONAL_AUTH_SECRET_MASTER is required but was not set');
const PROVISIONAL_AUTH_DOMAIN = ensureDefined(process.env.PROVISIONAL_AUTH_DOMAIN, 'Environment variable PROVISIONAL_AUTH_DOMAIN is required but was not set');
const JWT_EXPIRES_IN = ensureDefined(process.env.JWT_EXPIRES_IN, 'Environment variable JWT_EXPIRES_IN is required but was not set');
// Refresh window in seconds (env REFRESH_WINDOW_SEC), default 300s if not set
const REFRESH_WINDOW_SEC = Number(process.env.REFRESH_WINDOW_SEC ?? '300');

const plpaServer = new AuthServer({ secretMaster: PROVISIONAL_AUTH_SECRET_MASTER, authDomain: PROVISIONAL_AUTH_DOMAIN });

// Helper to ensure client is initialized and narrow its type
function getClient(): MongoClientType {
  if (!client) throw new Error('MongoClient not initialized');
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
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    return { ok: true, payload };
  } catch (err: any) {
    if (err && err.name === 'TokenExpiredError') return { ok: false, reason: 'token_expired' };
    return { ok: false, reason: 'invalid_token' };
  }
}

// Helper: refresh an expired JWT within a grace window. Does not refresh provisional tokens.
function refreshJwtToken(token: string): { ok: true; token: string; expiresIn: string } | { ok: false; reason: 'not_expired' | 'invalid_token' | 'provisional_forbidden' | 'refresh_window_exceeded' } {
  // If token is still valid, don't refresh
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    return { ok: false, reason: 'not_expired' };
  } catch (err: any) {
    if (!err || err.name !== 'TokenExpiredError') return { ok: false, reason: 'invalid_token' };
    // Token expired — verify signature ignoring expiration
    let payload: any;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: true });
    } catch (_e) {
      return { ok: false, reason: 'invalid_token' };
    }
    // Do not refresh provisional tokens
    if (payload && payload.userType === 'provisional') return { ok: false, reason: 'provisional_forbidden' };
    // Check expiry field and grace window
    const exp = payload && payload.exp ? Number(payload.exp) : undefined;
    if (!exp) return { ok: false, reason: 'invalid_token' };
    const now = Math.floor(Date.now() / 1000);
    if (now - exp > REFRESH_WINDOW_SEC) return { ok: false, reason: 'refresh_window_exceeded' };
    // Remove iat/exp/nbf before signing new token
    const { iat, exp: _exp, nbf, ...rest } = payload as any;
    const newToken = jwt.sign(rest, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    return { ok: true, token: newToken, expiresIn: JWT_EXPIRES_IN };
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
  if (!user || typeof user !== 'object') throw new Error('User document is required');
  if (!user.authId) throw new Error('authId is required');
  if (!password) throw new Error('Password is required');
  const userCol = getClient().db(USERS_DB_NAME).collection(USERS_COLLECTION);
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
  if (!_id && !authId) throw new Error('Either _id or authId must be provided');
  const userCol = getClient().db(USERS_DB_NAME).collection(USERS_COLLECTION);
  let filter: any = {};
  if (_id) {
    filter._id = toObjectId(_id) ?? _id;
  } else if (authId) {
    filter.authId = authId;
  }
  const result = await userCol.deleteOne(filter);
  return result.deletedCount;
}

let server: any;

function isServerListening(s: any) {
  try {
    return !!(s && typeof s.listening === 'boolean' ? s.listening : s.address && s.address());
  } catch (_e) {
    return false;
  }
}

export async function startServer() {
  if (isServerListening(server)) return server;
  const port = Number(process.env.PORT) || 3000;
  console.log('### 4', MONGO_URI)
  const c = new MongoClient(MONGO_URI);
  client = c;
  try {
    await c.connect();
    await c.db().admin().ping();
    // connection ok
    console.log('MongoDB connected');
    // Retrieve and log serverInfo and serverStatus for diagnostics
    try {
      const admin = c.db().admin();
      const serverInfo = await admin.serverInfo();
      const serverStatus = await admin.serverStatus();
      console.log('### 10: MongoDB serverInfo:', serverInfo);
      console.log('### 11: MongoDB serverStatus:', serverStatus);
    } catch (adminErr: any) {
      console.log('Failed to retrieve MongoDB admin info - Error name:', adminErr && adminErr.name, 'Error message:', adminErr && adminErr.message);
      if (adminErr && adminErr.stack) console.log(adminErr.stack);
    }
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
  console.log('### 5')

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
        const passwordValid = await plpaServer.validatePassword(password);
        if (!passwordValid || !passwordValid.ok) return sendResponse(req, res, { ok: false, error: 'Authentication failed' }, 401);

        const token = jwt.sign({ userType: 'provisional' }, process.env.JWT_SECRET, { expiresIn: '5s' });
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
      const userCol = getClient().db(USERS_DB_NAME).collection(USERS_COLLECTION);
      const user = await userCol.findOne({ authId });
      if (!user || !user.passwordHash) return sendResponse(req, res, { ok: false, error: 'Authentication failed' }, 401);
      const valid = await bcrypt.compare(password, user.passwordHash);
      if (!valid) return sendResponse(req, res, { ok: false, error: 'Authentication failed' }, 401);
      const { _id, userType, roles, merchantId } = user;
      const token = jwt.sign({ _id, userType, roles, merchantId }, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
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
