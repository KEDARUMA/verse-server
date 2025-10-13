import type { Request, Response, NextFunction } from 'express';
import { User } from './models/user-types';
import {AuthServer} from "./auth-token";
const express = require('express');
const dotenv = require('dotenv');
const { MongoClient } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { ObjectId, EJSON } = require('bson');

dotenv.config();

const app = express();
app.use(express.text({ type: 'application/ejson' }));
app.use(express.json());

const mongoUri = process.env.MONGO_URI;
// Client binding (created inside startServer()). Exported at bottom to avoid duplicate export declarations.
let client: any; // MongoClient will be assigned in startServer()

const DB_NAME = process.env.DATA_BASE_NAME || 'verse';
const USERS_COLLECTION = process.env.USERS_COLLECTION_NAME;
if (!USERS_COLLECTION) throw new Error('Environment variable USERS_COLLECTION is required but was not set')
const PROVISIONAL_LOGIN_ENABLED =
  process.env.PROVISIONAL_LOGIN_ENABLED === 'true' ||
  process.env.PROVISIONAL_LOGIN_ENABLED === '1';
const PROVISIONAL_AUTH_ID = process.env.PROVISIONAL_AUTH_ID;
if (!PROVISIONAL_AUTH_ID) throw new Error('Environment variable PROVISIONAL_AUTH_ID is required but was not set')
const PROVISIONAL_AUTH_SECRET_MASTER = process.env.PROVISIONAL_AUTH_SECRET_MASTER;
if (!PROVISIONAL_AUTH_SECRET_MASTER) throw new Error('Environment variable PROVISIONAL_AUTH_SECRET_MASTER is required but was not set')
const PROVISIONAL_AUTH_DOMAIN = process.env.PROVISIONAL_AUTH_DOMAIN;
if (!PROVISIONAL_AUTH_DOMAIN) throw new Error('Environment variable PROVISIONAL_AUTH_DOMAIN is required but was not set')
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;
if (!JWT_EXPIRES_IN) throw new Error('Environment variable JWT_EXPIRES_IN is required but was not set')

// provisional login passwd auth server
const plpaServer = new AuthServer({ secretMaster: PROVISIONAL_AUTH_SECRET_MASTER, authDomain: PROVISIONAL_AUTH_DOMAIN });

// Response helper: if client accepts application/ejson, send EJSON; otherwise send standard JSON
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

// JWT authentication middleware
function verifyToken(req: Request, res: Response, next: NextFunction) {
  const header = req.headers['authorization'] as string | undefined;
  const token = header && header.split(' ')[1];
  if (!token) return sendResponse(req, res, { ok: false, error: 'No token provided' }, 401);
  try {
    (req as any).user = jwt.verify(token, process.env.JWT_SECRET);

    // If the token payload indicates a provisional user, restrict access.
    // Allow only the registerUser and login endpoints for provisional users.
    // Note: /login is typically public (no token), but we include it here
    // for completeness if routes change in the future.
    const provisionalAllowedPaths = new Set(['/registerUser', '/login']);
    const userType = (req as any).user && (req as any).user.userType;
    if (userType === 'provisional') {
      const path = (req as any).path || (req as any).originalUrl || '';
      if (!provisionalAllowedPaths.has(path)) {
        return sendResponse(req, res, { ok: false, error: 'provisional user cannot access this endpoint' }, 403);
      }
    }

    next();
  } catch {
    return sendResponse(req, res, { ok: false, error: 'Invalid token' }, 403);
  }
}

// User registration
export async function registerUserRaw(user: User, password: string) {
  if (!user || typeof user !== 'object') throw new Error('User document is required');
  if (!user.authId) throw new Error('authId is required');
  if (!password) throw new Error('Password is required');
  const userCol = client.db(DB_NAME).collection(USERS_COLLECTION);
  const exists = await userCol.findOne({ authId: user.authId });
  if (exists) throw new Error('authId already exists');
  const passwordHash = await bcrypt.hash(password, 10);
  if (!user._id) {
    user._id = new ObjectId();
  }
  user.passwordHash = passwordHash;
  await userCol.insertOne(user);
  return user;
}

// User deletion
export async function deleteUserRaw(_id: any, authId?: string) {
  if (!_id && !authId) throw new Error('Either _id or authId must be provided');
  const userCol = client.db(DB_NAME).collection(USERS_COLLECTION);
  let filter: any = {};
  if (_id) {
    filter._id = _id;
  } else if (authId) {
    filter.authId = authId;
  }
  const result = await userCol.deleteOne(filter);
  return result.deletedCount;
}

let server: any;

// Helper to determine if server is already listening.
function isServerListening(s: any) {
  try {
    return !!(s && typeof s.listening === 'boolean' ? s.listening : s.address && s.address());
  } catch (_e) {
    return false;
  }
}

async function startServer() {
  // If server already started and listening, reuse it.
  if (isServerListening(server)) return server;
  // Ensure we have a numeric port value available for listen()/logs.
  const port = Number(process.env.PORT) || 3000;
  // create client here (delay creation until startServer is called)
  client = new MongoClient(mongoUri);
  await client.connect();

  // Middleware: if body was sent as application/ejson, parse it into BSON types
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
        // DEBUG: decode and log the token payload for inspection
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

  // Login endpoint: Authenticate user and issue JWT
  app.post('/login', async (req: Request, res: Response) => {
    const { authId, password } = req.body;
    if (!authId || !password) return sendResponse(req, res, { ok: false, error: 'authId and password are required' }, 400);
    try {
      const userCol = client.db(DB_NAME).collection(USERS_COLLECTION);
      const user = await userCol.findOne({ authId });
      if (!user || !user.passwordHash) return sendResponse(req, res, { ok: false, error: 'Authentication failed' }, 401);
      const valid = await bcrypt.compare(password, user.passwordHash);
      if (!valid) return sendResponse(req, res, { ok: false, error: 'Authentication failed' }, 401);
      const { _id, userType, roles, merchantId } = user;
      const token = jwt.sign({ _id, userType, roles, merchantId }, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
      // DEBUG: decode and log the token payload for inspection
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

  // User registration (with authentication required)
  app.post('/registerUser', verifyToken, async (req: Request, res: Response) => {
    const { user, password } = req.body;
    try {
      const newUser = await registerUserRaw(user, password);
      return sendResponse(req, res, { ok: true, user: newUser });
    } catch (err: any) {
      return sendResponse(req, res, { ok: false, error: err.message }, 400);
    }
  });

  // User deletion (with authentication required)
  app.post('/deleteUser', verifyToken, async (req: Request, res: Response) => {
    // Reject if userType is provisional
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

  // MongoDB operation API that is almost transparent, similar to Realm
  app.post('/verse-gate', verifyToken, async (req: Request, res: Response) => {
    const { collection, method, document, options, filter, update, replacement, pipeline, documents } = req.body as any;
    try {
      const db = client.db(DB_NAME);
      const col = db.collection(collection);
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

  // app.listen can throw synchronously (EADDRINUSE) in some environments.
  // Wrap in try/catch to handle that case and avoid unhandled exceptions in tests.
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
      console.log(`🚀 Verse API server started on port ${port}`);
      resolve();
    });
    server.once('error', (err: any) => {
      // If port is already in use by another test worker/process, don't fail the start.
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

async function stopServer() {
  // close http server if running
  if (server) {
    await new Promise<void>((resolve, reject) => {
      server.close((err?: Error) => (err ? reject(err) : resolve()));
    });
    server = undefined;
  }
  // force-close MongoClient to terminate underlying sockets
  try {
    if (client) {
      // ask client to close and wait for internal close operations
      try {
        await client.close(true);
      } catch (_e) {
        // ignore errors from driver close
      }
      // also try to directly close internal topology if present (defensive)
      try {
        const topologyClose = (client as any)?.topology?.close;
        if (typeof topologyClose === 'function') {
          try { await (client as any).topology.close(); } catch (_e) { /* ignore */ }
        }
      } catch (_e) { /* ignore */ }
      // drop reference to client to avoid accidental reuse
      try { client = undefined; } catch (_e) { /* ignore */ }
    }
  } catch (e) {
    // ignore
  }

  // After attempting to close the client, some TLSSocket handles may linger briefly
  // (driver internal cleanup). Aggressively destroy any remote MongoDB TLSSocket/Socket
  // we can find for a short period to avoid leaving open handles that prevent node exit.
  try {
    const getHandles = (process as any)._getActiveHandles;
    if (typeof getHandles === 'function') {
      const deadline = Date.now() + 2000; // wait up to 2000ms
      const targetCtors = new Set(['TLSSocket', 'Socket', 'TLSWrap', 'TCP']);
      while (Date.now() < deadline) {
        let destroyedOne = false;
        const handles = getHandles();
        for (const h of handles) {
          try {
            const ctor = h && h.constructor && h.constructor.name;
            if (targetCtors.has(ctor)) {
              const peer = h._peername || (h._parent && h._parent.remoteAddress) || null;
              const servername = h.servername || (h._parent && h._parent.servername) || null;
              if (peer || (servername && String(servername).includes('mongodb'))) {
                try { h.destroy(); destroyedOne = true; } catch (_e) { /* ignore */ }
              }
            }
          } catch (e) {
            // ignore per-handle errors
          }
        }
        if (!destroyedOne) break;
        // small backoff to let driver settle
        await new Promise((r) => setTimeout(r, 100));
      }
    }
  } catch (e) {
    // ignore
  }
}

export { startServer, stopServer, client };

// Setup signal and exception handlers for graceful shutdown (useful for pm2/systemd)
function setupSignalHandlers() {
  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGQUIT'];
  let shuttingDown = false;

  const graceful = async (reason?: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    try {
      console.log(`Shutting down server (${reason || 'signal'})...`);
      await stopServer();
      console.log('Shutdown complete.');
      process.exit(0);
    } catch (err) {
      console.error('Error during shutdown:', err);
      process.exit(1);
    }
  };

  for (const sig of signals) {
    process.on(sig, () => { void graceful(sig); });
  }

  process.on('uncaughtException', (err) => {
    console.error('uncaughtException:', err);
    void graceful('uncaughtException');
  });
  process.on('unhandledRejection', (reason) => {
    console.error('unhandledRejection:', reason);
    void graceful('unhandledRejection');
  });
}

// If this module is executed directly (node dist/server.js), start the server and
// ensure the process remains alive and reacts to termination signals.
if (require.main === module) {
  setupSignalHandlers();
  (async () => {
    try {
      const serverInstance = await startServer();
      const runPort = Number(process.env.PORT) || 3000;
      if (!serverInstance) {
        console.error(`Server did not start on port ${runPort}. Exiting.`);
        // ensure shutdown of any partial resources
        await stopServer().catch(() => { /* ignore */ });
        process.exit(1);
      }
      console.log(`Server running (pid ${process.pid}) on port ${runPort}`);
      // keep process alive while http server listens
    } catch (err) {
      console.error('Failed to start server:', err);
      await stopServer().catch(() => { /* ignore */ });
      process.exit(1);
    }
  })();
}
