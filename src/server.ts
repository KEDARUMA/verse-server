import type { Request, Response, NextFunction } from 'express';
import { User } from './models/user-types';
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

const client = new MongoClient(process.env.MONGO_URI);
const DB_NAME = process.env.DATA_BASE_NAME || 'verse';
const USERS_COLLECTION = process.env.USERS_COLLECTION_NAME || 'users';

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
    next();
  } catch {
    return sendResponse(req, res, { ok: false, error: 'Invalid token' }, 403);
  }
}

// トークンチェック無しのユーザー登録関数
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

// トークンチェック無しのユーザー削除関数
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

(async () => {
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
      const { authId: id, userType, roles, merchantId } = user;
      const jwtExpiresIn = process.env.JWT_EXPIRES_IN || '1h';
      const token = jwt.sign({ authId: id, userType, roles, merchantId }, process.env.JWT_SECRET, { expiresIn: jwtExpiresIn });
      return sendResponse(req, res, { ok: true, token, user });
    } catch (err: any) {
      return sendResponse(req, res, { ok: false, error: err.message }, 500);
    }
  });

  // 認証必須API
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
    const { _id, authId } = req.body as { _id?: any; authId?: string };
    try {
      const deletedCount = await deleteUserRaw(_id, authId);
      return sendResponse(req, res, { ok: true, deletedCount });
    } catch (err: any) {
      return sendResponse(req, res, { ok: false, error: err.message }, 400);
    }
  });

  // Realm風API
  app.post('/mongo', verifyToken, async (req: Request, res: Response) => {
    const { collection, method, query, document, options } = req.body as any;
    try {
      const db = client.db(DB_NAME);
      const col = db.collection(collection);
      let result;
      switch (method) {
        case 'find':
          result = await col.find(query || {}, options || {}).toArray();
          break;
        case 'insertOne':
          result = await col.insertOne(document);
          break;
        default:
          return sendResponse(req, res, { ok: false, error: 'Unsupported method' }, 400);
      }
      return sendResponse(req, res, { ok: true, result });
    } catch (err: any) {
      return sendResponse(req, res, { ok: false, error: err.message }, 500);
    }
  });

  app.listen(process.env.PORT || 3000, () => {
    console.log(`🚀 Verse API server started on port ${process.env.PORT || 3000}`);
  });
})();
