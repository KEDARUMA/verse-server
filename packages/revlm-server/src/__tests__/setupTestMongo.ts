// Setup test MongoDB utility for integration tests
// - If mongoUri is provided, use it; otherwise start MongoMemoryServer
// - Return uri and mongod instance (if started)
// 統合テスト用の MongoDB セットアップユーティリティ
// - mongoUri が指定されていればそれを使用、未指定なら MongoMemoryServer を起動
// - uri と mongod インスタンス（起動した場合）を返す

import {deleteUserRaw, ServerConfig, startServer, stopServer} from '@kedaruma/revlm-server/server';
import { MongoMemoryServer } from 'mongodb-memory-server';
import http, { Server } from 'http';
import {AuthClient} from "@kedaruma/revlm-shared/auth-token";
import request from "supertest";
import { SignatureV4 } from '@aws-sdk/signature-v4';
import { Sha256 } from '@aws-crypto/sha256-js';

export interface ServerConfigEnv extends Omit<ServerConfig, 'mongoUri'> {
  mongoUri?: string | null;
}

export interface SetupTestEnvironmentOptions {
  serverConfig: ServerConfigEnv;   // Server configuration (e.g., ServerConfig from revlm-server)
}

export interface SetupTestEnvironmentResult {
  uri: string;
  mongod?: MongoMemoryServer | undefined;
  server: Server;
  serverUrl: string;
}

export async function buildSigV4Headers(serverUrl: string, path: string, method: string, body?: any): Promise<Record<string, string>> {
  const url = new URL(serverUrl);
  const signer = new SignatureV4({
    credentials: {
      accessKeyId: process.env.REVLM_SIGV4_ACCESS_KEY || 'revlm-access',
      secretAccessKey: process.env.REVLM_SIGV4_SECRET_KEY || 'test-sigv4-secret',
    },
    region: process.env.REVLM_SIGV4_REGION || 'revlm',
    service: process.env.REVLM_SIGV4_SERVICE || 'revlm',
    sha256: Sha256,
  });
  const headers: Record<string, string> = {
    host: url.host,
    'content-type': 'application/json',
  };
  const payload = body !== undefined ? JSON.stringify(body) : '';
  const reqToSign: any = {
    method,
    protocol: url.protocol,
    path,
    headers,
    hostname: url.hostname,
    body: payload,
  };
  if (url.port) {
    reqToSign.port = Number(url.port);
  }
  const signed = await signer.sign(reqToSign as any) as any;
  const out: Record<string, string> = {};
  Object.entries(signed.headers || {}).forEach(([k, v]) => {
    out[k] = Array.isArray(v) ? v.join(',') : String(v);
  });
  return out;
}

/**
 * Setup test environment (MongoDB + Server)
 * @param options - Configuration options
 * @returns MongoDB URI, mongod instance (if started), server instance, and server URL
 */
export async function setupTestEnvironment(
  options: SetupTestEnvironmentOptions
): Promise<SetupTestEnvironmentResult> {

  // Setup MongoDB (start MongoMemoryServer if mongoUri is not provided)
  // MongoDB をセットアップ（mongoUri が未指定の場合は MongoMemoryServer を起動）
  let mongoUri = options.serverConfig.mongoUri;
  let mongod: MongoMemoryServer | undefined;

  if (!mongoUri) {
    const dbName = options.serverConfig.usersDbName || 'testdb';
    try {
      mongod = await MongoMemoryServer.create({ instance: { dbName } });
      if (!mongod) {
        throw new Error('MongoMemoryServer.create() returned null/undefined');
      }
      mongoUri = mongod.getUri();
    } catch (err) {
      console.error('Failed to start MongoMemoryServer:', err);
      throw err;
    }
  }

  // Start the server with MongoDB URI
  // MongoDB URI を渡してサーバーを起動
  const server: http.Server = await startServer({ ...options.serverConfig, mongoUri } as ServerConfig);

  // Get server URL from actual listening port
  // 実際のリスニングポートから serverUrl を取得
  let serverUrl: string;
  try {
    const addr: any = server && server.address ? server.address() : undefined;
    const port = addr && typeof addr === 'object' ? addr.port : 0;
    if (addr == null || port === 0) {
      throw new Error('Failed to get server address or port');
    }
    serverUrl = `http://localhost:${port}`;
  } catch (_e) {
    throw _e;
  }

  return {
    uri: mongoUri,
    mongod,
    server,
    serverUrl,
  };
}


export interface CreateTestUserOptions {
  serverUrl: string;
  user: any; // User object to register
  password: string; // Password for the test user
  provisionalAuthId: string;
  provisionalAuthSecretMaster: string;
  provisionalAuthDomain: string;
}

/**
 * Create test user via provisional login
 * Obtain a token via provisional login and use it to register the test user through the API
 * @param options - Configuration options
 * @returns void
 */
export async function createTestUser(options: CreateTestUserOptions): Promise<void> {
  const {
    serverUrl,
    user,
    password,
    provisionalAuthId,
    provisionalAuthSecretMaster,
    provisionalAuthDomain,
  } = options;

  try {
    // make it idempotent across runs
    try {
      await cleanupTestUser(user.authId);
    } catch (_e) {
      /* ignore if user does not exist */
    }

    // Generate a password for provisional login
    // provisional login のパスワードを生成
    const provisionalClient = new AuthClient({
      secretMaster: provisionalAuthSecretMaster,
      authDomain: provisionalAuthDomain,
    });
    const provisionalPassword = await provisionalClient.producePassword(provisionalAuthId);

    // Perform provisional login to obtain a token
    // provisional login で仮認証を行いトークンを取得
    const provisionalHeaders = await buildSigV4Headers(serverUrl, '/provisional-login', 'POST', { authId: provisionalAuthId, password: provisionalPassword });
    const provisionalLoginRes = await request(serverUrl)
      .post('/provisional-login')
      .set(provisionalHeaders)
      .send({ authId: provisionalAuthId, password: provisionalPassword });

    if (!provisionalLoginRes.body || !provisionalLoginRes.body.ok) {
      throw new Error('provisional-login failed: ' + JSON.stringify(provisionalLoginRes.body));
    }
    const provisionalToken = provisionalLoginRes.body.token as string;

    // Register the test user
    // テストユーザを登録
    const regRes = await request(serverUrl)
      .post('/registerUser')
      .set(await buildSigV4Headers(serverUrl, '/registerUser', 'POST', { user, password }))
      .set('X-Revlm-JWT', `Bearer ${provisionalToken}`)
      .send({ user, password });

    if (!regRes.body || !regRes.body.ok) {
      throw new Error('registerUser via API failed: ' + JSON.stringify(regRes.body));
    }

    console.log(`Test user registered via API: ${user.authId}`);
  } catch (error) {
    console.error(`Failed to register test user (${user.authId}):`, error);
    throw error;
  }
}

/**
 * Clean up test user
 * Delete the user created during the test
 * @param authId - The authId of the user to delete
 */
export async function cleanupTestUser(authId: string): Promise<void> {
  try {
    await deleteUserRaw(undefined, authId);
    console.log(`Test user deleted: ${authId}`);
  } catch (error) {
    console.error(`Failed to delete test user (${authId}):`, error);
    throw error;
  }
}

/**
 * Clean up test environment
 * Stop the server and MongoMemoryServer
 * @param testEnv - The SetupTestEnvironmentResult returned from setupTestEnvironment
 */
export async function cleanupTestEnvironment(
  testEnv: SetupTestEnvironmentResult
): Promise<void> {
  console.log('Cleaning up test environment...');

  // Stop the server
  // サーバーを停止
  try {
    await stopServer();
    console.log('Server stopped');
  } catch (error) {
    console.error('Failed to stop server:', error);
  }

  // Stop the in-memory MongoDB server if it was started
  // MongoMemoryServer が起動されていれば停止
  const mongod = testEnv.mongod;
  if (mongod) {
    try {
      await mongod.stop();
      console.log('MongoMemoryServer stopped');
    } catch (error) {
      console.warn('Failed to stop MongoMemoryServer:', error);
    }
  }

  console.log('Test environment cleanup done');
}

// ---- Dummy test to satisfy Jest when this helper resides under __tests__ ----
// このヘルパーが __tests__ 配下にあるため、Jest がテストとして実行した際に
// "Your test suite must contain at least one test" を避けるための最小限のテスト。
describe('setupTestMongo helpers smoke', () => {
  it('exports helper functions', () => {
    expect(typeof setupTestEnvironment).toBe('function');
  });
});
