import { EJSON } from 'bson';
import { AuthClient } from '@kedaruma/revlm-shared';
import { SignatureV4 } from '@aws-sdk/signature-v4';
import { Sha256 } from '@aws-crypto/sha256-js';
import type { User as UserDoc } from '@kedaruma/revlm-shared/models/user-types';
import RevlmDBDatabase from "./RevlmDBDatabase";
import { LoginResponse, ProvisionalLoginResponse } from './Revlm.types';

type EmailPasswordCredential = { type: 'emailPassword'; email: string; password: string };
type UserInput = Omit<UserDoc, 'userType'> & { userType: UserDoc['userType'] | string };

export type RevlmOptions = {
  fetchImpl?: typeof fetch;
  defaultHeaders?: Record<string, string>;
  // provisional (optional) client-side configuration
  provisionalEnabled?: boolean;
  provisionalAuthSecretMaster?: string;
  provisionalAuthDomain?: string;
  // automatically set token returned from login/provisionalLogin into the client
  autoSetToken?: boolean;
  // automatically refresh on 401 once and retry the original request
  autoRefreshOn401?: boolean;
  // SigV4 settings (default on if secret is present)
  sigv4SecretKey?: string;
  sigv4AccessKey?: string;
  sigv4Region?: string;
  sigv4Service?: string;
  sigv4Enabled?: boolean;
};

export type RevlmResponse<T = any> = {
  ok: boolean;
  error?: string;
  token?: string;
  user?: any;
  result?: T;
  [k: string]: any;
};

export default class Revlm {
  baseUrl: string;
  fetchImpl: typeof fetch;
  defaultHeaders: Record<string, string>;
  private _token: string | undefined;
  private provisionalEnabled: boolean;
  private provisionalAuthSecretMaster: string;
  private provisionalAuthDomain: string;
  private autoSetToken: boolean;
  private autoRefreshOn401: boolean;
  private sigv4Signer: SignatureV4 | null;

  constructor(baseUrl: string, opts: RevlmOptions = {}) {
    if (!baseUrl) throw new Error('baseUrl is required');
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetchImpl = opts.fetchImpl || (typeof fetch !== 'undefined' ? fetch : (undefined as any));
    this.defaultHeaders = opts.defaultHeaders || {};
    this.provisionalEnabled = opts.provisionalEnabled || false;
    this.provisionalAuthSecretMaster = opts.provisionalAuthSecretMaster || '';
    this.provisionalAuthDomain = opts.provisionalAuthDomain || '';
    this.autoSetToken = opts.autoSetToken ?? true;
    this.autoRefreshOn401 = opts.autoRefreshOn401 || false;
    const sigv4SecretKey = opts.sigv4SecretKey || process.env.REVLM_SIGV4_SECRET_KEY;
    const sigv4AccessKey = opts.sigv4AccessKey || process.env.REVLM_SIGV4_ACCESS_KEY || 'revlm-access';
    const sigv4Region = opts.sigv4Region || process.env.REVLM_SIGV4_REGION || 'revlm';
    const sigv4Service = opts.sigv4Service || process.env.REVLM_SIGV4_SERVICE || 'revlm';
    const sigv4Enabled = opts.sigv4Enabled ?? true;
    if (sigv4Enabled) {
      if (!sigv4SecretKey) {
        throw new Error('SigV4 is enabled but REVLM_SIGV4_SECRET_KEY or opts.sigv4SecretKey is not provided');
      }
      // SigV4 signer for all outgoing requests
      // 送信リクエスト全てにSigV4署名を付与するサイナー
      this.sigv4Signer = new SignatureV4({
        credentials: { accessKeyId: sigv4AccessKey, secretAccessKey: sigv4SecretKey },
        region: sigv4Region,
        service: sigv4Service,
        sha256: Sha256,
      });
    } else {
      this.sigv4Signer = null;
    }

    if (!this.fetchImpl) {
      throw new Error('No fetch implementation available. Provide fetchImpl in options or run in Node 18+ with global fetch.');
    }
  }

  setToken(token: string) {
    this._token = token;
  }
  getToken() {
    return this._token;
  }
  clearToken() {
    this._token = undefined;
  }

  // Logout clears client-side token (simple, synchronous)
  logout(): void {
    this.clearToken();
  }

  // Call server to refresh token. Uses Authorization header with current token.
  // On success, if autoSetToken is true and res.token is set, update the client token.
  async refreshToken(): Promise<RevlmResponse> {
    if (!this._token) return { ok: false, error: 'No token set' };
    const res = await this.requestWithRetry('/refresh-token', 'POST', undefined, { allowAuthRetry: false, retrying: false });
    if (this.autoSetToken && res && res.ok && res.token) {
      this.setToken(res.token as string);
    }
    return res;
  }

  // Verify current token with server. If invalid/expired, clear local token.
  async verifyToken(): Promise<RevlmResponse> {
    if (!this._token) return { ok: false, error: 'No token set' };
    const res = await this.request('/verify-token', 'POST');
    // Server returns { ok: false, reason: 'token_expired' | 'invalid_token' | 'no_token' }
    const reason = (res as any).reason || (res as any).error;
    if (res && !res.ok) {
      if (reason === 'invalid_token' || reason === 'token_expired' || reason === 'no_token' || res.status === 401 || res.status === 403) {
        this.clearToken();
      }
    }
    return res;
  }

  private makeHeaders(hasBody: boolean) {
    const headers: Record<string, string> = {
      Accept: 'application/ejson',
      ...this.defaultHeaders,
    };
    if (hasBody) {
      headers['Content-Type'] = 'application/ejson';
    }
    if (this._token) {
      headers['X-Revlm-JWT'] = `Bearer ${this._token}`;
    }
    return headers;
  }

  private async parseResponse(res: Response): Promise<any> {
    const text = await res.text();
    if (!text) return null;
    try {
      return EJSON.parse(text);
    } catch (e) {
    }
    try {
      return JSON.parse(text);
    } catch (e) {
      return text;
    }
  }

  private async request(path: string, method = 'POST', body?: any): Promise<RevlmResponse> {
    return this.requestWithRetry(path, method, body, { allowAuthRetry: this.autoRefreshOn401, retrying: false });
  }

  private shouldSkipAuthRetry(path: string): boolean {
    const pathname = path.startsWith('http') ? new URL(path).pathname : path;
    return pathname.includes('/login') || pathname.includes('/provisional-login') || pathname.includes('/refresh-token') || pathname.includes('/verify-token');
  }

  private async signIfNeeded(
    url: string,
    method: string,
    headers: Record<string, string>,
    body?: string
  ): Promise<{ signedUrl: string; signedHeaders: Record<string, string> }> {
    if (!this.sigv4Signer) {
      return { signedUrl: url, signedHeaders: headers };
    }
    // Canonicalize and sign the request for SigV4
    // SigV4用にリクエストを正規化して署名
    const u = new URL(url);
    // ensure host header present for signing
    const signingHeaders: Record<string, string> = {
      host: u.host,
      ...headers,
    };
    const reqToSign: any = {
      method,
      protocol: u.protocol,
      path: u.pathname + (u.search || ''),
      hostname: u.hostname,
      headers: signingHeaders,
      body: body ?? '',
    };
    if (u.port) {
      reqToSign.port = Number(u.port);
    }
    const signed = await this.sigv4Signer.sign(reqToSign as any) as any;
    const signedHeaders: Record<string, string> = {};
    Object.entries(signed.headers || {}).forEach(([k, v]) => {
      signedHeaders[k] = Array.isArray(v) ? v.join(',') : String(v);
    });
    return { signedUrl: url, signedHeaders };
  }

  private async requestWithRetry(
    path: string,
    method = 'POST',
    body?: any,
    opts: { allowAuthRetry: boolean; retrying: boolean } = { allowAuthRetry: false, retrying: false }
  ): Promise<RevlmResponse> {
    const { allowAuthRetry, retrying } = opts;
    const url = path.startsWith('http') ? path : `${this.baseUrl}${path.startsWith('/') ? '' : '/'}${path}`;
    const hasBody = body !== undefined;
    const headers = this.makeHeaders(hasBody);
    let serializedBody: string | undefined;
    if (hasBody) {
      serializedBody = EJSON.stringify(body);
    }
    const { signedUrl, signedHeaders } = await this.signIfNeeded(url, method, headers, serializedBody);
    try {
      const res = await this.fetchImpl(signedUrl, {
        method,
        headers: signedHeaders,
        body: serializedBody,
      } as any);
      const parsed = await this.parseResponse(res);
      const out: RevlmResponse = (parsed && typeof parsed === 'object') ? parsed : { ok: res.ok, result: parsed };
      out.status = res.status;
      if (out && out.ok === false && !out.error) {
        // normalize error field for compatibility
        out.error = (parsed as any)?.reason || (parsed as any)?.message || 'Unknown error';
      }
      if (allowAuthRetry && !retrying && res.status === 401 && !this.shouldSkipAuthRetry(path)) {
        const refreshRes = await this.refreshToken();
        if (refreshRes && refreshRes.ok && refreshRes.token) {
          return this.requestWithRetry(path, method, body, { allowAuthRetry: false, retrying: true });
        }
      }
      return out;
    } catch (err: any) {
      return { ok: false, error: err?.message || String(err) };
    }
  }

  async login(authId: string, password: string): Promise<LoginResponse> {
    if (!authId || !password) throw new Error('authId and password are required');
    const res = await this.request('/login', 'POST', { authId, password });
    if (this.autoSetToken && res && res.ok && res.token) {
      this.setToken(res.token as string);
    }
    return res as LoginResponse;
  }

  async provisionalLogin(authId: string): Promise<ProvisionalLoginResponse> {
    if (!this.provisionalEnabled) {
      throw new Error('provisional login is disabled by client configuration');
    }
    if (!authId) throw new Error('authId is required');
    const provisionalClient = new AuthClient({ secretMaster: this.provisionalAuthSecretMaster, authDomain: this.provisionalAuthDomain });
    const provisionalPassword = await provisionalClient.producePassword(String(Date.now() * 1000));
    const res = await this.request('/provisional-login', 'POST', { authId, password: provisionalPassword });
    if (this.autoSetToken && res && res.ok && res.token) {
      this.setToken(res.token as string);
    }
    return res as ProvisionalLoginResponse;
  }

  async registerUser(user: UserInput, password: string) {
    if (!user) throw new Error('user is required');
    if (!password) throw new Error('password is required');
    return this.request('/registerUser', 'POST', { user, password });
  }

  async deleteUser(params: { _id?: any; authId?: string }) {
    if (!params || (!params._id && !params.authId)) throw new Error('Either _id or authId must be provided');
    return this.request('/deleteUser', 'POST', params);
  }

  async revlmGate(payload: any) {
    if (!payload || typeof payload !== 'object') throw new Error('payload object is required');
    return this.request('/revlm-gate', 'POST', payload);
  }

  db(dbName: string) {
    return new RevlmDBDatabase(dbName, this);
  }
}

export { Revlm };

// Realm.Web emulation layer (minimal surface without listeners)
class MongoDBService {
  private _revlm: Revlm;
  constructor(revlm: Revlm) {
    this._revlm = revlm;
  }
  db(dbName: string) {
    return new RevlmDBDatabase(dbName, this._revlm);
  }
}

class Credentials {
  static emailPassword(email: string, password: string): EmailPasswordCredential {
    if (!email || !password) throw new Error('email and password are required');
    return { type: 'emailPassword', email, password };
  }
}

class User {
  private _app: App;
  private _token: string;
  private _profile: any;
  functions: {
    callFunction: (_name: string, _args?: any[]) => Promise<any>;
  };
  constructor(app: App, token: string, profile: any) {
    this._app = app;
    this._token = token;
    this._profile = profile || {};
    this.functions = {
      callFunction: async (_name: string, _args?: any[]) => {
        throw new Error('user.functions.callFunction is not implemented in Revlm client');
      },
    };
  }
  get id(): string {
    return String(this._profile && this._profile._id ? this._profile._id : '');
  }
  get accessToken(): string {
    return this._token;
  }
  get profile(): any {
    return this._profile;
  }
  mongoClient(_serviceName = 'mongodb-atlas'): MongoDBService {
    return new MongoDBService(this._app.__revlm);
  }
  async logOut() {
    await this._app.logOut();
  }
}

class App {
  private _currentUser: User | null = null;
  private _users: Record<string, User> = {};
  // Expose for internal use by emulated classes
  __revlm: Revlm;
  emailPasswordAuth: {
    registerUser: (email: string, password: string) => Promise<RevlmResponse>;
    deleteUser: (email: string) => Promise<RevlmResponse>;
  };

  constructor(baseUrl: string, opts: RevlmOptions & { id?: string } = {}) {
    this.__revlm = new Revlm(baseUrl, opts);
    this.emailPasswordAuth = {
      registerUser: async (email: string, password: string) => {
        return this.__revlm.registerUser({ authId: email, userType: 'user', roles: ['user'] }, password);
      },
      deleteUser: async (email: string) => {
        return this.__revlm.deleteUser({ authId: email });
      },
    };
  }

  get currentUser(): User | null {
    return this._currentUser;
  }

  get allUsers(): Record<string, User> {
    return { ...this._users };
  }

  async logIn(cred: EmailPasswordCredential): Promise<User> {
    if (!cred || cred.type !== 'emailPassword') {
      throw new Error('Unsupported credentials type');
    }
    const res = await this.__revlm.login(cred.email, cred.password);
    if (!res || !res.ok || !res.token) {
      const errMsg = res && !res.ok ? res.error : 'login failed';
      throw new Error(errMsg);
    }
    this.__revlm.setToken(res.token as string);
    const user = new User(this, res.token as string, res.user);
    const userId = user.id || 'current';
    this._users[userId] = user;
    this._currentUser = user;
    return user;
  }

  switchUser(user: User): User {
    if (!user) throw new Error('user is required');
    this._currentUser = user;
    this.__revlm.setToken(user.accessToken);
    return user;
  }

  async removeUser(user: User): Promise<void> {
    if (!user) return;
    const id = user.id || 'current';
    delete this._users[id];
    if (this._currentUser === user) {
      await this.logOut();
    }
  }

  async logOut(): Promise<void> {
    this.__revlm.logout();
    this._currentUser = null;
  }

  // Realm compatibility: allow deleteUser(user) pattern
  async deleteUser(user: User): Promise<void> {
    if (!user) return;
    const authId = (user.profile && (user.profile as any).authId) || user.id;
    await this.__revlm.deleteUser({ authId });
    await this.removeUser(user);
  }
}

export { App, Credentials, MongoDBService, User };
