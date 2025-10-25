import { EJSON } from 'bson';
import { AuthClient } from '@kedaruma/revlm-shared';
import RevlmDBDatabase from "./RevlmDBDatabase";

export type RevlmOptions = {
  fetchImpl?: typeof fetch;
  defaultHeaders?: Record<string, string>;
  // provisional (optional) client-side configuration
  provisionalEnabled?: boolean;
  provisionalAuthSecretMaster?: string;
  provisionalAuthDomain?: string;
  // automatically set token returned from login/provisionalLogin into the client
  autoSetToken?: boolean;
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

  constructor(baseUrl: string, opts: RevlmOptions = {}) {
    if (!baseUrl) throw new Error('baseUrl is required');
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetchImpl = opts.fetchImpl || (typeof fetch !== 'undefined' ? fetch : (undefined as any));
    this.defaultHeaders = opts.defaultHeaders || {};
    this.provisionalEnabled = opts.provisionalEnabled || false;
    this.provisionalAuthSecretMaster = opts.provisionalAuthSecretMaster || '';
    this.provisionalAuthDomain = opts.provisionalAuthDomain || '';
    this.autoSetToken = opts.autoSetToken ?? true;

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
    const res = await this.request('/refresh-token', 'POST');
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
      headers['Authorization'] = `Bearer ${this._token}`;
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
    const url = path.startsWith('http') ? path : `${this.baseUrl}${path.startsWith('/') ? '' : '/'}${path}`;
    const hasBody = body !== undefined;
    const headers = this.makeHeaders(hasBody);
    let serializedBody: string | undefined;
    if (hasBody) {
      serializedBody = EJSON.stringify(body);
    }
    try {
      const res = await this.fetchImpl(url, {
        method,
        headers,
        body: serializedBody,
      } as any);
      const parsed = await this.parseResponse(res);
      const out: RevlmResponse = (parsed && typeof parsed === 'object') ? parsed : { ok: res.ok, result: parsed };
      out.status = res.status;
      return out;
    } catch (err: any) {
      return { ok: false, error: err?.message || String(err) };
    }
  }

  async login(authId: string, password: string) {
    if (!authId || !password) throw new Error('authId and password are required');
    const res = await this.request('/login', 'POST', { authId, password });
    if (this.autoSetToken && res && res.ok && res.token) {
      this.setToken(res.token as string);
    }
    return res;
  }

  async provisionalLogin(authId: string) {
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
    return res;
  }

  async registerUser(user: any, password: string) {
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
