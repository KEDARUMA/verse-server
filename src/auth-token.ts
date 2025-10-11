// auth-token.ts
// AES-GCM + HKDF (SHA-256) による「password=暗号トークン」実装
// - 形式: base64url(iv | ciphertext|tag)
// - payload: { ts, nonce, deviceId? } をJSONバイト化して暗号化
// - AAD: "auth-v1|<authDomain>" でドメイン分離
//
// Node 18+/Browser対応: globalThis.crypto.subtle を使用

// ========= Shared Utilities =========
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function b64urlEncode(buf: ArrayBuffer | Uint8Array): string {
  // ArrayBuffer/TypedArray を安定的に Uint8Array に変換
  let bytes: Uint8Array;
  if (ArrayBuffer.isView(buf)) {
    const view = buf as ArrayBufferView;
    bytes = new Uint8Array(view.buffer, (view as any).byteOffset || 0, (view as any).byteLength || (view as any).length);
  } else {
    bytes = new Uint8Array(buf as ArrayBuffer);
  }
  let s = Buffer.from(bytes).toString('base64');
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function b64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  s += '='.repeat(pad);
  return new Uint8Array(Buffer.from(s, 'base64'));
}

function base64Encode(arr: Uint8Array): string {
  return Buffer.from(arr).toString('base64');
}
function base64Decode(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'base64'));
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// ========= HKDF (SubtleCrypto) =========
async function hkdfDeriveKeyRaw(masterSecret: Uint8Array, info: Uint8Array, length = 32, salt?: Uint8Array): Promise<Uint8Array> {
  // WebCrypto expects BufferSource (ArrayBuffer or ArrayBufferView)
  const secretBuffer = masterSecret.buffer as ArrayBuffer;
  const infoBuffer = info.buffer as ArrayBuffer;
  const saltBuffer = (salt && salt.buffer) as ArrayBuffer | undefined;
  const key = await crypto.subtle.importKey('raw', secretBuffer, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', info: infoBuffer, salt: saltBuffer ?? new Uint8Array().buffer },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

// ========= AES-GCM =========
async function aesGcmEncrypt(kRaw: Uint8Array, iv: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', kRaw.buffer as ArrayBuffer, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const additionalData = aad ? (aad.buffer as ArrayBuffer) : undefined;
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, additionalData, tagLength: 128 }, key, plaintext.buffer as ArrayBuffer);
  return new Uint8Array(ct);
}
async function aesGcmDecrypt(kRaw: Uint8Array, iv: Uint8Array, ciphertextAndTag: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', kRaw.buffer as ArrayBuffer, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const additionalData = aad ? (aad.buffer as ArrayBuffer) : undefined;
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, additionalData, tagLength: 128 }, key, ciphertextAndTag.buffer as ArrayBuffer);
  return new Uint8Array(pt);
}

// ========= Payload codec (JSON; サイズ小ならこれで十分。CBORに替えてもOK) =========
type Payload = { ts: number; nonce: string; deviceId?: string; };
function encodePayload(p: Payload): Uint8Array { return textEncoder.encode(JSON.stringify(p)); }
function decodePayload(b: Uint8Array): Payload { return JSON.parse(textDecoder.decode(b)); }

// ========= Client =========
export class AuthClient {
  // クライアントに埋め込む secretMaster（任意の文字列）。
  private secretMaster: string;
  private authDomain: string; // AAD用。サーバと一致させる。
  private hkdfInfo: Uint8Array; // ドメイン分離（例: "auth-v1|<authDomain>")

  constructor(opts: { secretMaster: string; authDomain: string; hkdfInfo?: Uint8Array }) {
    this.secretMaster = opts.secretMaster;
    this.authDomain = opts.authDomain;
    this.hkdfInfo = opts.hkdfInfo ?? textEncoder.encode(`auth-v1|${this.authDomain}`);
  }

  // password（=暗号トークン）を生成。
  async producePassword(deviceId?: string): Promise<string> {
    // base64Decode(this.secretMaster) → TextEncoderでエンコード
    const master = textEncoder.encode(this.secretMaster);
    const key = await hkdfDeriveKeyRaw(master, this.hkdfInfo, 32);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ts = Math.floor(Date.now() / 1000);
    const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
    const nonce = b64urlEncode(nonceBytes);
    const payload: Payload = (typeof deviceId === 'string') ? { ts, nonce, deviceId } : { ts, nonce };
    const aad = this.hkdfInfo;
    const ct = await aesGcmEncrypt(key, iv, encodePayload(payload), aad);
    // token構造： iv(12) | ct||tag(可変)
    const tokenBytes = concatBytes(iv, ct);
    return b64urlEncode(tokenBytes);
  }
}

// ========= Server =========
export class AuthServer {
  // サーバ管理の secretMaster（任意の文字列）。KMS/HSM保管推奨。
  private secretMaster: string;
  private authDomain: string;
  private hkdfInfo: Uint8Array;
  // リプレイ防止用の短期キャッシュ（本番はRedis等）
  private seenNonces: Map<string, number>;
  private windowSec: number;

  constructor(opts: {
    secretMaster: string;
    authDomain: string;
    hkdfInfo?: Uint8Array;
    timestampWindowSec?: number;
  }) {
    this.secretMaster = opts.secretMaster;
    this.authDomain = opts.authDomain;
    this.hkdfInfo = opts.hkdfInfo ?? textEncoder.encode(`auth-v1|${this.authDomain}`);
    this.seenNonces = new Map();
    this.windowSec = opts.timestampWindowSec ?? 120;
  }

  private purgeOldNonces(now: number) {
    for (const [n, t] of this.seenNonces) {
      if (now - t > this.windowSec) this.seenNonces.delete(n);
    }
  }

  // 受け取った password（=暗号トークン）だけで妥当性を検証
  async validatePassword(token: string): Promise<{ ok: true; payload: Payload } | { ok: false; reason: string }> {
    const tokenBytes = b64urlDecode(token);
    if (tokenBytes.length < 12 + 16) return { ok: false, reason: 'token_too_short' };
    // base64Decode(this.secretMaster) → TextEncoderでエンコード
    const master = textEncoder.encode(this.secretMaster);
    const iv = tokenBytes.slice(0, 12);
    const ct = tokenBytes.slice(12);
    const key = await hkdfDeriveKeyRaw(master, this.hkdfInfo, 32);
    let pt: Uint8Array;
    try {
      pt = await aesGcmDecrypt(key, iv, ct, this.hkdfInfo);
    } catch {
      return { ok: false, reason: 'decrypt_failed' };
    }
    let payload: Payload;
    try {
      payload = decodePayload(pt);
    } catch {
      return { ok: false, reason: 'payload_parse_error' };
    }
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - payload.ts) > this.windowSec) {
      return { ok: false, reason: 'timestamp_out_of_window' };
    }
    if (!payload.nonce || payload.nonce.length < 10) {
      return { ok: false, reason: 'bad_nonce' };
    }
    this.purgeOldNonces(now);
    if (this.seenNonces.has(payload.nonce)) {
      return { ok: false, reason: 'replay' };
    }
    this.seenNonces.set(payload.nonce, now);
    return { ok: true, payload };
  }
}

// ========= Example (Node or Browser) =========
export async function demo() {
  // デモ用 secretMaster を1つ用意（任意の文字列でOK）
  const msStr = 'muster-secret';
  const authDomain = "com.example.app";
  const client = new AuthClient({ secretMaster: msStr, authDomain });
  const server = new AuthServer({ secretMaster: msStr, authDomain });
  // クライアントがpasswordを作る
  const password = await client.producePassword("device-xyz");
  // サーバが検証
  const res = await server.validatePassword(password);
  console.log("verify:", res);
}
if (typeof process !== "undefined" && require.main === module) {
  demo().catch((e) => { console.error(e); process.exit(1); });
}
