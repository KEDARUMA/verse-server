// auth-token.ts (moved to revlm-shared)
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
  let bytes: Uint8Array;
  if (ArrayBuffer.isView(buf)) {
    const view = buf as ArrayBufferView;
    bytes = new Uint8Array(view.buffer, (view as any).byteOffset || 0, (view as any).byteLength || (view as any).length);
  } else {
    bytes = new Uint8Array(buf as ArrayBuffer);
  }
  // Browser-safe base64url
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    const s = Buffer.from(bytes).toString('base64');
    return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64 = (typeof btoa === 'function') ? btoa(binary) : Buffer.from(bytes).toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 ? 4 - (b64.length % 4) : 0;
  const withPad = b64 + '='.repeat(pad);
  if (typeof atob === 'function') {
    const bin = atob(withPad);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }
  return new Uint8Array(Buffer.from(withPad, 'base64'));
}

function base64Encode(arr: Uint8Array): string {
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') return Buffer.from(arr).toString('base64');
  let binary = '';
  for (const b of arr) binary += String.fromCharCode(b);
  return (typeof btoa === 'function') ? btoa(binary) : Buffer.from(arr).toString('base64');
}
function base64Decode(str: string): Uint8Array {
  if (typeof atob === 'function') {
    const bin = atob(str);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }
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
  const secretBuffer = masterSecret.buffer as ArrayBuffer;
  const infoBuffer = info.buffer as ArrayBuffer;
  const saltBuffer = (salt && salt.buffer) as ArrayBuffer | undefined;
  const key = await (crypto as any).subtle.importKey('raw', secretBuffer, 'HKDF', false, ['deriveBits']);
  const bits = await (crypto as any).subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', info: infoBuffer, salt: saltBuffer ?? new Uint8Array().buffer },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

// ========= AES-GCM =========
async function aesGcmEncrypt(kRaw: Uint8Array, iv: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const key = await (crypto as any).subtle.importKey('raw', kRaw.buffer as ArrayBuffer, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const additionalData = aad ? (aad.buffer as ArrayBuffer) : undefined;
  const ct = await (crypto as any).subtle.encrypt({ name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, additionalData, tagLength: 128 }, key, plaintext.buffer as ArrayBuffer);
  return new Uint8Array(ct);
}
async function aesGcmDecrypt(kRaw: Uint8Array, iv: Uint8Array, ciphertextAndTag: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const key = await (crypto as any).subtle.importKey('raw', kRaw.buffer as ArrayBuffer, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const additionalData = aad ? (aad.buffer as ArrayBuffer) : undefined;
  const pt = await (crypto as any).subtle.decrypt({ name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, additionalData, tagLength: 128 }, key, ciphertextAndTag.buffer as ArrayBuffer);
  return new Uint8Array(pt);
}

// ========= Payload codec (JSON; サイズ小ならこれで十分。CBORに替えてもOK) =========
type Payload = { ts: number; nonce: string; deviceId?: string; };
function encodePayload(p: Payload): Uint8Array { return textEncoder.encode(JSON.stringify(p)); }
function decodePayload(b: Uint8Array): Payload { return JSON.parse(textDecoder.decode(b)); }

// ========= Client =========
export class AuthClient {
  private secretMaster: string;
  private authDomain: string;
  private hkdfInfo: Uint8Array;

  constructor(opts: { secretMaster: string; authDomain: string; hkdfInfo?: Uint8Array }) {
    this.secretMaster = opts.secretMaster;
    this.authDomain = opts.authDomain;
    this.hkdfInfo = opts.hkdfInfo ?? textEncoder.encode(`auth-v1|${this.authDomain}`);
  }

  async producePassword(deviceId?: string): Promise<string> {
    const master = textEncoder.encode(this.secretMaster);
    const key = await hkdfDeriveKeyRaw(master, this.hkdfInfo, 32);
    const iv = (crypto as any).getRandomValues(new Uint8Array(12));
    const ts = Math.floor(Date.now() / 1000);
    const nonceBytes = (crypto as any).getRandomValues(new Uint8Array(16));
    const nonce = b64urlEncode(nonceBytes);
    const payload: Payload = (typeof deviceId === 'string') ? { ts, nonce, deviceId } : { ts, nonce };
    const aad = this.hkdfInfo;
    const ct = await aesGcmEncrypt(key, iv, encodePayload(payload), aad);
    const tokenBytes = concatBytes(iv, ct);
    return b64urlEncode(tokenBytes);
  }
}

// ========= Server =========
export class AuthServer {
  private secretMaster: string;
  private authDomain: string;
  private hkdfInfo: Uint8Array;
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

  async validatePassword(token: string): Promise<{ ok: true; payload: Payload } | { ok: false; reason: string }> {
    const tokenBytes = b64urlDecode(token);
    if (tokenBytes.length < 12 + 16) return { ok: false, reason: 'token_too_short' };
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

// demo
export async function demo() {
  const msStr = 'muster-secret';
  const authDomain = "com.example.app";
  const client = new AuthClient({ secretMaster: msStr, authDomain });
  const server = new AuthServer({ secretMaster: msStr, authDomain });
  const password = await client.producePassword("device-xyz");
  const res = await server.validatePassword(password);
  console.log("verify:", res);
}
