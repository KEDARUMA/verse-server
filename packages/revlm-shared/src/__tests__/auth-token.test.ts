/*
AuthToken tests overview:
- Verify password token generation on client and validation on server (including replay protection and wrong-secret handling).
- Ensure demo() runs without throwing errors.

AuthToken テスト概要:
- クライアントでのパスワードトークン生成とサーバでの検証（リプレイ防止、誤シークレットの取り扱いを含む）を確認。
- demo() が例外を投げずに動作することを確認。
*/

import { AuthClient, AuthServer } from '@kedaruma/revlm-shared/auth-token';

// Tests for AuthClient/AuthServer password token behavior
// AuthClient/AuthServer のパスワードトークン動作に関するテスト

// Tests grouped for password token lifecycle and demo
// パスワードトークンのライフサイクルと demo に関するテスト群
describe('AuthToken', () => {
  // Test constants used across cases
  // テスト全体で使う定数
  const secretMaster = 'test_secret_123!@#日本語';
  const authDomain = 'test.domain';
  let client: AuthClient;
  let server: AuthServer;

  // Initialize client/server instances before tests
  // テスト前に AuthClient と AuthServer のインスタンスを初期化する
  beforeAll(() => {
    client = new AuthClient({ secretMaster, authDomain });
    server = new AuthServer({ secretMaster, authDomain });
  });

  // クライアントでトークンを生成し、サーバで検証する
  it('should generate and validate a password token', async () => {
    const password = await client.producePassword('test-device');
    const result = await server.validatePassword(password);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.payload.deviceId).toBe('test-device');
      expect(typeof result.payload.ts).toBe('number');
      expect(typeof result.payload.nonce).toBe('string');
    }
  });

  // サーバの secret が間違っていると検証は失敗する
  it('should fail validation with wrong secret', async () => {
    const password = await client.producePassword('test-device');
    const wrongServer = new AuthServer({ secretMaster: 'wrong_secret', authDomain });
    const result = await wrongServer.validatePassword(password);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('decrypt_failed');
    }
  });

  // 同一トークンの再検証はリプレイとして検出・拒否される
  it('should fail replay attack', async () => {
    const password = await client.producePassword('test-device');
    const first = await server.validatePassword(password);
    const second = await server.validatePassword(password);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(second.reason).toBe('replay');
    }
  });
});

// demo を実行してサンプルフローが例外なく動くことを確認
describe('AuthToken demo', () => {
  // Run demo via dynamic import and capture any error
  // 動的 import で demo を実行し、エラーが発生しないことを確認
  it('should run demo without error', async () => {
    const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const spyErr = jest.spyOn(console, 'error').mockImplementation(() => {});
    let error: any = null;
    try {
      await (await import('@kedaruma/revlm-shared/auth-token')).demo();
    } catch (e) {
      error = e;
    }
    spy.mockRestore();
    spyErr.mockRestore();
    expect(error).toBeNull();
  });
});
