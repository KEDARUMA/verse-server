import { AuthClient, AuthServer } from '../auth-token';

describe('AuthToken', () => {
  const secretMaster = 'test_secret_123!@#日本語';
  const authDomain = 'test.domain';
  let client: AuthClient;
  let server: AuthServer;

  beforeAll(() => {
    client = new AuthClient({ secretMaster, authDomain });
    server = new AuthServer({ secretMaster, authDomain });
  });

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

  it('should fail validation with wrong secret', async () => {
    const password = await client.producePassword('test-device');
    const wrongServer = new AuthServer({ secretMaster: 'wrong_secret', authDomain });
    const result = await wrongServer.validatePassword(password);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('decrypt_failed');
    }
  });

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

describe('AuthToken demo', () => {
  it('should run demo without error', async () => {
    const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const spyErr = jest.spyOn(console, 'error').mockImplementation(() => {});
    let error: any = null;
    try {
      await (await import('../auth-token')).demo();
    } catch (e) {
      error = e;
    }
    spy.mockRestore();
    spyErr.mockRestore();
    expect(error).toBeNull();
  });
});

