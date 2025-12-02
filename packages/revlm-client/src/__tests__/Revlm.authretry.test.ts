import Revlm from '../Revlm';

process.env.REVLM_SIGV4_SECRET_KEY = process.env.REVLM_SIGV4_SECRET_KEY || 'test-sigv4-secret';
process.env.REVLM_SIGV4_ACCESS_KEY = process.env.REVLM_SIGV4_ACCESS_KEY || 'revlm-access';
process.env.REVLM_SIGV4_REGION = process.env.REVLM_SIGV4_REGION || 'revlm';
process.env.REVLM_SIGV4_SERVICE = process.env.REVLM_SIGV4_SERVICE || 'revlm';

type MockResponseInit = { status: number; body: any };

function makeMockResponse({ status, body }: MockResponseInit) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return JSON.stringify(body);
    },
  } as any;
}

describe('Revlm autoRefreshOn401', () => {
  // 401でリフレッシュした後に同じリクエストを再送する
  it('retries original request after refresh on 401', async () => {
    const fetchMock = jest.fn()
      // initial call -> 401
      .mockResolvedValueOnce(makeMockResponse({ status: 401, body: { ok: false, reason: 'token_expired' } }))
      // refresh-token -> 200 with new token
      .mockResolvedValueOnce(makeMockResponse({ status: 200, body: { ok: true, token: 'new-token' } }))
      // retry original -> 200 success
      .mockResolvedValueOnce(makeMockResponse({ status: 200, body: { ok: true, result: { data: 1 } } }));

    const client = new Revlm('https://api.example.com', { fetchImpl: fetchMock as any, autoRefreshOn401: true });
    client.setToken('expired-token');

    const res = await client.revlmGate({ db: 'db', collection: 'col', method: 'find', filter: {} });

    expect(res.ok).toBe(true);
    expect(res.result).toEqual({ data: 1 });
    expect(client.getToken()).toBe('new-token');
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect((fetchMock.mock.calls[0][0] as string)).toContain('/revlm-gate');
    expect((fetchMock.mock.calls[1][0] as string)).toContain('/refresh-token');
    expect((fetchMock.mock.calls[2][0] as string)).toContain('/revlm-gate');
  });

  // autoRefreshOn401がfalseのときは401でもリトライしない
  it('does not retry when autoRefreshOn401 is false', async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce(makeMockResponse({ status: 401, body: { ok: false, reason: 'token_expired' } }));
    const client = new Revlm('https://api.example.com', { fetchImpl: fetchMock as any, autoRefreshOn401: false });
    client.setToken('expired-token');

    const res = await client.revlmGate({ db: 'db', collection: 'col', method: 'find', filter: {} });

    expect(res.ok).toBe(false);
    expect(res.status).toBe(401);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
