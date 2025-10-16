// Use .env for configuration
require('dotenv').config();

import { startServer, stopServer } from '../../../verse-server/src/server';
import Verse from '../Verse';

jest.setTimeout(20000);

describe('Verse.provisionalLogin (integration)', () => {
  beforeAll(async () => {
    await startServer();
  });

  afterAll(async () => {
    try {
      await stopServer();
    } catch (e) {
      // ignore
    }
  });

  it('round-trips provisionalLogin successfully using .env settings', async () => {
    const provisionalAuthId = process.env.PROVISIONAL_AUTH_ID as string;
    const v = new Verse(`http://localhost:${process.env.PORT || 3000}`,
      {
        provisionalEnabled: true,
        provisionalAuthSecretMaster: process.env.PROVISIONAL_AUTH_SECRET_MASTER as string,
        provisionalAuthDomain: process.env.PROVISIONAL_AUTH_DOMAIN as string
      }
    );
    const res = await v.provisionalLogin(provisionalAuthId);
    expect(res.ok).toBe(true);
    expect(res.token).toBeDefined();
    expect(res.user).toBeDefined();
  });
});
