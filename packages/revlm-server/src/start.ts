import { config as dotenvConfig } from 'dotenv';
dotenvConfig();
import { startServer, stopServer, ServerConfig } from './server';

function toBool(v: string | undefined): boolean | undefined {
  if (v === undefined) return undefined;
  return v === 'true' || v === '1';
}

function toNumber(v: string | undefined): number | undefined {
  if (v === undefined || v === '') return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

function getEnvOrUndefined(name: string): string | undefined {
  const v = process.env[name];
  if (v === undefined || v === '') return undefined;
  return v;
}

async function main() {
  const raw: Record<string, any> = {
    mongoUri: getEnvOrUndefined('MONGO_URI'),
    usersDbName: getEnvOrUndefined('USERS_DB_NAME'),
    usersCollectionName: getEnvOrUndefined('USERS_COLLECTION_NAME'),
    provisionalLoginEnabled: toBool(getEnvOrUndefined('PROVISIONAL_LOGIN_ENABLED')),
    provisionalAuthId: getEnvOrUndefined('PROVISIONAL_AUTH_ID'),
    provisionalAuthSecretMaster: getEnvOrUndefined('PROVISIONAL_AUTH_SECRET_MASTER'),
    provisionalAuthDomain: getEnvOrUndefined('PROVISIONAL_AUTH_DOMAIN'),
    jwtSecret: getEnvOrUndefined('JWT_SECRET'),
    jwtExpiresIn: getEnvOrUndefined('JWT_EXPIRES_IN'),
    refreshWindowSec: toNumber(getEnvOrUndefined('REFRESH_WINDOW_SEC')),
    port: toNumber(getEnvOrUndefined('PORT')),
  };

  // Remove undefined entries so optional properties are omitted (satisfies exactOptionalPropertyTypes)
  const cfgPartial: Partial<ServerConfig> = Object.fromEntries(
    Object.entries(raw).filter(([, v]) => v !== undefined)
  ) as Partial<ServerConfig>;

  try {
    await startServer(cfgPartial as ServerConfig);
    console.log('startServer called successfully');
    // Attach shutdown handlers only after successful start (Ctrl+C will trigger SIGINT)
    const shutdown = async (signal?: string, err?: any) => {
      if (signal) console.log(`Received ${signal}, shutting down...`);
      if (err) console.log('Shutdown triggered by error - Error name:', err && err.name, 'Error message:', err && err.message);
      try {
        await stopServer();
        console.log('Server stopped cleanly');
        process.exit(0);
      } catch (stopErr: any) {
        console.log('stopServer failed - Error name:', stopErr && stopErr.name, 'Error message:', stopErr && stopErr.message);
        process.exit(1);
      }
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('uncaughtException', (ex) => {
      console.log('uncaughtException - Error name:', ex && ex.name, 'Error message:', ex && ex.message);
      shutdown(undefined, ex);
    });
    process.on('unhandledRejection', (reason: any) => {
      console.log('unhandledRejection -', reason && (reason.name || ''), reason && reason.message ? reason.message : reason);
      shutdown(undefined, reason);
    });
  } catch (err: any) {
    console.log('start failed - Error name:', err && err.name, 'Error message:', err && err.message);
    if (err && err.stack) console.log(err.stack);
    process.exit(1);
  }
}

void main();
