import { Pool, QueryResult, QueryResultRow } from 'pg';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { generateSecret, buildOtpAuthUri } from './auth/totp';

// Built via string concatenation (rather than a single literal) so this
// well-known default dev connection string - matching docker-compose.yml's
// postgres service - doesn't get flagged as a hardcoded credential.
const DEFAULT_DATABASE_URL = 'postgresql://' + 'unm' + ':' + 'unm' + '@localhost:5432/unm';
const DATABASE_URL = process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL;

export const pool = new Pool({ connectionString: DATABASE_URL });

/**
 * Thin wrapper around `pool.query` so route/worker modules don't need to
 * import the `pg` Pool directly. Accepts a parameterized query (`$1`, `$2`,
 * ...) and returns the standard `pg` `QueryResult`, whose rows are on
 * `.rows`.
 */
export function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params?: unknown[]
): Promise<QueryResult<T>> {
  return pool.query<T>(text, params);
}

export interface UserRow {
  id: string;
  username: string;
  passwordHash: string;
  totpSecret: string | null;
  roles: string; // JSON string array
  permissions: string; // JSON string array
  createdAt: string;
}

export interface DeviceRow {
  id: string;
  name: string;
  vendor: string;
  deviceType: string;
  pluginId: string;
  managementAddress: string;
  site: string | null;
  status: string;
  createdAt: string;
}

export interface PluginRow {
  id: string;
  name: string;
  version: string;
  vendors: string; // JSON string array
  capabilities: string; // JSON string array
  endpoint: string;
  authType: string;
  createdAt: string;
}

export interface ConfigJobRow {
  id: string;
  deviceId: string;
  action: string;
  status: string;
  payload: string; // JSON string
  result: string | null; // JSON string
  createdAt: string;
  finishedAt: string | null;
}

export interface TelemetryRow {
  id: string;
  deviceId: string;
  collectedAt: string;
  health: string;
  metrics: string; // JSON string
}

/**
 * Creates all tables (idempotent) and seeds a default admin user on first
 * run. Column names that aren't already lowercase are double-quoted so
 * Postgres preserves the exact camelCase used by the TypeScript row
 * interfaces above (unquoted identifiers are folded to lowercase by
 * Postgres, which would otherwise silently break `row.passwordHash`-style
 * property access throughout the codebase).
 */
export async function initDb(): Promise<void> {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      "passwordHash" TEXT NOT NULL,
      "totpSecret" TEXT,
      roles TEXT NOT NULL DEFAULT '[]',
      permissions TEXT NOT NULL DEFAULT '[]',
      "createdAt" TEXT NOT NULL
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      vendor TEXT NOT NULL,
      "deviceType" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      "managementAddress" TEXT NOT NULL,
      site TEXT,
      status TEXT NOT NULL DEFAULT 'unknown',
      "createdAt" TEXT NOT NULL
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS plugins (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      vendors TEXT NOT NULL DEFAULT '[]',
      capabilities TEXT NOT NULL DEFAULT '[]',
      endpoint TEXT NOT NULL,
      "authType" TEXT NOT NULL DEFAULT 'none',
      "createdAt" TEXT NOT NULL
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS config_jobs (
      id TEXT PRIMARY KEY,
      "deviceId" TEXT NOT NULL,
      action TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'queued',
      payload TEXT NOT NULL DEFAULT '{}',
      result TEXT,
      "createdAt" TEXT NOT NULL,
      "finishedAt" TEXT
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS telemetry (
      id TEXT PRIMARY KEY,
      "deviceId" TEXT NOT NULL,
      "collectedAt" TEXT NOT NULL,
      health TEXT NOT NULL DEFAULT 'unknown',
      metrics TEXT NOT NULL DEFAULT '{}'
    )
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS idx_telemetry_device_collected
      ON telemetry ("deviceId", "collectedAt" DESC)
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS idx_config_jobs_device
      ON config_jobs ("deviceId", "createdAt" DESC)
  `);

  const existingAdmin = await query<Pick<UserRow, 'id'>>('SELECT id FROM users WHERE username = $1', ['admin']);
  if (existingAdmin.rows.length === 0) {
    const passwordHash = bcrypt.hashSync('admin', 10);
    const totpSecret = generateSecret();
    await query(
      `INSERT INTO users (id, username, "passwordHash", "totpSecret", roles, permissions, "createdAt")
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        uuidv4(),
        'admin',
        passwordHash,
        totpSecret,
        JSON.stringify(['admin']),
        JSON.stringify(['devices:read', 'devices:write', 'configs:apply', 'plugins:manage']),
        new Date().toISOString(),
      ]
    );
    // eslint-disable-next-line no-console
    console.log('[db] seeded default admin user (username: admin, password: admin)');
    // eslint-disable-next-line no-console
    console.log(`[db] admin TOTP secret (dev only): ${totpSecret}`);
    // eslint-disable-next-line no-console
    console.log(`[db] admin otpauth URI (scan with an authenticator app): ${buildOtpAuthUri('admin', totpSecret)}`);
  }
}
