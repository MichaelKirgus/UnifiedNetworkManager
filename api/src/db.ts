import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { eq, isNull } from 'drizzle-orm';
import { generateSecret, buildOtpAuthUri } from './auth/totp';
import * as schema from './db/schema';

const DEFAULT_DATABASE_URL = 'postgresql://' + 'unm' + ':' + 'unm' + '@localhost:5432/unm';
const DATABASE_URL = process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL;

export const pool = new Pool({ connectionString: DATABASE_URL });
export const db = drizzle(pool, { schema });

export type User = typeof schema.users.$inferSelect;
export type Device = typeof schema.devices.$inferSelect;
export type Plugin = typeof schema.plugins.$inferSelect;
export type ConfigJob = typeof schema.configJobs.$inferSelect;
export type Telemetry = typeof schema.telemetry.$inferSelect;
export type Secret = typeof schema.secrets.$inferSelect;

/**
 * Database bootstrap hook.
 *
 * The API owns the `users` table (the single source of truth for local
 * identities). Identity *verification* is delegated to the active identity
 * provider plugin, but user *provisioning* (seeding the default admin) stays
 * here so the API is always able to resolve usernames (e.g. for secrets).
 */
export async function initDb(): Promise<void> {
  // Defensive migration: ensure the telemetry.metricDescriptors column exists.
  // (drizzle-kit push handles this on setup, but this covers hot-reload / dev.)
  await pool.query(
    `ALTER TABLE telemetry ADD COLUMN IF NOT EXISTS "metricDescriptors" TEXT`
  );

  // Defensive migrations for plugin options: descriptor cache column + the
  // settings table. Same rationale as above — host-dev hot reload may run
  // before drizzle-kit push has created them.
  await pool.query(
    `ALTER TABLE plugins ADD COLUMN IF NOT EXISTS "optionDescriptors" TEXT`
  );
  await pool.query(`
    CREATE TABLE IF NOT EXISTS plugin_settings (
      id TEXT PRIMARY KEY,
      "pluginId" TEXT NOT NULL,
      "deviceId" TEXT,
      "optionKey" TEXT NOT NULL,
      value TEXT NOT NULL,
      "updatedAt" TEXT NOT NULL
    )`);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_plugin_settings_global
      ON plugin_settings ("pluginId", "optionKey") WHERE "deviceId" IS NULL`);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_plugin_settings_device
      ON plugin_settings ("pluginId", "deviceId", "optionKey") WHERE "deviceId" IS NOT NULL`);

  // Multi-plugin-per-device model: the device_plugins join table is the single
  // source of truth for which plugins serve a device (each with its own secret).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_plugins (
      id TEXT PRIMARY KEY,
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      "secretId" TEXT,
      "isPrimary" BOOLEAN NOT NULL DEFAULT FALSE,
      "createdAt" TEXT NOT NULL
    )`);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_device_plugins
      ON device_plugins ("deviceId", "pluginId")`);

  // Attribute telemetry + config jobs to the plugin that produced/executed them.
  await pool.query(
    `ALTER TABLE telemetry ADD COLUMN IF NOT EXISTS "pluginId" TEXT`
  );
  await pool.query(
    `ALTER TABLE config_jobs ADD COLUMN IF NOT EXISTS "pluginId" TEXT`
  );

  // The legacy singular columns are superseded by device_plugins. There is no
  // production data to migrate (confirmed), so drop them outright — any dev
  // devices must be recreated via the new multi-plugin create flow.
  await pool.query(`ALTER TABLE devices DROP COLUMN IF EXISTS "pluginId"`);
  await pool.query(`ALTER TABLE devices DROP COLUMN IF EXISTS "secretId"`);

  const existingAdmin = await db.query.users.findFirst({
    where: (users, { eq }) => eq(users.username, 'admin'),
  });

  if (existingAdmin) {
    return;
  }

  const passwordHash = bcrypt.hashSync('admin', 10);
  const totpSecret = generateSecret();

  await db.insert(schema.users).values({
    id: uuidv4(),
    username: 'admin',
    passwordHash,
    totpSecret,
    roles: JSON.stringify(['admin']),
    permissions: JSON.stringify([
      'devices:read',
      'devices:write',
      'configs:apply',
      'plugins:manage',
      'secrets:read',
      'secrets:write',
      'secrets:delete',
    ]),
    createdAt: new Date().toISOString(),
  });

  // eslint-disable-next-line no-console
  console.log('[db] seeded default admin user (username: admin, password: admin)');
  // eslint-disable-next-line no-console
  console.log(`[db] admin TOTP secret (dev only): ${totpSecret}`);
  // eslint-disable-next-line no-console
  console.log(`[db] admin otpauth URI (scan with an authenticator app): ${buildOtpAuthUri('admin', totpSecret)}`);
}

/**
 * One-time backfill for the multi-provider secrets model: any secret rows that
 * predate the `type`/`providerId` columns are bound to the built-in
 * secrets-provider plugin and typed as `apiKey` (the legacy shape).
 */
export async function backfillSecrets(): Promise<void> {
  const SECRETS_PROVIDER_UUID = '00000000-0000-4000-8000-000000000002';
  const orphans = await db.query.secrets.findMany({
    where: (secrets, { isNull }) => isNull(secrets.providerId),
  });
  if (orphans.length === 0) {
    return;
  }
  await db
    .update(schema.secrets)
    .set({ providerId: SECRETS_PROVIDER_UUID, type: 'apiKey' })
    .where(isNull(schema.secrets.providerId));
  // eslint-disable-next-line no-console
  console.log(`[db] backfilled ${orphans.length} secret(s) to the built-in secrets provider`);
}