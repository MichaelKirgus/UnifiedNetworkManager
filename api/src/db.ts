import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
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
 * Seeds a default admin user on first run.
 * Note: Table creation is now handled by Drizzle migrations/push.
 */
export async function initDb(): Promise<void> {
  const existingAdmin = await db.query.users.findFirst({
    where: (users, { eq }) => eq(users.username, 'admin'),
  });

  if (!existingAdmin) {
    const passwordHash = bcrypt.hashSync('admin', 10);
    const totpSecret = generateSecret();
    
    await db.insert(schema.users).values({
      id: uuidv4(),
      username: 'admin',
      passwordHash,
      totpSecret,
      roles: JSON.stringify(['admin']),
      permissions: JSON.stringify(['devices:read', 'devices:write', 'configs:apply', 'plugins:manage', 'secrets:read', 'secrets:write', 'secrets:delete']),
      createdAt: new Date().toISOString(),
    });

    console.log('[db] seeded default admin user (username: admin, password: admin)');
    console.log(`[db] admin TOTP secret (dev only): ${totpSecret}`);
    console.log(`[db] admin otpauth URI (scan with an authenticator app): ${buildOtpAuthUri('admin', totpSecret)}`);
  }
}