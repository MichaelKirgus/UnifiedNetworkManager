/** Prints the current TOTP code for admin (minted from the seeded secret). */
import path from 'node:path';
import { createRequire } from 'node:module';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const row = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
  await pool.end();
  if (!row.totpSecret) { console.log('NO_TOTP'); return; }
  const { authenticator } = apiRequire('otplib');
  console.log(authenticator.generate(row.totpSecret));
}
main().catch((e) => { console.error(e.message); process.exit(1); });
