/** Logs into the UNM API as admin (password + fresh TOTP) and prints the bearer token. */
import path from 'node:path';
import { createRequire } from 'node:module';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const row = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
  await pool.end();
  if (!row.totpSecret) throw new Error('NO_TOTP');
  const { authenticator } = apiRequire('otplib');
  const code = authenticator.generate(row.totpSecret);

  const base = process.env.UNM_API ?? 'http://localhost:3000/v1';
  // Step 1: password → challenge token.
  const r1 = await fetch(`${base}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: process.env.UNM_ADMIN_PW ?? 'admin' }),
  });
  const j1 = (await r1.json()) as { challengeToken?: string; token?: string };
  if (!j1.challengeToken) throw new Error(`login step1 failed (${r1.status}): ${JSON.stringify(j1).slice(0, 300)}`);

  // Step 2: TOTP → bearer token.
  const r2 = await fetch(`${base}/auth/2fa/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeToken: j1.challengeToken, totpCode: code }),
  });
  const j2 = (await r2.json()) as { token?: string; accessToken?: string };
  const tok = j2.accessToken ?? j2.token;
  if (!tok) throw new Error(`login step2 failed (${r2.status}): ${JSON.stringify(j2).slice(0, 300)}`);
  console.log(tok);
}
main().catch((e) => { console.error(e.message ?? e); process.exit(1); });
