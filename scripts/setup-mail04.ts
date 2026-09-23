/**
 * One-shot setup: bind a mailcow API key to MAIL04 in UNM.
 *
 * Usage (run in your own terminal — the key is typed directly and never logged):
 *   npx tsx scripts/setup-mail04.ts
 *
 * Steps: admin login → create secret (type apiKeyNoSecret) → assign Mailcow Plugin
 * to MAIL04 → force a device refresh → print the resulting mail inventory counts.
 */
import readline from 'node:readline';
import path from 'node:path';
import { createRequire } from 'node:module';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

const MAIL04_ID = process.env.MAIL04_DEVICE_ID ?? '589688ae-729c-4860-8c86-375db11691a1';
const MAILCOW_PLUGIN_ID = '00000000-0000-4000-8000-00000000000f';

async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const row = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
  await pool.end();
  if (!row.totpSecret) throw new Error('NO_TOTP');
  const { authenticator } = apiRequire('otplib');

  const base = process.env.UNM_API ?? 'http://localhost:3000/v1';
  const r1 = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: process.env.UNM_ADMIN_PW ?? 'admin' }) });
  const j1 = (await r1.json()) as { challengeToken?: string };
  if (!j1.challengeToken) throw new Error(`login step1 failed (${r1.status})`);
  const r2 = await fetch(`${base}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: j1.challengeToken, totpCode: authenticator.generate(row.totpSecret) }) });
  const j2 = (await r2.json()) as { accessToken?: string };
  if (!j2.accessToken) throw new Error(`login step2 failed (${r2.status})`);
  const token = j2.accessToken;
  const authed = (method: string, p: string, body?: unknown) =>
    fetch(`${base}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body ? { body: JSON.stringify(body) } : {}) });

  // 1. Ask for the mailcow API key (typed directly into the terminal).
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q: string): Promise<string> => new Promise((res) => rl.question(q, (a) => res(a.trim())));
  const apiKey = await ask('Mailcow API key for MAIL04 (read-write recommended): ');
  rl.close();
  if (!apiKey) throw new Error('No API key provided');

  // 2. Create the secret.
  const rs = await authed('POST', '/secrets', { type: 'apiKeyNoSecret', label: 'MAIL04 mailcow API', fields: { apiKey } });
  const js = (await rs.json()) as { id?: string; error?: string };
  if (!rs.ok || !js.id) throw new Error(`secret creation failed (${rs.status}): ${js.error ?? ''}`);
  console.log(`Secret created: ${js.id}`);

  // 3. Assign the Mailcow Plugin to MAIL04 with that secret.
  const ra = await authed('POST', `/devices/${MAIL04_ID}/plugins`, { pluginId: MAILCOW_PLUGIN_ID, secretId: js.id });
  const ja = (await ra.json()) as Record<string, unknown>;
  if (!ra.ok) throw new Error(`plugin assignment failed (${ra.status}): ${JSON.stringify(ja).slice(0, 300)}`);
  console.log('Mailcow Plugin assigned to MAIL04.');

  // 4. Force a refresh so the first inventory poll happens now.
  const rr = await authed('POST', '/devices/refresh', { deviceIds: [MAIL04_ID] });
  console.log(`Refresh requested (${rr.status}). Waiting for the poll cycle...`);

  // 5. Poll the mail endpoints until rows appear (max ~90 s).
  for (let i = 0; i < 18; i++) {
    await new Promise((r) => setTimeout(r, 5000));
    const [d, m, a] = await Promise.all([
      authed('GET', '/mail/domains').then((x) => x.json() as Promise<unknown[]>),
      authed('GET', '/mail/mailboxes').then((x) => x.json() as Promise<unknown[]>),
      authed('GET', '/mail/aliases').then((x) => x.json() as Promise<unknown[]>),
    ]);
    if (d.length > 0 || m.length > 0 || a.length > 0) {
      console.log(`\nMAIL INVENTORY: ${d.length} domain(s), ${m.length} mailbox(es), ${a.length} alias(es)`);
      for (const dom of d.slice(0, 10)) console.log('  domain:', JSON.stringify(dom).slice(0, 200));
      return;
    }
  }
  console.log('\nNo mail rows after ~90 s — check the device status / plugin health on the Devices page.');
}

main().catch((e) => { console.error(e.message ?? e); process.exit(1); });
