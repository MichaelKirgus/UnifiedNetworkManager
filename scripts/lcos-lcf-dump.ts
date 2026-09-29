/**
 * Debug: SFTP-read /config from a LCOS device and print the raw lines of the
 * SNMP Users (1.2.9.32) and Groups (1.2.9.28) table regions, plus every line
 * mentioning probeuser/root. Read-only.
 *
 * Usage: ./node_modules/.bin/tsx scripts/lcos-lcf-dump.ts [host]
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const HOST = process.argv[2] ?? '10.25.0.20';
const PORT = Number(process.env.LCOS_SSH_PORT ?? 22);
const SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

async function getCredentials(): Promise<{ username: string; password: string }> {
  const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username='admin'`)).rows[0] as { totpSecret: string | null };
  let token: string | null = null;
  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  } else {
    const { authenticator } = apiRequire('otplib');
    const code = authenticator.generate(adminRow.totpSecret);
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
  }
  await pool.end();
  if (!token) throw new Error('login failed');
  const sr = await fetch(`${API}/secrets/${SECRET_ID}`, { headers: { Authorization: `Bearer ${token}` } });
  const f = ((await sr.json()) as { fields?: Record<string, string> }).fields ?? {};
  return { username: f.username, password: f.password };
}

async function readConfig(creds: { username: string; password: string }): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    const timer = setTimeout(() => fail(new Error('timeout')), 90_000);
    const fail = (e: Error) => { if (!settled) { settled = true; clearTimeout(timer); try { conn.end(); } catch { /* */ } reject(e); } };
    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) return fail(err as Error);
        const chunks: Buffer[] = [];
        const rs = sftp.createReadStream('/config');
        rs.on('data', (d: Buffer) => chunks.push(d));
        rs.on('error', (e: Error) => fail(e));
        rs.on('close', () => { clearTimeout(timer); if (!settled) { settled = true; conn.end(); resolve(Buffer.concat(chunks)); } });
      });
    });
    conn.on('error', (err) => fail(err as Error));
    conn.connect({ host: HOST, port: PORT, username: creds.username, password: creds.password, readyTimeout: 20_000 });
  });
}

async function main() {
  const creds = await getCredentials();
  const raw = await readConfig(creds);
  console.log(`read ${raw.length} bytes`);
  const lines = raw.toString('binary').split('\r\n');

  // Print every line that mentions the SNMP tables or our users.
  let inRegion = false;
  for (const l of lines) {
    const t = l.trim();
    if (/^<1\.2\.9\.(28|32)>$/.test(t)) inRegion = true;
    else if (/^</.test(t) && !/^<1\.2\.9\.(28|32)\./.test(t)) inRegion = false;
    if (inRegion || /probeuser|\broot\b/.test(l)) {
      console.log(JSON.stringify(l));
    }
  }
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
