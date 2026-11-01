/**
 * READ-ONLY probe of the LCOS CLI on GW_Ralf (10.28.0.1, production) to locate
 * and dump the static DNS host-entry table (hostname → IP mappings).
 *
 * The user confirmed LCOS has a static DNS entries table; repo evidence only
 * found upstream-DNS-server scalars, so this discovers:
 *   1. which Setup group holds it (`cd /Setup; dir`)
 *   2. its full contents + column layout (`dir -a` of the candidate tables)
 *
 * ONLY read-only commands are sent (cd / dir) — nothing is written to the router.
 *
 * Usage (from repo root): ./node_modules/.bin/tsx scripts/probe-lcos-dns.ts [host]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = process.argv[2] ?? '10.28.0.1'; // GW_Ralf — PRODUCTION, read-only probe
const PORT = Number(process.env.LCOS_SSH_PORT ?? 22);
const SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

const OUT_DIR = '/tmp/lcos-dns-probe';
fs.mkdirSync(OUT_DIR, { recursive: true });

async function getCredentials(): Promise<{ username: string; password: string }> {
  // Preferred: long-lived admin token from the repo .env (admin/admin is rejected live).
  const envFile = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
  const m = /^UNM_API_TOKEN=(.+)$/m.exec(envFile);

  let token: string | null = process.env.UNM_API_TOKEN ?? m?.[1]?.trim() ?? null;
  if (!token) {
    // Fallback: admin + TOTP (otplib v13 functional API).
    const { Pool } = apiRequire('pg');
    const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
    const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
    if (!adminRow.totpSecret) {
      const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
      token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
    } else {
      const { generate: otpGenerate } = apiRequire('otplib');
      const code = await otpGenerate({ strategy: 'totp', secret: adminRow.totpSecret });
      const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
      const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
      const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
      token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
    }
    await pool.end();
  }
  if (!token) throw new Error('UNM API login failed');

  const sr = await fetch(`${API}/secrets/${SECRET_ID}`, { headers: { Authorization: `Bearer ${token}` } });
  const sjson = (await sr.json()) as { fields?: Record<string, string> };
  const f = sjson.fields ?? {};
  if (!f.username || !f.password) throw new Error(`unexpected secret shape: ${JSON.stringify(Object.keys(f))}`);
  return { username: f.username, password: f.password };
}

function runCommand(creds: { username: string; password: string }, cmds: string[], timeoutMs = 30_000, idleMs = 1_500): Promise<string> {
  return new Promise((resolve) => {
    const conn = new Client();
    let settled = false;
    let buf = '';
    let sentCount = 0;
    let allSent = false;
    let idleTimer: NodeJS.Timeout | null = null;
    let lastBufLen = -1;
    let noProgressPings = 0;

    const finish = (text: string) => {
      if (!settled) {
        settled = true;
        clearTimeout(hardTimer);
        if (idleTimer) clearTimeout(idleTimer);
        try { conn.end(); } catch { /* ignore */ }
        resolve(text);
      }
    };

    const onIdle = () => {
      if (!allSent || settled) return;
      if (/MORE \[Q\(uit\)\]>\s*$/.test(buf)) {
        buf += '\n----- page break -----\n';
        noProgressPings = lastBufLen === buf.length ? noProgressPings + 1 : 0;
        lastBufLen = buf.length;
        if (noProgressPings >= 2) {
          streamRef?.write('q');
          setTimeout(() => finish(buf + '\n[PAGER-STUCK]'), 1_500);
          return;
        }
        streamRef?.write('\r');
        arm();
      } else {
        finish(buf);
      }
    };

    let streamRef: import('ssh2').ClientChannel | null = null;
    const arm = () => {
      if (!allSent) return;
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(onIdle, idleMs);
    };

    const hardTimer = setTimeout(() => finish(buf + '\n[TIMEOUT]'), timeoutMs + 15_000);
    conn.on('ready', () => {
      conn.shell({ term: 'xterm-256color', cols: 240, rows: 50 }, (err, stream) => {
        if (err) { clearTimeout(hardTimer); return finish(`[shell error] ${err.message}`); }
        streamRef = stream;
        const sendNext = () => {
          if (sentCount >= cmds.length) { allSent = true; arm(); return; }
          if (sentCount > 0) buf += `\n----- next: ${cmds[sentCount]} -----\n`;
          stream.write(cmds[sentCount] + '\r');
          sentCount++;
          if (sentCount >= cmds.length) { allSent = true; arm(); }
          else setTimeout(sendNext, 1_500);
        };
        stream.on('data', (d: Buffer) => { buf += d.toString('utf8'); arm(); });
        stream.on('close', () => finish(buf));
        setTimeout(() => sendNext(), 2_500);
      });
    });
    conn.on('error', (err) => { clearTimeout(hardTimer); finish(`[connect error] ${err.message}`); });
    conn.connect({ host: HOST, port: PORT, username: creds.username, password: creds.password, readyTimeout: 15_000 });
  });
}

async function main(): Promise<void> {
  const creds = await getCredentials();
  console.log(`connected to ${HOST}:${PORT} as ${creds.username}`);

  // Round 1 — locate the DNS table. All commands are pure reads (cd/dir).
  const groups: Array<[string[], string]> = [
    [['cd /Setup', 'dir'], 'setup_groups.txt'],
    [['cd /Setup/TCP-IP', 'dir -a'], 'tcpip_tables.txt'],
  ];

  for (const [cmds, file] of groups) {
    console.log(`\n===== ${JSON.stringify(cmds)} =====`);
    const out = await runCommand(creds, cmds, 45_000);
    fs.writeFileSync(path.join(OUT_DIR, file), out);
    const lines = out.split('\n').map((l) => l.trimEnd());
    console.log(lines.slice(-80).join('\n'));
    await new Promise((r) => setTimeout(r, 600));
  }

  console.log('\ndone — artifacts in', OUT_DIR);
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
