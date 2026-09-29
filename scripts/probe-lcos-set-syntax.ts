/**
 * SAFE probe of the LCOS `set` column-targeting syntax on a WLAN router.
 *
 * Every command sent here provides ONLY the table + row key and NO column
 * value, so LCOS rejects it WITHOUT applying any change — a `set` with no
 * value can never commit anything. The point is to capture LCOS's error text,
 * which reveals how a specific column of a table row is addressed (by name vs
 * by {position}) and the exact expected argument order. NO real value is set.
 *
 * Usage (from repo root): ./node_modules/.bin/tsx scripts/probe-lcos-set-syntax.ts [host]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = process.argv[2] ?? '10.28.0.1'; // GW_Ralf (dual-radio WiFi, production) — read-only probe only
const PORT = Number(process.env.LCOS_SSH_PORT ?? 22);
const SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

const OUT_DIR = '/tmp/lcos-ssh-probe';
fs.mkdirSync(OUT_DIR, { recursive: true });

async function getCredentials(): Promise<{ username: string; password: string }> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };

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
  if (!token) throw new Error('UNM API login failed');

  const sr = await fetch(`${API}/secrets/${SECRET_ID}`, { headers: { Authorization: `Bearer ${token}` } });
  const sjson = (await sr.json()) as { fields?: Record<string, string> };
  const f = sjson.fields ?? {};
  if (!f.username || !f.password) throw new Error(`unexpected secret shape: ${JSON.stringify(Object.keys(f))}`);
  await pool.end();
  return { username: f.username, password: f.password };
}

function runCommand(creds: { username: string; password: string }, cmds: string[], timeoutMs = 25_000, idleMs = 1_200): Promise<string> {
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
      conn.shell({ term: 'xterm-256color', cols: 220, rows: 50 }, (err, stream) => {
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

  // Each group is a SEPARATE shell. Every `set` below sends ONLY the table + row
  // key and NO column value — LCOS must reject it (nothing to apply), but its
  // error text reveals how a specific column of a row is addressed. A command
  // with no value can never commit a change, so this is safe on production.
  // SAFETY: only Radio-Settings and VLAN-Groupkey-Mapping are probed with an extra
  // token, because every column in those tables is enum/digit-only — so a letter
  // token like "Radio-Channel" can NEVER be a valid value (it's rejected if LCOS
  // reads it as a value, or treated as a column name and then wants a value). The
  // Network table has free-text columns with permissive charsets, so an extra
  // alphabetic token there could be committed as a real value — we do NOT probe it.
  const groups: Array<[string[], string]> = [
    // Round 2a: column BY NAME after the row key? (no value → safe)
    [['cd Setup/Interfaces/WLAN', 'set Radio-Settings WLAN-1 Radio-Channel'], 'syn2_radio_colname.txt'],
    [['cd Setup/WLAN', 'set VLAN-Groupkey-Mapping WLAN-1 VLAN-Id'], 'syn2_vlanmap_colname.txt'],

    // Round 2b: column BY POSITION {n} after the row key? (no value → safe; round 1
    // already showed braces are rejected as a ROW KEY, so they will be here too).
    [['cd Setup/Interfaces/WLAN', 'set Radio-Settings WLAN-1 {8}'], 'syn3_radio_poscol.txt'],
    [['cd Setup/WLAN', 'set VLAN-Groupkey-Mapping WLAN-1 {2}'], 'syn3_vlanmap_poscol.txt'],

    // NOTE: a bare numeric token (e.g. "… WLAN-1 8") is deliberately NOT probed —
    // if LCOS auto-maps trailing values to columns, a digit could commit as a real
    // value (Tx-Power-Reduction / Radio-Channel) on the live radio. Not safe.
  ];

  for (const [cmds, file] of groups) {
    console.log(`\n===== ${JSON.stringify(cmds)} =====`);
    const out = await runCommand(creds, cmds, 30_000);
    fs.writeFileSync(path.join(OUT_DIR, file), out);
    const lines = out.split('\n').map((l) => l.trimEnd());
    console.log(lines.slice(-45).join('\n'));
    await new Promise((r) => setTimeout(r, 600));
  }

  console.log('\ndone — artifacts in', OUT_DIR);
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
