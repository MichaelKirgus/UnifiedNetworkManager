/**
 * SAFE probe of LCOS table-row creation grammar on WLC01 (TEST device).
 * Every command is either read-only or a valueless `set` that cannot commit
 * anything — the goal is to learn how a NEW row in a table is created
 * (by name? by {position}? via an ACTION?) from LCOS's error text.
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = process.argv[2] ?? '10.25.0.20'; // WLC01 — test device
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

  // Round 10: CREATE a throwaway v3 user (dummy creds) + RW mapping row, then
  // verify via SNMPv3. WLC01 is the test device; both rows are deleted after.
  const groupsA: Array<[string[], string]> = [
    [['cd Setup/SNMP/Communities', 'add ?'], 'wlc_comm_add_help.txt'],
  ];
  // Group B: create the throwaway user (8 columns, tab-header order).
  const groupsB: Array<[string[], string]> = [
    [
      [
        'cd Setup/SNMP/Users',
        'add "probeuser" HMAC-SHA(3) "dummyauthpass1234567890" "" AES128(4) "dummypriappass1234567890" "" active(1)',
        'dir -a',
      ],
      'wlc_users_add_probe.txt',
    ],
  ];
  // Group C: none this round.
  const groupsC: Array<[string[], string]> = [];

  for (const label of ['A', 'B', 'C'] as const) {
    const groups = label === 'A' ? groupsA : label === 'B' ? groupsB : groupsC;
    for (const [cmds, file] of groups) {
      console.log(`\n===== ${label}: ${JSON.stringify(cmds)} =====`);
      const out = await runCommand(creds, cmds, 180_000);
      fs.writeFileSync(path.join(OUT_DIR, file), out);
      const lines = out.split('\n').map((l) => l.trimEnd());
      console.log(lines.slice(-30).join('\n'));
      await new Promise((r) => setTimeout(r, 600));
    }
  }

  // Group E (separate session): final Users table state + cleanup if needed.
  const outE = await runCommand(creds, ['cd Setup/SNMP/Users', 'dir -a'], 45_000);
  fs.writeFileSync(path.join(OUT_DIR, 'wlc_users_after_create.txt'), outE);
  console.log('\n===== E: Users table after create =====');
  const hasProbe = /probeuser/.test(outE);
  if (hasProbe) {
    const outF = await runCommand(creds, ['cd Setup/SNMP/Users', 'del probeuser'], 45_000);
    fs.writeFileSync(path.join(OUT_DIR, 'wlc_users_del_probe.txt'), outF);
    console.log('\n===== F: del probeuser =====');
    const lines = outF.split('\n').map((l) => l.trimEnd());
    console.log(lines.slice(-15).join('\n'));
  } else {
    console.log('\n(no probe row found — nothing to delete)');
  }

  console.log('\ndone — artifacts in', OUT_DIR);
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
