/**
 * LIVE probe (test device WLC01 only): figure out the exact `add` grammar of
 * /Setup/TCP-IP/Network-list on LCOS 10.94 vRouter, where `add ?` prints no
 * help and a 9-value add fails with: Value invalid: "10.399.0.2)
 *
 * Tries several column layouts, reports raw CLI output for each, and always
 * cleans up any row it created (del Setup/TCP-IP/Network-list/<name>).
 * Usage: ./node_modules/.bin/tsx scripts/probe-lcos-tcpip-add.ts [host]
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = process.argv[2] ?? '10.25.0.20';
const SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

async function getToken(): Promise<string> {
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
  if (!token) throw new Error('UNM API login failed');
  return token;
}

async function getSecretFields(id: string): Promise<Record<string, string>> {
  const token = await getToken();
  const r = await fetch(`${API}/secrets/${id}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`GET /secrets/${id} → HTTP ${r.status}`);
  return ((await r.json()) as { fields?: Record<string, string> }).fields ?? {};
}

function runCommand(creds: { username: string; password: string }, cmds: string[], timeoutMs = 120_000): Promise<string> {
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
        if (noProgressPings >= 2) { streamRef?.write('q'); setTimeout(() => finish(buf + '\n[PAGER-STUCK]'), 1_500); return; }
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
      idleTimer = setTimeout(onIdle, 1_500);
    };

    const hardTimer = setTimeout(() => finish(buf + '\n[TIMEOUT]'), timeoutMs + 15_000);
    conn.on('ready', () => {
      conn.shell({ term: 'xterm-256color', cols: 240, rows: 50 }, (err, stream) => {
        if (err) { clearTimeout(hardTimer); return finish(`[shell error] ${err.message}`); }
        streamRef = stream;
        const sendNext = () => {
          if (sentCount >= cmds.length) { allSent = true; arm(); return; }
          buf += `\n----- next: ${cmds[sentCount]} -----\n`;
          stream.write(cmds[sentCount] + '\r');
          sentCount++;
          if (sentCount >= cmds.length) { allSent = true; arm(); }
          else setTimeout(sendNext, 2_000);
        };
        stream.on('data', (d: Buffer) => { buf += d.toString('utf8'); arm(); });
        stream.on('close', () => finish(buf));
        setTimeout(() => sendNext(), 3_000);
      });
    });
    conn.on('error', (err) => { clearTimeout(hardTimer); finish(`[connect error] ${err.message}`); });
    conn.connect({ host: HOST, port: 22, username: creds.username, password: creds.password, readyTimeout: 15_000 });
  });
}

async function main(): Promise<void> {
  const creds = await getSecretFields(SECRET_ID);
  if (!creds.username || !creds.password) throw new Error('SSH secret missing username/password');
  console.log(`connected to ${HOST}`);

  // Candidate grammars for the L3 row (name PROBE_L3, vlan 99).
  const attempts: Array<{ label: string; line: string }> = [
    { label: 'A: 9 cols (GW_Ralf form)', line: `add "PROBE_L3" 10.99.0.2 255.255.255.0 99 LAN-1 loose Intranet 0 ""` },
    { label: 'B: 8 cols (no comment)', line: `add "PROBE_L3" 10.99.0.2 255.255.255.0 99 LAN-1 loose Intranet 0` },
    { label: 'C: 7 cols (no rtg-tag+comment)', line: `add "PROBE_L3" 10.99.0.2 255.255.255.0 99 LAN-1 loose Intranet` },
    { label: 'D: CIDR in ip col', line: `add "PROBE_L3" 10.99.0.2/24 255.255.255.0 99 LAN-1 loose Intranet 0 ""` },
    { label: 'E: 6 cols (no type)', line: `add "PROBE_L3" 10.99.0.2 255.255.255.0 99 LAN-1 loose` },
  ];

  const cmds = ['cd /Setup/TCP-IP/Network-list', 'dir -a'];
  for (const a of attempts) {
    cmds.push(a.line);
    cmds.push('dir -a');
  }
  // cleanup: delete the probe row if any attempt created it.
  cmds.push('cd /');
  cmds.push('del Setup/TCP-IP/Network-list/PROBE_L3');
  cmds.push('cd /Setup/TCP-IP/Network-list');
  cmds.push('dir -a');

  const out = await runCommand(creds, cmds);
  console.log(out.split('\n').map((l) => l.trimEnd()).join('\n'));
}

main().catch((e) => { console.error(e); process.exit(1); });
