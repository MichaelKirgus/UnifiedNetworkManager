/**
 * READ-ONLY probe of the LCOS router CLI over SSH (WLC01, 10.25.0.20).
 *
 * The web UI locked out repeated failed POSTs ("Access Forbidden"), so this
 * probes the interactive CLI instead: discovers the command syntax for config
 * backup/restore and settings changes. ONLY read-only commands are sent
 * (help / show / print) — no writes, no reboot.
 *
 * Usage (from repo root): ./node_modules/.bin/tsx scripts/probe-lcos-ssh.ts [host]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = process.argv[2] ?? '10.25.0.20';
const PORT = Number(process.env.LCOS_SSH_PORT ?? 22);
const SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

// ssh2 lives in the plugin-sdk's node_modules — resolve it from there.
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

/**
 * Runs one or more commands in a fresh shell (sent sequentially) and returns the
 * combined output produced AFTER sending started. Termination: after ALL commands
 * are sent, wait for `idleMs` of silence — but if the LCOS pager prompt
 * "MORE [Q(uit)]>" appears, send Enter to continue (Space does NOT advance on
 * this firmware). If two consecutive pings make no progress, quit the pager.
 */
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

    // After the last data chunk: continue paging, or finish when idle.
    const onIdle = () => {
      if (!allSent || settled) return;
      if (/MORE \[Q\(uit\)\]>\s*$/.test(buf)) {
        buf += '\n----- page break -----\n';
        noProgressPings = lastBufLen === buf.length ? noProgressPings + 1 : 0;
        lastBufLen = buf.length;
        if (noProgressPings >= 2) {
          // Pager is stuck — quit it and finish with what we have.
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
          if (sentCount >= cmds.length) {
            allSent = true;
            arm();
            return;
          }
          if (sentCount > 0) buf += `\n----- next: ${cmds[sentCount]} -----\n`;
          stream.write(cmds[sentCount] + '\r');
          sentCount++;
          if (sentCount >= cmds.length) { allSent = true; arm(); }
          else setTimeout(sendNext, 1_500);
        };
        stream.on('data', (d: Buffer) => {
          buf += d.toString('utf8');
          arm();
        });
        stream.on('close', () => finish(buf));
        // Wait for the banner to settle, then start sending.
        setTimeout(() => {
          sendNext();
        }, 2_500);
      });
    });
    conn.on('error', (err) => { clearTimeout(hardTimer); finish(`[connect error] ${err.message}`); });
    conn.connect({ host: HOST, port: PORT, username: creds.username, password: creds.password, readyTimeout: 15_000 });
  });
}

async function main(): Promise<void> {
  const creds = await getCredentials();
  console.log(`connected to ${HOST}:${PORT} as ${creds.username}`);

  // Read-only discovery: menu tree + help texts. Each group in its own shell.
  const groups: Array<[string[], string, number?]> = [
    [['cd Setup/Interfaces/WLAN', 'set Radio-Settings ?'], 'gw_set_radio.txt', 90_000],
    [['cd Setup/Interfaces/WLAN', 'set Encryption ?'], 'gw_set_encryption.txt', 90_000],
    [['cd Setup/WLAN', 'dir -a'], 'gw_wlan_setup_dir_a.txt', 60_000],
    [['cd Setup/WLAN', 'set VLAN-Groupkey-Mapping ?'], 'gw_set_vlanmap.txt', 90_000],
    [['cd Setup/Interfaces/WLAN', 'print Network WLAN-1'], 'gw_print_network_wlan1.txt', 60_000],
    [['cd Setup/Interfaces/WLAN', 'print Radio-Settings WLAN-1'], 'gw_print_radio_wlan1.txt', 60_000],
  ];

  for (const [cmds, file, timeout] of groups) {
    console.log(`\n===== ${JSON.stringify(cmds)} =====`);
    const out = await runCommand(creds, cmds, timeout ?? 25_000);
    fs.writeFileSync(path.join(OUT_DIR, file), out);
    // Print a trimmed view.
    const lines = out.split('\n').map((l) => l.trimEnd());
    console.log(lines.slice(0, 80).join('\n'));
    if (lines.length > 80) console.log(`... (${lines.length} lines total — full output in ${file})`);
    await new Promise((r) => setTimeout(r, 500));
  }

  console.log('\ndone — artifacts in', OUT_DIR);
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
