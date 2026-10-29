/**
 * READ-ONLY probe of WLC01 (10.25.0.20, LCOS vRouter test device) to dump the
 * Setup/DNS group + DNS-List table layout. GW_Ralf (1803VAW-5G, 10.94) shows
 * [Host-name,Rtg-tag,IP-Address,IPV6-Address] — but WLC01 may run a different
 * LCOS build with a different column set, which would explain the live
 * `add "NAME" 0 <ip> ""` rejection ("Value invalid: )").
 *
 * ONLY read-only commands are sent (cd / dir). Usage:
 *   ./node_modules/.bin/tsx scripts/probe-lcos-dns-wlc.ts [host]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = process.argv[2] ?? '10.25.0.20'; // WLC01 — test device, writes allowed but this probe is read-only
const PORT = Number(process.env.LCOS_SSH_PORT ?? 22);
const SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

const OUT_DIR = '/tmp/lcos-dns-wlc-probe';
fs.mkdirSync(OUT_DIR, { recursive: true });

async function getCredentials(): Promise<{ username: string; password: string }> {
  const envFile = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
  const fromEnv = (process.env.UNM_API_TOKEN ?? /^UNM_API_TOKEN=(.+)$/m.exec(envFile)?.[1]?.trim()) ?? '';
  let token: string | null = fromEnv || null;
  if (!token) throw new Error('no UNM_API_TOKEN in .env');

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
      if (/MORE \[Q\(uit\)\]>\s*$/.test(buf)) { streamRef?.write('\r'); arm(); }
      else finish(buf);
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

  const groups: Array<[string[], string]> = [
    [['cd /', 'dir'], 'root_dir.txt'],
    [['cd /Setup/DNS', 'dir -a'], 'dns_group.txt'],
    [['cd /Setup/DNS', 'dir -a DNS-List'], 'dns_list_rows.txt'],
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
