/**
 * WRITE probe (round 2) on WLC01 — v6 add grammar for Setup/DNS/DNS-List.
 * Round 1 established: `add "NAME" 0 <v4>` works; `""` as a value is rejected.
 * Now determine how to write an IPv6-only entry (columns: Host-name Rtg-tag
 * IP-Address IPV6-Address). Always cleans up afterwards.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-lcos-dns-add-v6.ts [host]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = process.argv[2] ?? '10.25.0.20'; // WLC01 — TEST device, writes OK
const PORT = Number(process.env.LCOS_SSH_PORT ?? 22);
const SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

const OUT_DIR = '/tmp/lcos-dns-add-v6-probe';
fs.mkdirSync(OUT_DIR, { recursive: true });

async function getCredentials(): Promise<{ username: string; password: string }> {
  const envFile = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
  const fromEnv = (process.env.UNM_API_TOKEN ?? /^UNM_API_TOKEN=(.+)$/m.exec(envFile)?.[1]?.trim()) ?? '';
  if (!fromEnv) throw new Error('no UNM_API_TOKEN in .env');

  const sr = await fetch(`${API}/secrets/${SECRET_ID}`, { headers: { Authorization: `Bearer ${fromEnv}` } });
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

  const candidates: Array<{ label: string; cmd: string }> = [
    // v6 in the v4 slot (3 values) — does LCOS type-check per column?
    { label: 'D', cmd: `add "unm-probe-d" 0 fd00::1` },
    // explicit zero-v4 placeholder + v6 (4 values)
    { label: 'E', cmd: `add "unm-probe-e" 0 0.0.0.0 fd00::2` },
  ];

  for (const c of candidates) {
    console.log(`\n===== ${c.label}: ${c.cmd} =====`);
    const out = await runCommand(creds, ['cd /Setup/DNS/DNS-List', c.cmd], 45_000);
    fs.writeFileSync(path.join(OUT_DIR, `${c.label}.txt`), out);
    const lines = out.split('\n').map((l) => l.trimEnd());
    const addIdx = lines.findIndex((l) => l.includes(`----- next: ${c.cmd}`));
    if (addIdx >= 0) console.log(lines.slice(addIdx, addIdx + 12).join('\n'));
    await new Promise((r) => setTimeout(r, 600));
  }

  // Dump the table from the PARENT dir (bare `dir -a` inside the table is fine too — use parent for clarity).
  console.log('\n===== final state =====');
  const out = await runCommand(creds, ['cd /Setup/DNS', 'dir -a DNS-List'], 45_000);
  fs.writeFileSync(path.join(OUT_DIR, 'final.txt'), out);
  const lines = out.split('\n').map((l) => l.trimEnd());
  const start = lines.findIndex((l) => /^\[1\.3\.6\.1\.4\.1\.2356\.11\]\[2\.17\.5\]$/.test(l));
  if (start >= 0) console.log(lines.slice(start, start + 14).join('\n'));

  // Cleanup.
  console.log('\n===== cleanup =====');
  const clean = await runCommand(creds, [
    'cd /',
    `del Setup/DNS/DNS-List/unm-probe-d`,
    `del Setup/DNS/DNS-List/unm-probe-e`,
    'cd /Setup/DNS',
    'dir -a DNS-List',
  ], 60_000);
  fs.writeFileSync(path.join(OUT_DIR, 'cleanup.txt'), clean);
  const cl = clean.split('\n').map((l) => l.trimEnd());
  const cs = cl.findIndex((l) => /^\[1\.3\.6\.1\.4\.1\.2356\.11\]\[2\.17\.5\]$/.test(l));
  if (cs >= 0) console.log(cl.slice(cs, cs + 10).join('\n'));

  console.log('\ndone — artifacts in', OUT_DIR);
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
