/**
 * WRITE probe on WLC01 — how does Setup/DNS/DNS-List handle v4 AND v6 for one
 * name? The table is single-keyed by Host-name with columns
 * (Host-name, Rtg-tag, IP-Address[v4], IPV6-Address[v6]). Known grammar:
 *   add "NAME" 0 <v4>            → v4-only row (v6 defaults to ::)
 *   add "NAME" 0 0.0.0.0 <v6>    → v6-only row (zero-v4 placeholder)
 * Open questions this probe answers:
 *   A) Does `add "NAME" 0 <v4> <v6>` (5 values) put BOTH addresses in ONE row?
 *   B) If not, does a second `add` with the same name UPDATE the other column
 *      (merge), or is it rejected / create nothing?
 * Always cleans up afterwards. Read-only otherwise.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-lcos-dns-dual.ts [host]
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

const OUT_DIR = '/tmp/lcos-dns-dual-probe';
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

function dumpTable(out: string): void {
  const lines = out.split('\n').map((l) => l.trimEnd());
  // The DNS-List rows are the data rows after the separator; print a window.
  const start = lines.findIndex((l) => /^\[1\.3\.6\.1\.4\.1\.2356\.11\]\[2\.17\.5\]$/.test(l));
  if (start >= 0) console.log(lines.slice(start, start + 16).join('\n'));
  else {
    // Fallback: print lines mentioning our probe names.
    const hits = lines.filter((l) => /unm-dual-/.test(l));
    console.log(hits.length ? hits.join('\n') : '(no probe rows found in output)');
  }
}

async function main(): Promise<void> {
  const creds = await getCredentials();
  console.log(`connected to ${HOST}:${PORT} as ${creds.username}`);

  // A) One command, both addresses (5 values).
  console.log('\n===== A: add "unm-dual-a" 0 192.0.2.10 fd00::a =====');
  let out = await runCommand(creds, ['cd /Setup/DNS/DNS-List', 'add "unm-dual-a" 0 192.0.2.10 fd00::a'], 45_000);
  fs.writeFileSync(path.join(OUT_DIR, 'A.txt'), out);
  dumpTable(out);

  // B) Two commands: v4 first, then a second add with the same name + v6 only.
  console.log('\n===== B1: add "unm-dual-b" 0 192.0.2.11 =====');
  out = await runCommand(creds, ['cd /Setup/DNS/DNS-List', 'add "unm-dual-b" 0 192.0.2.11'], 45_000);
  fs.writeFileSync(path.join(OUT_DIR, 'B1.txt'), out);
  dumpTable(out);

  console.log('\n===== B2: add "unm-dual-b" 0 0.0.0.0 fd00::b (same name, v6) =====');
  out = await runCommand(creds, ['cd /Setup/DNS/DNS-List', 'add "unm-dual-b" 0 0.0.0.0 fd00::b'], 45_000);
  fs.writeFileSync(path.join(OUT_DIR, 'B2.txt'), out);
  dumpTable(out);

  // Final state from the parent dir for clarity.
  console.log('\n===== final table =====');
  const fin = await runCommand(creds, ['cd /Setup/DNS', 'dir -a DNS-List'], 45_000);
  fs.writeFileSync(path.join(OUT_DIR, 'final.txt'), fin);
  dumpTable(fin);

  // Cleanup — remove both probe names (whole rows).
  console.log('\n===== cleanup =====');
  const clean = await runCommand(creds, [
    'cd /',
    'del Setup/DNS/DNS-List/unm-dual-a',
    'del Setup/DNS/DNS-List/unm-dual-b',
    'cd /Setup/DNS',
    'dir -a DNS-List',
  ], 60_000);
  fs.writeFileSync(path.join(OUT_DIR, 'cleanup.txt'), clean);
  dumpTable(clean);

  console.log('\ndone — artifacts in', OUT_DIR);
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
