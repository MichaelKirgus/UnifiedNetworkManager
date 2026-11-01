/**
 * WRITE probe on WLC01 (10.25.0.20, LCOS vRouter TEST device — writes allowed)
 * to determine the correct `add` grammar for Setup/DNS/DNS-List. The live E2E
 * rejected `add "NAME" 0 <ip> ""` with `Value invalid: ")"`. This tries a few
 * candidate grammars in sequence and dumps `dir -a DNS-List` after each; it
 * always cleans up (del) whatever it created, so the device ends empty.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-lcos-dns-add.ts [host]
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

const OUT_DIR = '/tmp/lcos-dns-add-probe';
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

/** Extracts the DNS-List rows section from a `dir -a DNS-List` dump. */
function dnsRows(out: string): string[] {
  const lines = out.split('\n').map((l) => l.trimEnd());
  const start = lines.findIndex((l) => /^\[1\.3\.6\.1\.4\.1\.2356\.11\]\[2\.17\.5\]$/.test(l));
  if (start < 0) return [];
  const rows: string[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i];
    if (!l || /^={3,}$/.test(l.replace(/-+$/, '')) ) continue; // header/separator noise
    if (/^root@/.test(l) || /^>/.test(l) || /----- next:/.test(l)) break;
    rows.push(l);
  }
  return rows.filter((r) => r.length > 0 && !/^Host-name/.test(r) && !/^\[1\]/.test(r));
}

async function main(): Promise<void> {
  const creds = await getCredentials();
  console.log(`connected to ${HOST}:${PORT} as ${creds.username}`);

  // Candidate grammars for `add` in Setup/DNS/DNS-List (columns: Host-name Rtg-tag IP-Address IPV6-Address).
  const candidates: Array<{ label: string; cmd: string }> = [
    { label: 'A: name tag ip (3 values, no v6 col)', cmd: `add "unm-probe-a" 0 192.168.178.250` },
    { label: 'B: name tag ip "" (4 values, empty quoted v6)', cmd: `add "unm-probe-b" 0 192.168.178.250 ""` },
    { label: 'C: name tag ip :: (4 values, zero-addr v6)', cmd: `add "unm-probe-c" 0 192.168.178.250 ::` },
  ];

  for (const c of candidates) {
    console.log(`\n===== ${c.label}: ${c.cmd} =====`);
    const out = await runCommand(creds, ['cd /Setup/DNS/DNS-List', c.cmd, 'dir -a DNS-List'], 45_000);
    fs.writeFileSync(path.join(OUT_DIR, `${c.label[0]}.txt`), out);
    // Show the raw add response (between the command echo and the dir output).
    const lines = out.split('\n').map((l) => l.trimEnd());
    const addIdx = lines.findIndex((l) => l.includes(`----- next: ${c.cmd}`));
    if (addIdx >= 0) console.log(lines.slice(addIdx, addIdx + 8).join('\n'));
    const rows = dnsRows(out);
    console.log(`rows after: ${JSON.stringify(rows)}`);
    await new Promise((r) => setTimeout(r, 600));
  }

  // Cleanup — remove every probe row we may have created.
  console.log('\n===== cleanup =====');
  const clean = await runCommand(creds, [
    'cd /',
    `del Setup/DNS/DNS-List/unm-probe-a`,
    `del Setup/DNS/DNS-List/unm-probe-b`,
    `del Setup/DNS/DNS-List/unm-probe-c`,
    'cd /Setup/DNS',
    'dir -a DNS-List',
  ], 60_000);
  fs.writeFileSync(path.join(OUT_DIR, 'cleanup.txt'), clean);
  console.log(`rows after cleanup: ${JSON.stringify(dnsRows(clean))}`);

  console.log('\ndone — artifacts in', OUT_DIR);
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
