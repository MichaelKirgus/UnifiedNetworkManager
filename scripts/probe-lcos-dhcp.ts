/**
 * READ-ONLY probe of the LCOS DHCP setup tree over SSH (WLC01, 10.25.0.20).
 * Goal: find where static MAC→IP reservations live in Setup/DHCP and learn the
 * table column layout + add/del/set syntax for them. ONLY read commands are
 * sent (cd / dir / print / ?) — no writes.
 *
 * Usage (from repo root): ./node_modules/.bin/tsx scripts/probe-lcos-dhcp.ts [host]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = process.argv[2] ?? '10.25.0.20'; // WLC01 — test device (vRouter)
const PORT = Number(process.env.LCOS_SSH_PORT ?? 22);
const SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

// ssh2 lives in the plugin-sdk's node_modules — resolve it from there.
const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const jwt = apiRequire('jsonwebtoken') as { sign: (payload: Record<string, unknown>, secret: string, opts?: { expiresIn?: number | string }) => string };

function envValue(key: string): string | null {
  try {
    const m = new RegExp(`^${key}=(.+)$`, 'm').exec(fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

const OUT_DIR = '/tmp/lcos-dhcp-probe';
fs.mkdirSync(OUT_DIR, { recursive: true });

async function getCredentials(): Promise<{ username: string; password: string }> {
  const pg = apiRequire('pg') as typeof import('pg');
  const pool = new pg.Pool({ connectionString: envValue('DATABASE_URL') ?? 'postgres://unm:unm@localhost:5432/unm' });
  // Mint an admin JWT directly (admin has TOTP enrolled — API login is flaky).
  const row = (await pool.query(`SELECT id, username, roles, permissions FROM users WHERE username = 'admin'`)).rows[0] as
    | { id: string; username: string; roles: unknown; permissions: unknown }
    | undefined;
  if (!row) throw new Error('no admin user');
  const parseArr = (v: unknown): string[] => {
    if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string');
    if (typeof v !== 'string') return [];
    try {
      const p = JSON.parse(v);
      return Array.isArray(p) ? p.filter((x: unknown): x is string => typeof x === 'string') : [];
    } catch {
      return [];
    }
  };
  const token = jwt.sign({ sub: row.id, username: row.username, roles: parseArr(row.roles), permissions: parseArr(row.permissions), amr: ['totp'] }, envValue('JWT_SECRET') ?? 'dev-secret', { expiresIn: 3600 });

  const sr = await fetch(`${API}/secrets/${SECRET_ID}`, { headers: { Authorization: `Bearer ${token}` } });
  const sjson = (await sr.json()) as { fields?: Record<string, string> };
  const f = sjson.fields ?? {};
  if (!f.username || !f.password) throw new Error(`unexpected secret shape: ${JSON.stringify(Object.keys(f))}`);
  await pool.end();
  return { username: f.username, password: f.password };
}

/** Runs commands sequentially in one shell; handles the LCOS pager (Enter advances). */
function runCommand(creds: { username: string; password: string }, cmds: string[], timeoutMs = 30_000, idleMs = 1_200): Promise<string> {
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

  // Phase 1 — discover the DHCP setup tree. Each command its OWN element (LCOS
  // rejects compound `cd X; dir` strings).
  const groups: Array<[string[], string]> = [
    [['cd Setup/DHCP/Hosts', 'dir -a .'], 'dhcp_hosts.txt'],
    [['cd Setup/DHCP/Ports', 'dir -a .'], 'dhcp_ports.txt'],
  ];

  for (const [cmds, file] of groups) {
    console.log(`\n===== ${JSON.stringify(cmds)} =====`);
    const out = await runCommand(creds, cmds);
    fs.writeFileSync(path.join(OUT_DIR, file), out);
    const lines = out.split('\n').map((l) => l.trimEnd());
    console.log(lines.slice(0, 120).join('\n'));
    if (lines.length > 120) console.log(`... (${lines.length} lines total — full output in ${file})`);
    await new Promise((r) => setTimeout(r, 500));
  }

  console.log('\ndone — artifacts in', OUT_DIR);
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
