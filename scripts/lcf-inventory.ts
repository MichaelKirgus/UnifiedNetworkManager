/**
 * READ-ONLY: SFTP-read /config from a LCOS device and print an INVENTORY of the
 * LCF document grouped by table family (the first 4 dot-parts of each cell OID),
 * with column counts and sample values. This maps the writable config surface
 * for action design — the setup tree is not SNMP-walkable on LCOS agents, so
 * the LCF file is the authoritative object list.
 *
 * Usage: ./node_modules/.bin/tsx scripts/lcf-inventory.ts [host] [--full]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const ARGS = process.argv.slice(2);
const HOST = ARGS.find((a) => !a.startsWith('--')) ?? '10.25.0.20';
const FULL = ARGS.includes('--full');
const SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

async function getCredentials(): Promise<{ username: string; password: string }> {
  const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username='admin'`)).rows[0] as { totpSecret: string | null };
  let token: string | null = null;
  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as any).accessToken ?? null;
  } else {
    const { authenticator } = apiRequire('otplib');
    const code = authenticator.generate(adminRow.totpSecret);
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challenge = ((await r1.json()) as any).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = ((await r2.json()) as any).accessToken ?? null;
  }
  await pool.end();
  if (!token) throw new Error('login failed');
  const sr = await fetch(`${API}/secrets/${SECRET_ID}`, { headers: { Authorization: `Bearer ${token}` } });
  return ((await sr.json()) as any).fields ?? {};
}

async function readConfig(creds: { username: string; password: string }): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    const timer = setTimeout(() => fail(new Error('timeout')), 90_000);
    const fail = (e: Error) => { if (!settled) { settled = true; clearTimeout(timer); try { conn.end(); } catch { /* */ } reject(e); } };
    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) return fail(err as Error);
        const chunks: Buffer[] = [];
        const rs = sftp.createReadStream('/config');
        rs.on('data', (d: Buffer) => chunks.push(d));
        rs.on('error', (e: Error) => fail(e));
        rs.on('close', () => { clearTimeout(timer); if (!settled) { settled = true; conn.end(); resolve(Buffer.concat(chunks)); } });
      });
    });
    conn.on('error', (err) => fail(err as Error));
    conn.connect({ host: HOST, port: 22, username: creds.username, password: creds.password, readyTimeout: 20_000 });
  });
}

const CELL_RE = /^\s*\((\d+(?:\.\d+)*)\) (=|==) (.*)$/;
const SCALAR_RE = /^\s{4}(\d+(?:\.\d+)+)\s*=\s*(.*)$/;

async function main() {
  const creds = await getCredentials();
  const raw = await readConfig(creds);
  console.log(`read ${raw.length} bytes from ${HOST}`);
  fs.writeFileSync('/tmp/lcf-inventory-raw.lcf', raw);

  const lines = raw.toString('binary').split('\r\n');
  // family → { cols: Set, rows: Map<rowIdx, count>, samples: string[] }
  const fams = new Map<string, { cols: Map<number, number>; rows: Set<number>; samples: string[]; scalars: number }>();
  let scalarCount = 0;
  for (const line of lines) {
    const cell = CELL_RE.exec(line);
    if (cell) {
      const segs = cell[1].split('.');
      // Table cells have ≥6 parts: family(4).row.col — but some tables nest deeper.
      // Use the first 4 parts as the family key ONLY when there are exactly 6;
      // otherwise use 5 (family of a nested table).
      const famLen = segs.length === 6 ? 4 : 5;
      if (segs.length < famLen + 2) continue;
      const fam = segs.slice(0, famLen).join('.');
      let f = fams.get(fam);
      if (!f) { f = { cols: new Map(), rows: new Set(), samples: [], scalars: 0 }; fams.set(fam, f); }
      const rowIdx = Number(segs[famLen]);
      const colIdx = Number(segs[famLen + 1]);
      f.cols.set(colIdx, (f.cols.get(colIdx) ?? 0) + 1);
      f.rows.add(rowIdx);
      if (f.samples.length < 3 && cell[2] === '=' && cell[3].length > 0 && !/^[0-9a-f]{8,}$/i.test(cell[3])) {
        f.samples.push(`${cell[1]} = ${cell[3].slice(0, 60)}`);
      }
      continue;
    }
    const sc = SCALAR_RE.exec(line);
    if (sc && !line.trim().startsWith('(')) {
      scalarCount++;
      // Scalars: group by first 4 parts too.
      const segs = sc[1].split('.');
      const famLen = Math.min(4, segs.length - 1);
      const fam = segs.slice(0, famLen).join('.');
      let f = fams.get(fam);
      if (!f) { f = { cols: new Map(), rows: new Set(), samples: [], scalars: 0 }; fams.set(fam, f); }
      f.scalars++;
      if (f.samples.length < 3 && sc[2].length > 0) f.samples.push(`${sc[1]} = ${sc[2].slice(0, 60)}`);
    }
  }

  let out = `# LCF inventory — ${HOST} — ${new Date().toISOString()}\n# scalars: ${scalarCount}, table families: ${fams.size}\n\n`;
  for (const [fam, f] of [...fams.entries()].sort((a, b) => a[0].split('.').map(Number).reduce((x, y) => x * 1000 + y, 0) - b[0].split('.').map(Number).reduce((x, y) => x * 1000 + y, 0))) {
    const cols = [...f.cols.entries()].sort((a, b) => a[0] - b[0]).map(([c]) => c);
    out += `## ${fam} — rows=${f.rows.size}, scalars=${f.scalars}, cols=[${cols.join(',')}] (${f.cols.size})\n`;
    for (const s of f.samples) out += `     e.g. ${s}\n`;
  }
  fs.writeFileSync('/tmp/lcf-inventory.txt', out);
  console.log(out);
}

main().catch((e) => { console.error('FAILED:', e.message ?? e); process.exit(1); });
