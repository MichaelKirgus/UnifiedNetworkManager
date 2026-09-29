/**
 * READ-ONLY probe: walk the ENTIRE lcsSetup tree (.1.3.6.1.4.1.2356.11.2) on a
 * LCOS device and dump every OID → value to /tmp/lcos-setup-tree.txt, grouped by
 * second-level group (11.2.<group>). This inventories the writable config
 * surface for designing new actions. No SETs are performed.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-lcos-setup-tree.ts [host]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const HOST = process.argv[2] ?? '10.25.0.20'; // WLC01 — test device
const SECRET_ID = process.env.LCOS_SNMPV3_SECRET_ID ?? 'adeb8556-7245-43c4-b67e-20941bc8a10b';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const snmpRequire = createRequire(path.resolve(process.cwd(), 'packages', 'snmp-client', 'package.json'));
const { snmpWalk, buildSnmpCredentials } = snmpRequire('./dist/index.js') as typeof import('../packages/snmp-client/src/index');

async function main() {
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
  const fields = ((await sr.json()) as any).fields ?? {};
  const built = buildSnmpCredentials(fields);
  if (built.error || !built.creds) throw new Error(`credential error: ${built.error}`);

  // Walk the whole setup tree in one go; split per-group on timeout.
  const opts = { timeoutMs: 9_000, retries: 1 };
  let all = new Map<string, unknown>();
  try {
    console.log('walking .11.2 (whole tree)…');
    all = await snmpWalk(HOST, built.creds, '.1.3.6.1.4.1.2356.11.2', opts);
    console.log(`→ ${all.size} varbinds`);
  } catch (err) {
    console.log('whole-tree walk failed:', (err as Error).message, '— falling back to per-group walks');
    for (let g = 0; g <= 60; g++) {
      const sub = `.1.3.6.1.4.1.2356.11.2.${g}`;
      try {
        const m = await snmpWalk(HOST, built.creds, sub, opts);
        for (const [k, v] of m) all.set(k, v);
        if (m.size) console.log(`  ${sub} → ${m.size}`);
      } catch { /* group absent */ }
    }
  }

  // Group by second-level segment and dump.
  const groups = new Map<string, Array<[string, unknown]>>();
  for (const [oid, v] of all) {
    const segs = oid.replace(/^\./, '').split('.');
    const group = `${segs[0]}.${segs[1]}.${segs[2]}`; // 1.3.6… no — use the .11.2.<g> part:
    void segs;
    const m = /^\.1\.3\.6\.1\.4\.1\.2356\.11\.2\.(\d+)(?:\.(.*))?$/.exec(oid);
    if (!m) continue;
    const key = `11.2.${m[1]}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push([oid, v]);
  }

  let out = `# lcsSetup tree dump — ${HOST} — ${new Date().toISOString()}\n# total varbinds: ${all.size}\n\n`;
  for (const [g, rows] of [...groups.entries()].sort()) {
    out += `## group ${g} (${rows.length} objects)\n`;
    for (const [oid, v] of rows) {
      const val = Buffer.isBuffer(v) ? `<${v.length}B ${v.toString('hex').slice(0, 48)}…>` : String(v);
      out += `${oid} = ${val}\n`;
    }
    out += '\n';
  }
  fs.writeFileSync('/tmp/lcos-setup-tree.txt', out);
  console.log(`\nwrote /tmp/lcos-setup-tree.txt (${out.length} bytes, ${groups.size} groups)`);
  for (const [g, rows] of [...groups.entries()].sort()) console.log(`  ${g}: ${rows.length}`);
}

main().catch((e) => { console.error('FAILED:', e.message ?? e); process.exit(1); });
