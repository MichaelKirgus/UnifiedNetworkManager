/**
 * READ-ONLY probe — is the LCOS static DNS table (Setup/DNS/DNS-List, CLI OID
 * banner [1.3.6.1.4.1.2356.11][2.17.5]) exposed via SNMP?
 *
 * Walks the whole .11.2.17 subtree on a device (default GW_Ralf 10.28.0.1 —
 * PRODUCTION, read-only) and prints every OID + value so we can see:
 *   - which DNS tables exist in the SNMP config mirror (DNS-List = .5?)
 *   - the row index encoding (length-prefixed hostname text? int?)
 *   - the column layout (Host-name / Rtg-tag / IP-Address / IPV6-Address)
 *
 * No writes, no SETs. Usage: ./node_modules/.bin/tsx scripts/probe-lcos-dns-snmp.ts [host]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = process.argv[2] ?? '10.28.0.1'; // GW_Ralf — PRODUCTION, read-only!
const SNMP_SECRET_ID = process.env.LCOS_SNMPV3_SECRET_ID ?? 'adeb8556-7245-43c4-b67e-20941bc8a10b';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const snmpRequire = createRequire(path.resolve(process.cwd(), 'packages', 'snmp-client', 'package.json'));
const { snmpWalk } = snmpRequire('./dist/index.js') as typeof import('../packages/snmp-client/src/index');

async function getToken(): Promise<string> {
  // Preferred: long-lived admin token from the repo .env (admin/admin is rejected live).
  const envFile = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
  const m = /^UNM_API_TOKEN=(.+)$/m.exec(envFile);
  const tokenEnv = process.env.UNM_API_TOKEN ?? m?.[1]?.trim() ?? null;
  if (tokenEnv) return tokenEnv;
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username='admin'`)).rows[0] as { totpSecret: string | null };
  let token: string | null = null;
  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  } else {
    const { generate } = apiRequire('otplib');
    const code = await generate({ strategy: 'totp', secret: adminRow.totpSecret });
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
  const j = (await r.json()) as { fields?: Record<string, string> };
  return j.fields ?? {};
}

function fmt(v: unknown): string {
  if (v === null || v === undefined) return '(null)';
  if (Buffer.isBuffer(v)) return `<${v.length}B ${JSON.stringify(v.toString('utf8').replace(/[^\x20-\x7e]/g, '?'))}>`;
  return String(v);
}

async function main(): Promise<void> {
  const snmp = await getSecretFields(SNMP_SECRET_ID);
  console.log(`SNMPv3 secret: user=${snmp.username} level=${snmp.securityLevel} auth=${snmp.authProtocol} priv=${snmp.privProtocol}`);
  const creds = {
    version: 'v3' as const,
    username: snmp.username ?? '',
    securityLevel: (snmp.securityLevel ?? 'authPriv') as 'noAuthNoPriv' | 'authNoPriv' | 'authPriv',
    authProtocol: (snmp.authProtocol === 'MD5' ? 'MD5' : 'SHA') as 'MD5' | 'SHA',
    authPassword: snmp.authPassword,
    privProtocol: (snmp.privProtocol ?? 'AES') as 'DES' | 'AES',
    privPassword: snmp.privPassword,
  };
  if (!creds.username || !creds.authPassword) throw new Error('SNMP secret missing username/authPassword');

  const opts = { timeoutMs: 5_000, retries: 2, port: 161 };

  // 1. The DNS subtree — Setup/DNS group (CLI banner said .2.17.x).
  console.log(`\n=== walk ${HOST} .1.3.6.1.4.1.2356.11.2.17 ===`);
  try {
    const m = await snmpWalk(HOST, creds, ['1.3.6.1.4.1.2356.11.2.17'], opts);
    console.log(`${m.size} OIDs`);
    for (const [oid, v] of [...m.entries()].sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))) {
      console.log(`  ${oid.replace(/^1\.3\.6\.1\.4\.1\.2356\./, '')} = ${fmt(v)}`);
    }
  } catch (e) {
    console.log(`walk failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  // 2. Fallback — if .2.17 is empty/absent, the DNS table may live elsewhere in
  //    the setup tree; walk the whole .11.2 config mirror (bounded: it's small).
  console.log(`\n=== walk ${HOST} .1.3.6.1.4.1.2356.11.2 (setup/config mirror) ===`);
  try {
    const m = await snmpWalk(HOST, creds, ['1.3.6.1.4.1.2356.11.2'], opts);
    console.log(`${m.size} OIDs — table bases (.x.y with no further index):`);
    // Group by the first 3 suffix components to reveal the table layout.
    const groups = new Map<string, number>();
    for (const oid of m.keys()) {
      const parts = oid.replace(/^1\.3\.6\.1\.4\.1\.2356\./, '').split('.');
      // .2.<group>.<table>[.col...] — show group.table pairs that have rows.
      if (parts.length >= 4) groups.set(`${parts[0]}.${parts[1]}.${parts[2]}`, (groups.get(`${parts[0]}.${parts[1]}.${parts[2]}`) ?? 0) + 1);
    }
    for (const [k, n] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))) {
      console.log(`  .${k} — ${n} OIDs`);
    }
  } catch (e) {
    console.log(`walk failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

main().catch((e) => {
  console.error('probe error:', e);
  process.exit(1);
});
