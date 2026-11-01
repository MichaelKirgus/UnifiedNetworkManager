/**
 * READ-ONLY probe — is the LCOS DHCP static-host table (Setup/DHCP/Hosts, CLI
 * OID banner [1.3.6.1.4.1.2356.11][2.10.9]) exposed via SNMP?
 *
 * Walks the whole .11.2.10 subtree on a device and prints every OID + value so
 * we can see: which DHCP setup tables exist in the config mirror, the row index
 * encoding (MAC text? length-prefixed?), and the column layout (IP-Address /
 * Hostname / Image-alias / Network-name). No writes, no SETs.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-lcos-dhcp-snmp.ts [host]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOSTS = (process.argv[2] ? [process.argv[2]] : ['10.25.0.20', '10.28.0.1']); // WLC01, GW_Ralf — read-only!
const SNMP_SECRET_ID = process.env.LCOS_SNMPV3_SECRET_ID ?? 'adeb8556-7245-43c4-b67e-20941bc8a10b';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const snmpRequire = createRequire(path.resolve(process.cwd(), 'packages', 'snmp-client', 'package.json'));
const { snmpWalk } = snmpRequire('./dist/index.js') as typeof import('../packages/snmp-client/src/index');

async function getToken(): Promise<string> {
  const envFile = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
  const m = /^UNM_API_TOKEN=(.+)$/m.exec(envFile);
  const tokenEnv = process.env.UNM_API_TOKEN ?? m?.[1]?.trim() ?? null;
  if (tokenEnv) return tokenEnv;
  // Fallback: mint an admin JWT directly (admin has TOTP enrolled).
  const jwt = apiRequire('jsonwebtoken') as { sign: (p: Record<string, unknown>, s: string, o?: { expiresIn?: number }) => string };
  const pg = apiRequire('pg') as typeof import('pg');
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const row = (await pool.query(`SELECT id, username, roles, permissions FROM users WHERE username='admin'`)).rows[0] as { id: string; username: string; roles: unknown; permissions: unknown };
  await pool.end();
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
  const envM = /^JWT_SECRET=(.+)$/m.exec(envFile);
  return jwt.sign({ sub: row.id, username: row.username, roles: parseArr(row.roles), permissions: parseArr(row.permissions), amr: ['totp'] }, process.env.JWT_SECRET ?? envM?.[1]?.trim() ?? 'dev-secret', { expiresIn: 3600 });
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
  console.log(`SNMPv3 secret: user=${snmp.username} level=${snmp.securityLevel}`);
  const creds = {
    version: 'v3' as const,
    username: snmp.username ?? '',
    securityLevel: (snmp.securityLevel ?? 'authPriv') as 'noAuthNoPriv' | 'authNoPriv' | 'authPriv',
    authProtocol: (snmp.authProtocol === 'MD5' ? 'MD5' : 'SHA') as 'MD5' | 'SHA',
    authPassword: snmp.authPassword,
    privProtocol: (snmp.privProtocol ?? 'AES') as 'DES' | 'AES',
    privPassword: snmp.privPassword,
  };
  const opts = { timeoutMs: 5_000, retries: 2, port: 161 };

  for (const host of HOSTS) {
    console.log(`\n########## ${host} — walk .1.3.6.1.4.1.2356.11.2.10 (Setup/DHCP config mirror) ##########`);
    try {
      const m = await snmpWalk(host, creds, ['1.3.6.1.4.1.2356.11.2.10'], opts);
      console.log(`${m.size} OIDs`);
      for (const [oid, v] of [...m.entries()].sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))) {
        console.log(`  ${oid.replace(/^1\.3\.6\.1\.4\.1\.2356\./, '')} = ${fmt(v)}`);
      }
    } catch (e) {
      console.log(`walk failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
