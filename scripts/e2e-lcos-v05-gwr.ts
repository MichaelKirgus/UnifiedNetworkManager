/**
 * READ-ONLY check of the canonical intents' read path on GW_Ralf (production,
 * physical LANCOM 1803VAW-5G). Runs vlan.networks.read via a plan and prints
 * the decoded rows — proves the SNMP status walk works on hardware too.
 * NO writes are executed.
 * Usage: ./node_modules/.bin/tsx scripts/e2e-lcos-v05-gwr.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const LCOS_PLUGIN_ID = '00000000-0000-4000-8000-000000000006';
// GW_Ralf — 10.28.0.1, LANCOM 1803VAW-5G (PRODUCTION).
const DEVICE_GW = 'fb2f6114-f169-4ca0-b145-f741fec55f11';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

async function main(): Promise<void> {
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
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // vlan.networks.read is riskLevel 'read' + deviceCount 1 → use the peek endpoint.
  const r = await authed('POST', `/plugins/${LCOS_PLUGIN_ID}/actions/execute`, { deviceId: DEVICE_GW, actionId: 'vlan.networks.read', input: {} });
  console.log(`peek status=${r.status}`);
  const body = (await r.json()) as { details?: Record<string, unknown>; error?: string };
  if (body.error) {
    console.error('FAILED:', body.error);
    process.exitCode = 1;
    return;
  }
  const networks = (body.details?.networks ?? []) as Array<Record<string, unknown>>;
  console.log(`GW_Ralf L3 networks (${networks.length}):`);
  for (const n of networks) console.log(' ', JSON.stringify(n));

  // Cross-check: the SNMP walk must include the known production rows.
  const names = new Set(networks.map((n) => String(n.name).toUpperCase()));
  const expect = ['NET_MANAGEMENT', 'NET_MGMT_DHCP', 'NET_INTRANET'];
  for (const e of expect) {
    if (!names.has(e)) { console.error(`MISSING expected row ${e}`); process.exitCode = 1; }
  }
  await pool.end();
}

main().catch((e) => { console.error('crashed:', e); process.exit(1); });
