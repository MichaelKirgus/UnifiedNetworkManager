/**
 * E2E check for Phase G — server-side network-overlap checks + suggestions.
 *
 *   1. GET /networks/suggestions → free-range candidates (next free /24, lowest
 *      free VLAN id) computed from gaps in the live inventory.
 *   2. POST /plans/network-check with a DELIBERATELY OVERLAPPING subnet (taken
 *      from an existing live network row) → expect a 'subnet' warning; with a
 *      live network NAME and no CIDR → expect a 'name' warning. Per-device
 *      status must be present for the requested device.
 *   3. POST /plans/preflight on WLC01 (test device, read-only) → each result
 *      carries `check` { deployed: boolean, warnings[] }.
 *   4. Blocking mode: PUT /settings/rolloutOverlapMode=block → POST /plans with
 *      the overlapping network.create must be REJECTED (409). Revert to warn →
 *      the same request succeeds (201) and is deleted again (cleanup).
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-network-check.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const LCOS_PLUGIN_ID = '00000000-0000-4000-8000-000000000006';
// WLC01 — 10.25.0.20, LANCOM vRouter (TEST device).
const DEVICE_WLC = '38cf30d7-e53e-47ae-9545-c79af2270751';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 800) : '');
  }
}

interface LiveRow {
  key: string;
  name: string;
  subnet: string | null;
  subnets: string[];
  vlanId: number | null;
  devices: Array<{ deviceId: string; deviceName?: string | null }>;
}

async function main(): Promise<void> {
  // --- auth (login + TOTP from seeded secret) ---------------------------------
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
  check('authenticated (2FA flow)', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // --- pick a live network row to overlap -------------------------------------
  const nets = await authed('GET', '/networks');
  check('GET /networks → HTTP 200', nets.status === 200);
  const rows: LiveRow[] = (await nets.json()) as LiveRow[];
  const withSubnet = rows.find((r) => (r.subnets ?? []).some((s) => s.includes('/') && !s.includes(':')));
  check('found a live network row with an IPv4 subnet', Boolean(withSubnet), rows.length);
  if (!withSubnet) throw new Error('no live v4 subnet to overlap');

  // --- 1. suggestions -----------------------------------------------------------
  console.log('\n[1] GET /networks/suggestions');
  const sug = await authed('GET', '/networks/suggestions');
  check('suggestions → HTTP 200', sug.status === 200);
  const s = (await sug.json()) as { nextFreeSubnetV4: string | null; lowestFreeVlanId: number | null };
  check('nextFreeSubnetV4 is a /24 or null', s.nextFreeSubnetV4 === null || /^(\d{1,3}\.){3}\d{1,3}\/24$/.test(s.nextFreeSubnetV4), s);
  if (s.nextFreeSubnetV4) {
    const a = Number(s.nextFreeSubnetV4.split('.')[0]);
    check('nextFreeSubnetV4 skips 0/8 + multicast/reserved', a !== 0 && a < 224, s.nextFreeSubnetV4);
  }
  check('lowestFreeVlanId is null or in 1..4094', s.lowestFreeVlanId === null || (Number.isInteger(s.lowestFreeVlanId) && s.lowestFreeVlanId >= 1 && s.lowestFreeVlanId <= 4094), s);

  // --- 2. network-check: deliberate overlaps ------------------------------------
  console.log('\n[2] POST /plans/network-check (overlap + name collision)');
  const overlapCidr = withSubnet.subnets.find((x) => x.includes('/') && !x.includes(':'))!;
  const chk1 = await authed('POST', '/plans/network-check', { inputs: { name: 'UNM_E2E_CHK', cidr: overlapCidr }, deviceIds: [DEVICE_WLC] });
  check('network-check (subnet) → HTTP 200', chk1.status === 200);
  const c1 = (await chk1.json()) as { warnings: Array<{ kind: string; message: string }>; devices: Array<{ deviceId: string; status: string }> };
  check('subnet overlap produces a "subnet" warning', c1.warnings.some((w) => w.kind === 'subnet'), c1.warnings);
  check('per-device status present for WLC01', c1.devices.length === 1 && (c1.devices[0].status === 'deployed' || c1.devices[0].status === 'new'), c1.devices);

  const chk2 = await authed('POST', '/plans/network-check', { inputs: { name: withSubnet.name }, deviceIds: [DEVICE_WLC] });
  check('network-check (name) → HTTP 200', chk2.status === 200);
  const c2 = (await chk2.json()) as { warnings: Array<{ kind: string }> };
  check('live name collision produces a "name" warning', c2.warnings.some((w) => w.kind === 'name'), c2.warnings);

  // --- 3. preflight carries the server check ------------------------------------
  console.log('\n[3] POST /plans/preflight → per-device `check`');
  const pf = await authed('POST', '/plans/preflight', { pluginId: LCOS_PLUGIN_ID, intentActionId: 'network.create', inputs: { name: 'UNM_E2E_CHK' }, deviceIds: [DEVICE_WLC] });
  check('preflight → HTTP 200', pf.status === 200);
  const p = (await pf.json()) as { results: Array<{ deviceId: string; check?: { deployed: boolean; warnings: unknown[] } }> };
  check('preflight result carries `check`', Boolean(p.results[0]?.check), p.results[0]);
  if (p.results[0]?.check) {
    check('check.deployed is a boolean', typeof p.results[0].check!.deployed === 'boolean');
    check('check.warnings is an array', Array.isArray(p.results[0].check!.warnings));
  }

  // --- 4. blocking mode -----------------------------------------------------------
  console.log('\n[4] rolloutOverlapMode=block rejects the overlapping plan');
  const setBlock = await authed('PUT', '/settings/rolloutOverlapMode', { value: 'block' });
  check('set rolloutOverlapMode=block → HTTP 200', setBlock.status === 200, (await setBlock.json()));

  const planBody = {
    pluginId: LCOS_PLUGIN_ID,
    intentActionId: 'network.create',
    inputs: { name: 'UNM_E2E_BLK', cidr: overlapCidr }, // L3-only (no vlanId)
    devices: [{ deviceId: DEVICE_WLC }],
  };
  const blocked = await authed('POST', '/plans', planBody);
  check('overlapping network.create in block mode → HTTP 409', blocked.status === 409, (await blocked.json()));

  const setWarn = await authed('PUT', '/settings/rolloutOverlapMode', { value: 'warn' });
  check('revert rolloutOverlapMode=warn → HTTP 200', setWarn.status === 200);

  const allowed = await authed('POST', '/plans', planBody);
  const createdPlan = (await allowed.json()) as { id?: string };
  check('same request in warn mode → HTTP 201', allowed.status === 201, createdPlan);
  if (allowed.status === 201 && createdPlan.id) {
    const del = await authed('DELETE', `/plans/${createdPlan.id}`);
    check('cleanup: plan deleted', del.status < 300, del.status);
  } else {
    failures++;
    console.error('  FAIL cleanup skipped — no plan id returned');
  }

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('E2E crashed:', err);
  process.exit(1);
});
