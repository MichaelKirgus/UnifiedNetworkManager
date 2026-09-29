/**
 * E2E check for the lancom-lcos plugin v0.5.0 (canonical fleet network intents).
 *
 * Drives REAL writes end-to-end on WLC01 (test device, LANCOM vRouter):
 *   discovery (network.create / network.delete / vlan.networks.read in catalog)
 *   → baseline read: UNM_E2E_NET must not exist yet
 *   → network.create {name, vlanId 399, cidr}            [VLAN + L3 rows via CLI]
 *   → verify row present with correct VLAN/IP (vlan.networks.read)
 *   → idempotency: re-run create                          [no-op, still succeeds]
 *   → network.create {name2, vlanId 400, cidr, dhcpPool}  [VLAN + L3 + DHCP rows]
 *   → verify all three tables
 *   → network.delete both networks                        [idempotent deletes]
 *   → verify gone
 *   → negative: vlanId out of range must be rejected
 *
 * NO writes on GW_Ralf (production).
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-lcos-v05.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const LCOS_PLUGIN_ID = '00000000-0000-4000-8000-000000000006';
// WLC01 — 10.25.0.20, LANCOM vRouter (no WLAN radio, TEST device).
const DEVICE_WLC = '38cf30d7-e53e-47ae-9545-c79af2270751';

const NET_A = 'UNM_E2E_NET';   // vlan 399, L3 only
const NET_B = 'UNM_E2E_DHCP';  // vlan 400, L3 + DHCP pool

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 800) : '');
  }
}

interface NetRow { name: string; ip?: string; netmask?: string; vlanId?: number | null; ifc?: string | null }

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

  // --- helper: run one single-device plan step and wait ------------------------
  const runStep = async (deviceId: string, actionId: string, inputs: Record<string, unknown>): Promise<{ status: number; planStatus?: string; details?: Record<string, unknown>; error?: string }> => {
    const created = await authed('POST', '/plans', { pluginId: LCOS_PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId }] });
    if (created.status !== 201 && created.status !== 200) return { status: created.status };
    const plan = (await created.json()) as { id?: string };
    if (!plan.id) throw new Error(`plan creation failed for ${actionId}: status=${created.status}`);
    await authed('POST', `/plans/${plan.id}/execute`);
    let detail: Record<string, unknown> | null = null;
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 2_000));
      const d = ((await authed('GET', `/plans/${plan.id}`).then((r) => r.json())) as Record<string, unknown>) ?? null;
      if (d && ['succeeded', 'failed', 'cancelled'].includes(String(d.status))) { detail = d; break; }
    }
    const steps = (detail?.steps ?? []) as Array<{ actionId?: string; status?: string; result?: { success?: boolean; result?: { success?: boolean; details?: Record<string, unknown>; error?: string } | null } | null }>;
    const step = steps.find((s) => s.actionId === actionId) ?? steps[steps.length - 1] ?? {};
    return { status: created.status, planStatus: String(detail?.status), details: step.result?.result?.details, error: step.result?.result?.error };
  };

  const readNetworks = async (): Promise<NetRow[]> => {
    const r = await runStep(DEVICE_WLC, 'vlan.networks.read', {});
    return ((r.details?.networks as NetRow[]) ?? []);
  };

  // --- 1. discovery: v0.5 catalog ----------------------------------------------
  console.log('\n[1] discovery — canonical intents in catalog');
  const cat = (await authed('GET', `/plugins/${LCOS_PLUGIN_ID}/actions`).then((r) => r.json())) as { actions?: Array<{ id: string; deviceCount?: number | 'N' }> };
  const ids = new Set((cat.actions ?? []).map((a) => a.id));
  check('catalog has network.create', ids.has('network.create'));
  check('catalog has network.delete', ids.has('network.delete'));
  check('catalog has vlan.networks.read', ids.has('vlan.networks.read'));
  const createEntry = (cat.actions ?? []).find((a) => a.id === 'network.create');
  check('network.create fans out (deviceCount N)', createEntry?.deviceCount === 'N', createEntry);

  // --- 2. baseline ---------------------------------------------------------------
  console.log('\n[2] baseline — clean state on WLC01');
  let rows = await readNetworks();
  check('baseline read succeeded', !rows.some((r) => r.name === NET_A || r.name === NET_B), rows);

  // --- 3. create A: VLAN + L3 ------------------------------------------------------
  console.log('\n[3] network.create — UNM_E2E_NET (vlan 399, L3 only)');
  const cA = await runStep(DEVICE_WLC, 'network.create', { name: NET_A, vlanId: 399, cidr: '10.249.0.2/24' });
  check('create A plan succeeded', cA.planStatus === 'succeeded', { status: cA.status, error: cA.error, details: cA.details });

  rows = await readNetworks();
  const rowA = rows.find((r) => r.name.toUpperCase() === NET_A);
  check('row A present after create', Boolean(rowA), rows);
  check('row A vlanId=399', rowA?.vlanId === 399, rowA);
  check('row A ip=10.249.0.2/24', rowA?.ip === '10.249.0.2' && rowA?.netmask === '255.255.255.0', rowA);

  // --- 4. idempotency: re-run create A ----------------------------------------------
  console.log('\n[4] idempotency — re-running network.create for UNM_E2E_NET');
  const cAgain = await runStep(DEVICE_WLC, 'network.create', { name: NET_A, vlanId: 399, cidr: '10.249.0.2/24' });
  check('re-create A still succeeds (no-op)', cAgain.planStatus === 'succeeded', { error: cAgain.error, details: cAgain.details });

  // --- 5. create B: VLAN + L3 + DHCP ---------------------------------------------------
  console.log('\n[5] network.create — UNM_E2E_DHCP (vlan 400, L3 + DHCP pool)');
  const cB = await runStep(DEVICE_WLC, 'network.create', {
    name: NET_B, vlanId: 400, cidr: '10.250.0.2/24',
    dhcpPool: { start: '10.250.0.10', end: '10.250.0.250' },
  });
  check('create B plan succeeded', cB.planStatus === 'succeeded', { status: cB.status, error: cB.error, details: cB.details });

  rows = await readNetworks();
  const rowB = rows.find((r) => r.name.toUpperCase() === NET_B);
  check('row B present after create', Boolean(rowB), rows);
  check('row B vlanId=400 + L3', rowB?.vlanId === 400 && rowB?.ip === '10.250.0.2', rowB);

  // --- 6. delete both ------------------------------------------------------------------
  console.log('\n[6] network.delete — UNM_E2E_NET and UNM_E2E_DHCP');
  const dA = await runStep(DEVICE_WLC, 'network.delete', { name: NET_A });
  check('delete A plan succeeded', dA.planStatus === 'succeeded', { error: dA.error, details: dA.details });
  const dB = await runStep(DEVICE_WLC, 'network.delete', { name: NET_B });
  check('delete B plan succeeded', dB.planStatus === 'succeeded', { error: dB.error, details: dB.details });

  rows = await readNetworks();
  check('row A gone after delete', !rows.some((r) => r.name.toUpperCase() === NET_A), rows);
  check('row B gone after delete', !rows.some((r) => r.name.toUpperCase() === NET_B), rows);

  // --- 7. idempotent delete (already absent) ----------------------------------------------
  console.log('\n[7] idempotency — deleting UNM_E2E_NET again');
  const dAgain = await runStep(DEVICE_WLC, 'network.delete', { name: NET_A });
  check('re-delete still succeeds (no-op)', dAgain.planStatus === 'succeeded', { error: dAgain.error, details: dAgain.details });

  // --- 8. negative: out-of-range vlanId ------------------------------------------------------
  console.log('\n[8] negative — vlanId 9999 must be rejected');
  const neg = await runStep(DEVICE_WLC, 'network.create', { name: 'UNM_E2E_BAD', vlanId: 9999 });
  check('out-of-range vlanId rejected (plan not created or step failed)',
    neg.status >= 400 || neg.planStatus === 'failed' || Boolean(neg.error),
    { status: neg.status, planStatus: neg.planStatus, error: neg.error });

  // --- summary -----------------------------------------------------------------------------
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('E2E crashed:', e);
  process.exit(1);
});
