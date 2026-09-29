/**
 * E2E check for Phase E — smart preflight + per-device input overrides.
 *
 *   1. POST /plans/preflight on WLC01 (test device) with network.create inputs
 *      → expect values incl. `interface` suggestion (WLC01 L3 ifcs = LAN-1, high
 *        confidence) and a vlanId hint; read-only — nothing written yet.
 *   2. POST /plans/preflight on GW_Ralf (PRODUCTION, reads only) → expect HTTP
 *      200 with either values or a degraded entry (never an error status).
 *   3. POST /plans with deviceInputs override (interface LAN-2) → GET plan and
 *      assert the persisted step input contains the merged override.
 *   4. Execute on WLC01, verify the network row exists, then clean up via
 *      network.delete (idempotent).
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-lcos-v06-preflight.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const LCOS_PLUGIN_ID = '00000000-0000-4000-8000-000000000006';
// WLC01 — 10.25.0.20, LANCOM vRouter (no WLAN radio, TEST device).
const DEVICE_WLC = '38cf30d7-e53e-47ae-9545-c79af2270751';
// GW_Ralf — 10.28.0.1, LANCOM 1803VAW-5G (PRODUCTION — preflight reads only).
const DEVICE_GWRALF = 'fb2f6114-f169-4ca0-b145-f741fec55f11';

const NET_NAME = 'UNM_E2E_NET';
const VLAN_ID = 399;
const CIDR = '10.249.0.2/24';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 800) : '');
  }
}

interface PreflightValueDto { key: string; value: unknown; confidence: 'high' | 'medium' | 'low'; note?: string }
interface PreflightResultDto { deviceId: string; values: PreflightValueDto[]; degraded?: boolean; error?: string }

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

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; text: () => Promise<string>; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, text: async () => (await res.text()), json: async () => (await res.json().catch(() => null)) as never };
  };

  const sharedInputs = { name: NET_NAME, vlanId: VLAN_ID, cidr: CIDR };

  // --- 1. preflight on WLC01 ---------------------------------------------------
  console.log('\n[1] preflight WLC01 (read-only)');
  const pfWlc = await authed('POST', '/plans/preflight', { pluginId: LCOS_PLUGIN_ID, intentActionId: 'network.create', inputs: sharedInputs, deviceIds: [DEVICE_WLC] });
  check('preflight WLC01 → HTTP 200', pfWlc.status === 200);
  const wlcRaw = await pfWlc.text();
  let wlcResults: PreflightResultDto[];
  try {
    wlcResults = ((JSON.parse(wlcRaw) as { results?: PreflightResultDto[] }).results) ?? [];
  } catch {
    console.error('     RAW BODY:', wlcRaw.slice(0, 1500));
    throw new Error('preflight WLC01 returned non-JSON body');
  }
  const wlcR = wlcResults.find((r) => r.deviceId === DEVICE_WLC);
  check('preflight WLC01 → result for device', Boolean(wlcR), wlcResults);
  if (wlcR) {
    console.log(`     values: ${JSON.stringify(wlcR.values, null, 2).replace(/\n/g, '\n     ')}`);
    check('preflight WLC01 → not degraded', !wlcR.degraded, wlcR.error);
    const iface = wlcR.values.find((v) => v.key === 'interface');
    check('preflight WLC01 → interface suggestion present', Boolean(iface), wlcR.values.map((v) => v.key));
    if (iface) {
      console.log(`     interface=${JSON.stringify(iface.value)} confidence=${iface.confidence} note=${iface.note ?? '-'}`);
      check('preflight WLC01 → interface is a LAN-n name', /^LAN-\d+$/.test(String(iface.value)), iface.value);
    }
    const vlanHint = wlcR.values.find((v) => v.key === 'vlanId');
    check('preflight WLC01 → vlanId hint present', Boolean(vlanHint), wlcR.values.map((v) => v.key));
  }

  // --- 2. preflight on GW_Ralf (production, reads only) -------------------------
  console.log('\n[2] preflight GW_Ralf (read-only, production)');
  const pfGw = await authed('POST', '/plans/preflight', { pluginId: LCOS_PLUGIN_ID, intentActionId: 'network.create', inputs: sharedInputs, deviceIds: [DEVICE_GWRALF] });
  check('preflight GW_Ralf → HTTP 200 (never an error status)', pfGw.status === 200);
  const gwRaw = await pfGw.text();
  let gwResults: PreflightResultDto[];
  try {
    gwResults = ((JSON.parse(gwRaw) as { results?: PreflightResultDto[] }).results) ?? [];
  } catch {
    console.error('     RAW BODY:', gwRaw.slice(0, 1500));
    throw new Error('preflight GW_Ralf returned non-JSON body');
  }
  const gwR = gwResults.find((r) => r.deviceId === DEVICE_GWRALF);
  check('preflight GW_Ralf → result for device', Boolean(gwR), gwResults);
  if (gwR) {
    console.log(`     degraded=${Boolean(gwR.degraded)} error=${gwR.error ?? '-'} values: ${JSON.stringify(gwR.values)}`);
  }

  // --- 3. plan with per-device override, verify merged step input ---------------
  console.log('\n[3] create plan with deviceInputs override (interface LAN-2)');
  const created = await authed('POST', '/plans', {
    pluginId: LCOS_PLUGIN_ID,
    intentActionId: 'network.create',
    inputs: sharedInputs,
    devices: [{ deviceId: DEVICE_WLC }],
    deviceInputs: { [DEVICE_WLC]: { interface: 'LAN-2' } },
  });
  check('POST /plans with deviceInputs → HTTP 201/200', created.status === 201 || created.status === 200);
  const createdRaw = await created.text();
  let plan: { id?: string; steps?: Array<{ input?: Record<string, unknown> }> };
  try {
    plan = JSON.parse(createdRaw) as typeof plan;
  } catch {
    console.error('     RAW BODY:', createdRaw.slice(0, 1500));
    throw new Error('POST /plans returned non-JSON body');
  }
  check('plan has an id', Boolean(plan.id), plan);

  // The step list may not be in the create response — fetch it.
  let steps: Array<{ actionId?: string; input?: Record<string, unknown> }> = plan.steps ?? [];
  if (steps.length === 0) {
    const got = await authed('GET', `/plans/${plan.id}`);
    steps = (((await got.json()) as { steps?: Array<{ actionId?: string; input?: Record<string, unknown> }> }).steps) ?? [];
  }
  // The plan carries a best-effort config.backup.download step before the intent step.
  const createStep = steps.find((s) => s.actionId === 'network.create');
  check('plan has a network.create step', Boolean(createStep), steps.map((s) => s.actionId));
  const stepInput = createStep?.input ?? {};
  console.log(`     step input: ${JSON.stringify(stepInput)}`);
  check('step input merged override interface=LAN-2', stepInput.interface === 'LAN-2', stepInput);
  check('step input kept shared name/vlanId/cidr', stepInput.name === NET_NAME && stepInput.vlanId === VLAN_ID && stepInput.cidr === CIDR, stepInput);

  // --- helper: run one single-device plan step and wait ------------------------
  const runStep = async (actionId: string, inputs: Record<string, unknown>): Promise<{ status: number; planStatus?: string; details?: Record<string, unknown>; error?: string }> => {
    const c = await authed('POST', '/plans', { pluginId: LCOS_PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId: DEVICE_WLC }] });
    if (c.status !== 201 && c.status !== 200) return { status: c.status };
    const p = ((await c.json()) as { id?: string }) ?? {};
    if (!p.id) throw new Error(`plan creation failed for ${actionId}: status=${c.status}`);
    await authed('POST', `/plans/${p.id}/execute`);
    let detail: Record<string, unknown> | null = null;
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 2_000));
      const d = ((await authed('GET', `/plans/${p.id}`).then((r) => r.json())) as Record<string, unknown>) ?? null;
      if (d && ['succeeded', 'failed', 'cancelled'].includes(String(d.status))) { detail = d; break; }
    }
    const st = (detail?.steps ?? []) as Array<{ actionId?: string; result?: { success?: boolean; result?: { success?: boolean; details?: Record<string, unknown>; error?: string } | null } | null }>;
    const step = st.find((s) => s.actionId === actionId) ?? st[st.length - 1] ?? {};
    return { status: c.status, planStatus: String(detail?.status), details: step.result?.result?.details, error: step.result?.result?.error };
  };

  // --- 4. execute on WLC01 + verify + cleanup -----------------------------------
  console.log('\n[4] execute on WLC01 (test device)');
  const exec = await authed('POST', `/plans/${plan.id}/execute`);
  check('execute → HTTP 2xx', exec.status === 200 || exec.status === 202, exec.status);

  let planStatus: string | undefined;
  for (let i = 0; i < 90; i++) {
    await new Promise((r) => setTimeout(r, 2_000));
    const d = ((await authed('GET', `/plans/${plan.id}`).then((r) => r.json())) as Record<string, unknown>) ?? null;
    planStatus = (d?.status as string | undefined);
    if (planStatus === 'succeeded' || planStatus === 'failed') break;
  }
  check('plan succeeded', planStatus === 'succeeded', { status: planStatus });

  // Verify the network row exists on WLC01 via a read action.
  const verify = await runStep('vlan.networks.read', {});
  const rows = ((verify.details?.networks as Array<Record<string, unknown>>) ?? []);
  const netRow = rows.find((r) => String(r.name).toUpperCase() === NET_NAME);
  check(`verify: ${NET_NAME} row exists on WLC01`, Boolean(netRow), { planStatus: verify.planStatus, error: verify.error, rows: rows.slice(0, 5) });
  if (netRow) console.log(`     row: ${JSON.stringify(netRow)}`);

  // Cleanup — idempotent delete.
  const del = await runStep('network.delete', { name: NET_NAME });
  check('cleanup: network.delete succeeded', del.planStatus === 'succeeded', { status: del.status, error: del.error });

  await pool.end();
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('E2E crashed:', err);
  process.exit(1);
});
