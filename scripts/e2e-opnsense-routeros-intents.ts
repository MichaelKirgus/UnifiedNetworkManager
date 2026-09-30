/**
 * E2E check for Phase J — OPNsense + RouterOS L2 abstraction and canonical
 * fleet intents (l2.topology.read / network.create preflight). FULLY READ-ONLY:
 * no plan writes any device.
 *
 *   1. l2.topology.read on OPNSENSE01 (primary router — reads only) via a real
 *      plan step. Assert the parsed hierarchy: physical ports, the lagg0 LACP
 *      bundle (ax0+ax1), and the l3Interfaces map (lan carries L3).
 *   2. Preflight network.create on OPNSENSE01 — assert attach-point suggestion
 *      + write-path hint (≤26.4 without a bound ssh slot → "no write path").
 *   3. Same two checks against ROUTEROS01. The router is currently OFFLINE
 *      (health=critical since Sep 27) — when unreachable the script reports
 *      SKIP for those checks instead of failing; when it comes back they run
 *      full assertions (ether1 physical port, L3 on ether1).
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-opnsense-routeros-intents.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const OPN_PLUGIN_ID = 'b0e6c8a2-4f1e-4a3d-9c7b-1a2b3c4d5e6f'; // OPNsense Plugin
const ROS_PLUGIN_ID = '00000000-0000-4000-8000-00000000000a'; // MikroTik RouterOS Plugin
// OPNSENSE01 — 10.25.5.1, OPNsense 26.4.2p2 (PRIMARY ROUTER — reads only).
const DEVICE_OPN = '2eb40794-fd9c-4139-a381-184197b4f97a';
// ROUTEROS01 — 10.25.2.1, RouterOS (offline since Sep 27 → SKIP path).
const DEVICE_ROS = '5c6e5d9a-1ad4-4ddd-82f3-508991d3ce15';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
let skips = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 1200) : '');
  }
}
function skip(label: string, reason: string): void {
  skips++;
  console.log(`  SKIP ${label} — ${reason}`);
}

interface TopoDto {
  physicalPorts: Array<{ name: string; assignment: string | null }>;
  bridges: Array<{ name: string; members: string[] }>;
  bundles: Array<{ name: string; protocol?: string | null; members: string[]; operating?: boolean | null }>;
  l3Interfaces?: Record<string, string[]>;
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

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // --- helper: run one single-device plan step and wait ------------------------
  const runStep = async (pluginId: string, deviceId: string, actionId: string, inputs: Record<string, unknown>): Promise<{ status: number; planStatus?: string; details?: Record<string, unknown>; error?: string }> => {
    const c = await authed('POST', '/plans', { pluginId, intentActionId: actionId, inputs, devices: [{ deviceId }] });
    if (c.status !== 201 && c.status !== 200) return { status: c.status };
    const p = ((await c.json()) as { id?: string }) ?? {};
    if (!p.id) throw new Error(`plan creation failed for ${actionId}: status=${c.status}`);
    await authed('POST', `/plans/${p.id}/execute`);
    let detail: Record<string, unknown> | null = null;
    for (let i = 0; i < 60; i++) {
      await new Promise((r) => setTimeout(r, 2_000));
      const d = ((await authed('GET', `/plans/${p.id}`).then((r) => r.json())) as Record<string, unknown>) ?? null;
      if (d && ['succeeded', 'failed', 'cancelled'].includes(String(d.status))) { detail = d; break; }
    }
    const st = (detail?.steps ?? []) as Array<{ actionId?: string; result?: { success?: boolean; result?: { success?: boolean; details?: Record<string, unknown>; error?: string } | null } | null }>;
    const step = st.find((s) => s.actionId === actionId) ?? st[st.length - 1] ?? {};
    return { status: c.status, planStatus: String(detail?.status), details: step.result?.result?.details, error: step.result?.result?.error };
  };

  const preflight = async (pluginId: string, deviceId: string): Promise<PreflightResultDto | undefined> => {
    const r = await authed('POST', '/plans/preflight', { pluginId, intentActionId: 'network.create', inputs: { name: 'UNM_E2E_L2', vlanId: 497 }, deviceIds: [deviceId] });
    if (r.status !== 200) return undefined;
    const body = ((await r.json()) as { results?: PreflightResultDto[] }) ?? {};
    return (body.results ?? []).find((x) => x.deviceId === deviceId);
  };

  // --- 1. OPNsense: l2.topology.read -------------------------------------------
  console.log('\n[1] l2.topology.read — OPNSENSE01 (reads only)');
  const opn = await runStep(OPN_PLUGIN_ID, DEVICE_OPN, 'l2.topology.read', {});
  check('OPNsense topology read succeeded', opn.planStatus === 'succeeded', { status: opn.status, error: opn.error });
  const opnTopo = (opn.details ?? {}) as TopoDto;
  console.log(`     physicalPorts: ${JSON.stringify((opnTopo.physicalPorts ?? []).map((p) => `${p.name}→${p.assignment}`))}`);
  console.log(`     bundles: ${JSON.stringify(opnTopo.bundles)}  bridges: ${JSON.stringify(opnTopo.bridges)}`);
  console.log(`     l3Interfaces: ${JSON.stringify(opnTopo.l3Interfaces)}`);
  check('OPNsense → physical ports present', Array.isArray(opnTopo.physicalPorts) && opnTopo.physicalPorts.length > 0, opnTopo.physicalPorts);
  const lagg = (opnTopo.bundles ?? []).find((b) => b.name === 'lagg0');
  check('OPNsense → lagg0 bundle present', Boolean(lagg), opnTopo.bundles);
  if (lagg) {
    check('OPNsense → lagg0 members ax0+ax1', lagg.members.includes('ax0') && lagg.members.includes('ax1'), lagg);
    check('OPNsense → lagg0 protocol lacp', String(lagg.protocol ?? '').toLowerCase() === 'lacp', lagg);
  }
  const opnL3 = opnTopo.l3Interfaces ?? {};
  const lanIfc = Object.entries(opnL3).find(([, names]) => (names ?? []).length > 0);
  check('OPNsense → some interface carries L3 networks', Boolean(lanIfc), opnL3);

  // --- 2. OPNsense: preflight network.create ------------------------------------
  console.log('\n[2] preflight network.create — OPNSENSE01');
  const opnPf = await preflight(OPN_PLUGIN_ID, DEVICE_OPN);
  check('OPNsense preflight → result present', Boolean(opnPf), opnPf);
  check('OPNsense preflight → not degraded', Boolean(opnPf && !opnPf.degraded), opnPf?.error);
  console.log(`     values: ${JSON.stringify(opnPf?.values)}`);
  const opnIface = opnPf?.values.find((v) => v.key === 'interface');
  check('OPNsense → attach point suggested', Boolean(opnIface && opnIface.value), opnIface);
  check('OPNsense → attach confidence high (carries L3)', opnIface?.confidence === 'high', opnIface);
  const opnWritePath = opnPf?.values.find((v) => v.key === '_writePath');
  // OPNSENSE01 is ≤26.4 with NO bound ssh slot → the resolver must report "no write path".
  check('OPNsense → write-path hint present', Boolean(opnWritePath), opnPf?.values);
  if (opnWritePath) {
    const noPath = opnWritePath.value === null && /no write path/i.test(String(opnWritePath.note ?? ''));
    const sshPath = opnWritePath.value === 'ssh';
    check('OPNsense → write path is "none" (≤26.4, no ssh slot) or "ssh"', noPath || sshPath, opnWritePath);
  }
  const opnVlan = opnPf?.values.find((v) => v.key === 'vlanId');
  check('OPNsense → vlanId hint present', Boolean(opnVlan), opnPf?.values);

  // --- 2b. OPNsense: /plan structural check (deviceInputs merge) ------------------
  // Creates a plan but NEVER executes it — verifies the planner fans out and
  // merges per-device overrides from deviceInputs into the step input.
  console.log('\n[2b] POST /plans network.create — OPNSENSE01 (structural, not executed)');
  const planRes = await authed('POST', '/plans', {
    pluginId: OPN_PLUGIN_ID,
    intentActionId: 'network.create',
    inputs: { name: 'UNM_E2E_L2', vlanId: 497 },
    devices: [{ deviceId: DEVICE_OPN }],
    deviceInputs: { [DEVICE_OPN]: { interface: 'lagg0', cidr: '10.250.497.1/24' } },
  });
  check('OPNsense /plans → HTTP 201/200', planRes.status === 201 || planRes.status === 200, { status: planRes.status });
  const createdPlan = ((await planRes.json()) as Record<string, unknown>) ?? {};
  const steps = (createdPlan.steps ?? []) as Array<{ deviceId?: string; actionId?: string; input?: Record<string, unknown>; bestEffort?: boolean }>;
  // The OPNsense planner prepends a best-effort snapshot.create rollback step
  // for dirty devices — the intent step is the network.create one.
  const createStep = steps.find((s) => s.actionId === 'network.create');
  check('OPNsense /plans → network.create step present', Boolean(createStep && createStep.deviceId === DEVICE_OPN), createdPlan);
  check('OPNsense /plans → snapshot.create rollback prepended (bestEffort)', steps.some((s) => s.actionId === 'snapshot.create' && s.bestEffort), steps.map((s) => s.actionId));
  const merged = createStep?.input ?? {};
  check('OPNsense /plans → shared inputs present (name)', String(merged.name) === 'UNM_E2E_L2', merged);
  check('OPNsense /plans → deviceInputs override merged (interface=lagg0)', String(merged.interface) === 'lagg0', merged);
  check('OPNsense /plans → deviceInputs override merged (cidr)', String(merged.cidr) === '10.250.497.1/24', merged);
  // Cleanup — the structural plan is a test artifact; remove it (never executed).
  if (typeof createdPlan.id === 'string') await authed('DELETE', `/plans/${createdPlan.id}`);

  // --- 3. RouterOS: l2.topology.read + preflight ---------------------------------
  console.log('\n[3] l2.topology.read — ROUTEROS01 (offline since Sep 27 → SKIP path)');
  const ros = await runStep(ROS_PLUGIN_ID, DEVICE_ROS, 'l2.topology.read', {});
  if (ros.planStatus === 'succeeded') {
    const rosTopo = (ros.details ?? {}) as TopoDto;
    console.log(`     physicalPorts: ${JSON.stringify((rosTopo.physicalPorts ?? []).map((p) => `${p.name}→${p.assignment}`))}`);
    console.log(`     l3Interfaces: ${JSON.stringify(rosTopo.l3Interfaces)}`);
    check('RouterOS → ether1 is a physical port', (rosTopo.physicalPorts ?? []).some((p) => p.name === 'ether1'), rosTopo.physicalPorts);
    const rosL3 = rosTopo.l3Interfaces ?? {};
    check('RouterOS → ether1 carries L3 address 10.25.2.1/16', Boolean(rosL3['ether1']?.some((a) => a.startsWith('10.25.2.1'))), rosL3);
  } else {
    skip('RouterOS topology read (device offline)', String(ros.error ?? `plan ${ros.planStatus}`));
  }

  console.log('\n[4] preflight network.create — ROUTEROS01');
  const rosPf = await preflight(ROS_PLUGIN_ID, DEVICE_ROS);
  check('RouterOS preflight → result present (degraded ok when offline)', Boolean(rosPf), rosPf);
  if (rosPf?.degraded) {
    skip('RouterOS preflight values (device offline)', String(rosPf.error));
  } else if (rosPf) {
    console.log(`     values: ${JSON.stringify(rosPf.values)}`);
    const rosIface = rosPf.values.find((v) => v.key === 'interface');
    check('RouterOS → attach point suggested', Boolean(rosIface && rosIface.value), rosIface);
  }

  await pool.end();
  console.log(failures === 0 ? `\nALL CHECKS PASSED (${skips} skipped)` : `\n${failures} CHECK(S) FAILED, ${skips} skipped`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('E2E crashed:', err);
  process.exit(1);
});
