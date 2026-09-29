/**
 * E2E check for Phase H — dual-stack (v4+v6) network rollout on LCOS.
 *
 *   1. POST /plans/network-check with cidrV6 → v6 overlap warning against the
 *      live ULA subnet on GW_Ralf + nextFreeSubnetV6 suggestion present.
 *   2. Preflight with cidrV6 → `cidrV6` hint value (no existing rows yet).
 *   3. Create + execute a dual-stack plan on WLC01 (test device): v4 CIDR +
 *      v6 ULA CIDR, VLAN 398. Step details must report both L3 addresses and
 *      the two separate Setup/IPv6 tables written.
 *   4. Verify via ipv6.networks.read (v6 rows) + vlan.networks.read (v4 row).
 *   5. Idempotency: re-run network.create with identical inputs → all rows
 *      "already exists — left untouched" (per-table, per-family idempotency).
 *   6. Cleanup via network.delete → both trees empty again; second delete is a
 *      no-op.
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-lcos-dualstack.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const LCOS_PLUGIN_ID = '00000000-0000-4000-8000-000000000006';
// WLC01 — 10.25.0.20, LANCOM vRouter (TEST device).
const DEVICE_WLC = '38cf30d7-e53e-47ae-9545-c79af2270751';

const NET_NAME = 'UNM_E2E_V6';
const VLAN_ID = 398;
const CIDR = '10.248.0.2/24';
// ULA prefix that does NOT collide with GW_Ralf's live fdf8:f53b:7*::/64 rows.
const CIDR_V6 = 'fd00:beef::1/64';

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

  const sharedInputs = { name: NET_NAME, vlanId: VLAN_ID, cidr: CIDR, cidrV6: CIDR_V6 };

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

  // --- 0. pre-cleanup (idempotent — makes the script re-runnable) --------------
  console.log('\n[0] pre-cleanup');
  const pre = await runStep('network.delete', { name: NET_NAME });
  check('pre-cleanup delete succeeded', pre.planStatus === 'succeeded', { status: pre.status, error: pre.error });

  // --- 1. network-check with cidrV6 --------------------------------------------
  console.log('\n[1] POST /plans/network-check (dual-stack inputs)');
  // Deliberate v6 overlap: exactly GW_Ralf's live NET_INTRANET subnet (from the
  // Status/IPv6 Prefix table). NOTE: fdf8:f53b:70e4::1/64 would NOT collide —
  // it is a DIFFERENT /64 than …70e4:1::/64.
  const chk = await authed('POST', '/plans/network-check', {
    inputs: { name: NET_NAME, vlanId: VLAN_ID, cidr: CIDR, cidrV6: 'fdf8:f53b:70e4:1::/64' }, // deliberate v6 overlap with GW_Ralf's NET_INTRANET
    deviceIds: [DEVICE_WLC],
  });
  // Read the body ONCE — check() evaluates its args eagerly, so an inline
  // `await chk.text()` would consume the stream before .json() could parse it.
  const chkRaw = await chk.text().catch(() => '');
  check('network-check → HTTP 200', chk.status === 200, chkRaw.slice(0, 400));
  let chkBody: { warnings?: Array<{ kind: string; message: string }>; suggestions?: Record<string, unknown> };
  try { chkBody = JSON.parse(chkRaw); } catch { chkBody = {}; }
  console.log(`     warnings: ${JSON.stringify(chkBody.warnings)}`);
  check('v6 overlap warning present (deliberate ULA collision)', (chkBody.warnings ?? []).some((w) => w.kind === 'subnet' && w.message.includes('fdf8:f53b:70e4:1::/64')), chkBody.warnings);
  check('no v4 overlap warning for the free v4 range', !(chkBody.warnings ?? []).some((w) => w.kind === 'subnet' && w.message.includes(CIDR)), chkBody.warnings);
  const sugg = (chkBody.suggestions ?? {}) as Record<string, unknown>;
  console.log(`     suggestions: ${JSON.stringify(sugg)}`);
  check('nextFreeSubnetV6 present (fleet uses v6)', typeof sugg.nextFreeSubnetV6 === 'string' && /^(fc|fd)[0-9a-f]{2}:[0-9a-f:.]+\/64$/.test(String(sugg.nextFreeSubnetV6)), sugg);
  check('nextFreeSubnetV4 still present', typeof sugg.nextFreeSubnetV4 === 'string', sugg);

  // --- 2. preflight with cidrV6 --------------------------------------------------
  console.log('\n[2] preflight WLC01 (dual-stack inputs, read-only)');
  const pf = await authed('POST', '/plans/preflight', { pluginId: LCOS_PLUGIN_ID, intentActionId: 'network.create', inputs: sharedInputs, deviceIds: [DEVICE_WLC] });
  check('preflight → HTTP 200', pf.status === 200);
  const pfRaw = await pf.text();
  let pfResults: PreflightResultDto[];
  try {
    pfResults = ((JSON.parse(pfRaw) as { results?: PreflightResultDto[] }).results) ?? [];
  } catch {
    console.error('     RAW BODY:', pfRaw.slice(0, 1500));
    throw new Error('preflight returned non-JSON body');
  }
  const wlcR = pfResults.find((r) => r.deviceId === DEVICE_WLC);
  check('preflight → result for device', Boolean(wlcR), pfResults);
  if (wlcR) {
    console.log(`     values: ${JSON.stringify(wlcR.values)}`);
    const v6hint = wlcR.values.find((v) => v.key === 'cidrV6');
    check('preflight → cidrV6 hint present', Boolean(v6hint), wlcR.values.map((v) => v.key));
    if (v6hint) {
      check('preflight → cidrV6 echoes the requested prefix', String(v6hint.value) === CIDR_V6, v6hint);
      check('preflight → note says rows will be created', /will create/i.test(String(v6hint.note ?? '')), v6hint.note);
    }
  }

  // --- 3. create + execute dual-stack plan on WLC01 ------------------------------
  console.log('\n[3] create + execute dual-stack plan (WLC01)');
  const created = await authed('POST', '/plans', { pluginId: LCOS_PLUGIN_ID, intentActionId: 'network.create', inputs: sharedInputs, devices: [{ deviceId: DEVICE_WLC }] });
  // Read the body ONCE — check() evaluates its args eagerly (see section [1]).
  const createdRaw = await created.text().catch(() => '');
  check('POST /plans → HTTP 201/200 (cidrV6 accepted by schema)', created.status === 201 || created.status === 200, createdRaw.slice(0, 400));
  let plan: { id?: string } = {};
  try { plan = JSON.parse(createdRaw); } catch { /* non-JSON body — already reported above */ }
  check('plan has an id', Boolean(plan.id), plan);

  let planStatus: string | undefined;
  let createDetails: Record<string, unknown> | null = null;
  if (plan.id) {
    await authed('POST', `/plans/${plan.id}/execute`);
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 2_000));
      const d = ((await authed('GET', `/plans/${plan.id}`).then((r) => r.json())) as Record<string, unknown>) ?? null;
      planStatus = (d?.status as string | undefined);
      if (planStatus === 'succeeded' || planStatus === 'failed') {
        const st = (d?.steps ?? []) as Array<{ actionId?: string; result?: { success?: boolean; result?: { details?: Record<string, unknown>; error?: string } | null } | null }>;
        createDetails = (st.find((s) => s.actionId === 'network.create') ?? st[st.length - 1] ?? {}).result?.result?.details ?? null;
        break;
      }
    }
  }
  check('plan succeeded', planStatus === 'succeeded', { status: planStatus });
  const stepsLog = ((createDetails?.steps as string[]) ?? []);
  console.log(`     steps: ${JSON.stringify(stepsLog, null, 2).replace(/\n/g, '\n     ')}`);
  check('details report l3v6 address', String(createDetails?.l3v6 ?? '') === CIDR_V6, createDetails);
  check('details report v4 L3 address', String(createDetails?.l3 ?? '').startsWith('10.248.0.2'), createDetails);
  check('IPv6/LAN-Interfaces row written', stepsLog.some((s) => s.includes('IPv6/LAN-Interfaces') && !s.includes('already exists')), stepsLog);
  check('IPv6/Network/Addresses row written', stepsLog.some((s) => s.includes('IPv6/Network/Addresses') && !s.includes('already exists')), stepsLog);

  // --- 4. verify both trees -------------------------------------------------------
  console.log('\n[4] verify via read actions');
  const v6read = await runStep('ipv6.networks.read', {});
  check('ipv6.networks.read succeeded', v6read.planStatus === 'succeeded', { status: v6read.status, error: v6read.error });
  const lanIfc = ((v6read.details?.lanInterfaces as Array<Record<string, unknown>>) ?? []);
  const addrs = ((v6read.details?.addresses as Array<Record<string, unknown>>) ?? []);
  console.log(`     lanInterfaces: ${JSON.stringify(lanIfc)}`);
  console.log(`     addresses: ${JSON.stringify(addrs)}`);
  check('v6 LAN-Interfaces row for UNM_E2E_V6', lanIfc.some((r) => String(r.name).toUpperCase() === NET_NAME && Number(r.vlanId) === VLAN_ID), lanIfc);
  check('v6 Addresses row with the ULA prefix', addrs.some((r) => String(r.name).toUpperCase() === NET_NAME && String(r.prefix) === CIDR_V6), addrs);

  const v4read = await runStep('vlan.networks.read', {});
  const v4rows = ((v4read.details?.networks as Array<Record<string, unknown>>) ?? []);
  check('v4 L3 row for UNM_E2E_V6 on VLAN 398', v4rows.some((r) => String(r.name).toUpperCase() === NET_NAME && Number(r.vlanId) === VLAN_ID), v4rows.filter((r) => String(r.name).includes('UNM')));

  // --- 5. idempotency: re-run create with identical inputs -------------------------
  console.log('\n[5] idempotency — re-run network.create (identical inputs)');
  const rerun = await runStep('network.create', sharedInputs);
  check('re-run plan succeeded', rerun.planStatus === 'succeeded', { status: rerun.status, error: rerun.error });
  const rerunSteps = ((rerun.details?.steps as string[]) ?? []);
  console.log(`     steps: ${JSON.stringify(rerunSteps)}`);
  check('v4 L3 row left untouched', rerunSteps.some((s) => s.includes('TCP-IP/Network-list') && s.includes('already exists')), rerunSteps);
  check('IPv6/LAN-Interfaces left untouched', rerunSteps.some((s) => s.includes('IPv6/LAN-Interfaces') && s.includes('already exists')), rerunSteps);
  check('IPv6/Network/Addresses left untouched', rerunSteps.some((s) => s.includes('IPv6/Network/Addresses') && s.includes('already exists')), rerunSteps);

  // --- 6. cleanup -------------------------------------------------------------------
  console.log('\n[6] cleanup');
  const del = await runStep('network.delete', { name: NET_NAME });
  check('cleanup delete succeeded', del.planStatus === 'succeeded', { status: del.status, error: del.error });

  const v6after = await runStep('ipv6.networks.read', {});
  const lanIfcAfter = ((v6after.details?.lanInterfaces as Array<Record<string, unknown>>) ?? []);
  const addrsAfter = ((v6after.details?.addresses as Array<Record<string, unknown>>) ?? []);
  check('v6 LAN-Interfaces row removed', !lanIfcAfter.some((r) => String(r.name).toUpperCase() === NET_NAME), lanIfcAfter);
  check('v6 Addresses row removed', !addrsAfter.some((r) => String(r.name).toUpperCase() === NET_NAME), addrsAfter);

  const v4after = await runStep('vlan.networks.read', {});
  const v4rowsAfter = ((v4after.details?.networks as Array<Record<string, unknown>>) ?? []);
  check('v4 L3 row removed', !v4rowsAfter.some((r) => String(r.name).toUpperCase() === NET_NAME), v4rowsAfter.filter((r) => String(r.name).includes('UNM')));

  const del2 = await runStep('network.delete', { name: NET_NAME });
  check('second delete is a no-op (idempotent)', del2.planStatus === 'succeeded', { status: del2.status, error: del2.error });

  await pool.end();
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('E2E crashed:', err);
  process.exit(1);
});
