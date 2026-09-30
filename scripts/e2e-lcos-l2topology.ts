/**
 * E2E check for Phase I — LCOS L2 abstraction (l2.topology.read + per-device
 * attach-point resolution). FULLY READ-ONLY: no plan writes any device.
 *
 *   1. l2.topology.read on WLC01 (vRouter, NO bridges) and GW_Ralf (physical,
 *      BRG-2 over LAN-1..4 + BUNDLE-1/2 LACP). Assert the parsed hierarchy:
 *        - physical port assignments (ETH-x → LAN-x),
 *        - bridge groups with members (GW_Ralf: BRG-2 ⊇ LAN-1..4),
 *        - bundles with members + operating flag,
 *        - l3Interfaces map (ifc → network names; GW_Ralf: BRG-2 carries the
 *          LAN networks, WLC01: plain LAN-1).
 *   2. Preflight network.create on BOTH devices and assert the resolved
 *      attach point per device:
 *        - GW_Ralf → interface=BRG-2 (high confidence) + vlanPorts convention
 *          list copied from an existing VLAN network's Ports column,
 *        - WLC01   → interface=LAN-1 (plain port carrying L3 directly — the
 *          disabled BUNDLE-1 over it must NOT win).
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-lcos-l2topology.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const LCOS_PLUGIN_ID = '00000000-0000-4000-8000-000000000006';
// WLC01 — 10.25.0.20, LANCOM vRouter (TEST device, no bridges configured).
const DEVICE_WLC = '38cf30d7-e53e-47ae-9545-c79af2270751';
// GW_Ralf — 10.28.0.1, LANCOM 1803VAW-5G (PRODUCTION — reads only).
const DEVICE_GWR = 'fb2f6114-f169-4ca0-b145-f741fec55f11';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 1200) : '');
  }
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

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; text: () => Promise<string>; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, text: async () => (await res.text()), json: async () => (await res.json().catch(() => null)) as never };
  };

  // --- helper: run one single-device plan step and wait ------------------------
  const runStep = async (deviceId: string, actionId: string, inputs: Record<string, unknown>): Promise<{ status: number; planStatus?: string; details?: Record<string, unknown>; error?: string }> => {
    const c = await authed('POST', '/plans', { pluginId: LCOS_PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId }] });
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

  // --- 1. l2.topology.read on both devices --------------------------------------
  console.log('\n[1] l2.topology.read — WLC01 (no bridges)');
  const wlc = await runStep(DEVICE_WLC, 'l2.topology.read', {});
  check('WLC01 topology read succeeded', wlc.planStatus === 'succeeded', { status: wlc.status, error: wlc.error });
  const wlcTopo = (wlc.details ?? {}) as TopoDto;
  console.log(`     physicalPorts: ${JSON.stringify(wlcTopo.physicalPorts)}`);
  console.log(`     bridges: ${JSON.stringify(wlcTopo.bridges)}  bundles: ${JSON.stringify(wlcTopo.bundles)}`);
  console.log(`     l3Interfaces: ${JSON.stringify(wlcTopo.l3Interfaces)}`);
  check('WLC01 → ETH-1 assigned to LAN-1', (wlcTopo.physicalPorts ?? []).some((p) => p.name === 'ETH-1' && p.assignment === 'LAN-1'), wlcTopo.physicalPorts);
  // Factory default: a BRG-1 exists holding the TUNNEL interfaces only — no LAN-x port is bridged.
  const wlcBrgs = (wlcTopo.bridges ?? []).filter((b) => /^BRG-\d+$/i.test(b.name));
  check('WLC01 → factory BRG-1 present with tunnel members', Boolean(wlcBrgs.find((b) => b.name === 'BRG-1' && b.members.some((m) => /GRE-TUNNEL|L2TP-ETHERNET/i.test(m)))), wlcTopo.bridges);
  check('WLC01 → no LAN-x port bridged (LAN domain unbridged)', !(wlcTopo.bridges ?? []).some((b) => b.members.some((m) => /^LAN-\d+$/i.test(m))), wlcTopo.bridges);
  const wlcB1 = (wlcTopo.bundles ?? []).find((b) => b.name === 'BUNDLE-1');
  check('WLC01 → BUNDLE-1 members LAN-1+LAN-2', Boolean(wlcB1 && wlcB1.members.includes('LAN-1') && wlcB1.members.includes('LAN-2')), wlcTopo.bundles);
  check('WLC01 → BUNDLE-1 reported not operating (Operating=No)', wlcB1?.operating === false, wlcB1);
  const wlcL3 = wlcTopo.l3Interfaces ?? {};
  check('WLC01 → plain LAN-1 carries L3 networks', Array.isArray(wlcL3['LAN-1']) && wlcL3['LAN-1'].length > 0, wlcL3);

  console.log('\n[2] l2.topology.read — GW_Ralf (BRG-2 + BUNDLE-1/2)');
  const gwr = await runStep(DEVICE_GWR, 'l2.topology.read', {});
  check('GW_Ralf topology read succeeded', gwr.planStatus === 'succeeded', { status: gwr.status, error: gwr.error });
  const gwrTopo = (gwr.details ?? {}) as TopoDto;
  console.log(`     physicalPorts: ${JSON.stringify(gwrTopo.physicalPorts)}`);
  console.log(`     bridges: ${JSON.stringify(gwrTopo.bridges)}  bundles: ${JSON.stringify(gwrTopo.bundles)}`);
  console.log(`     l3Interfaces: ${JSON.stringify(gwrTopo.l3Interfaces)}`);
  const gwrBrg2 = (gwrTopo.bridges ?? []).find((b) => b.name === 'BRG-2');
  check('GW_Ralf → BRG-2 exists', Boolean(gwrBrg2), gwrTopo.bridges);
  for (const m of ['LAN-1', 'LAN-2', 'LAN-3', 'LAN-4']) {
    check(`GW_Ralf → BRG-2 member ${m}`, Boolean(gwrBrg2?.members.includes(m)), gwrBrg2?.members);
  }
  const gwrB1 = (gwrTopo.bundles ?? []).find((b) => b.name === 'BUNDLE-1');
  check('GW_Ralf → BUNDLE-1 members LAN-1+LAN-2', Boolean(gwrB1 && gwrB1.members.includes('LAN-1') && gwrB1.members.includes('LAN-2')), gwrTopo.bundles);
  check('GW_Ralf → BUNDLE-1 protocol LACP', String(gwrB1?.protocol ?? '').toUpperCase() === 'LACP', gwrB1);
  const gwrB2 = (gwrTopo.bundles ?? []).find((b) => b.name === 'BUNDLE-2');
  check('GW_Ralf → BUNDLE-2 members LAN-3+LAN-4', Boolean(gwrB2 && gwrB2.members.includes('LAN-3') && gwrB2.members.includes('LAN-4')), gwrTopo.bundles);
  const gwrL3 = gwrTopo.l3Interfaces ?? {};
  check('GW_Ralf → BRG-2 carries the LAN networks', Array.isArray(gwrL3['BRG-2']) && gwrL3['BRG-2'].length > 0, gwrL3);
  check('GW_Ralf → NET_INTRANET rides BRG-2', Boolean(gwrL3['BRG-2']?.includes('NET_INTRANET')), gwrL3['BRG-2']);

  // --- 3. preflight network.create — attach-point resolution per device ---------
  const pfInputs = { name: 'UNM_E2E_L2', vlanId: 397 };

  console.log('\n[3] preflight network.create — GW_Ralf (expect BRG-2)');
  const pfGwr = await authed('POST', '/plans/preflight', { pluginId: LCOS_PLUGIN_ID, intentActionId: 'network.create', inputs: pfInputs, deviceIds: [DEVICE_GWR] });
  check('GW_Ralf preflight → HTTP 200', pfGwr.status === 200);
  const gwrPf = (((await pfGwr.json()) as { results?: PreflightResultDto[] }).results ?? []).find((r) => r.deviceId === DEVICE_GWR);
  check('GW_Ralf preflight → result present, not degraded', Boolean(gwrPf && !gwrPf.degraded), gwrPf);
  console.log(`     values: ${JSON.stringify(gwrPf?.values)}`);
  const gwrIface = gwrPf?.values.find((v) => v.key === 'interface');
  check('GW_Ralf → interface suggested BRG-2', String(gwrIface?.value ?? '') === 'BRG-2', gwrIface);
  check('GW_Ralf → confidence high (bridge carries L3)', gwrIface?.confidence === 'high', gwrIface);
  const gwrVlanPorts = gwrPf?.values.find((v) => v.key === 'vlanPorts');
  check('GW_Ralf → vlanPorts convention list present', Array.isArray(gwrVlanPorts?.value), gwrVlanPorts);
  if (Array.isArray(gwrVlanPorts?.value)) {
    for (const m of ['LAN-1', 'LAN-2', 'LAN-3', 'LAN-4']) {
      check(`GW_Ralf → vlanPorts includes ${m}`, (gwrVlanPorts.value as string[]).includes(m), gwrVlanPorts.value);
    }
  }

  console.log('\n[4] preflight network.create — WLC01 (expect plain LAN-1, NOT BUNDLE-1)');
  const pfWlc = await authed('POST', '/plans/preflight', { pluginId: LCOS_PLUGIN_ID, intentActionId: 'network.create', inputs: pfInputs, deviceIds: [DEVICE_WLC] });
  check('WLC01 preflight → HTTP 200', pfWlc.status === 200);
  const wlcPf = (((await pfWlc.json()) as { results?: PreflightResultDto[] }).results ?? []).find((r) => r.deviceId === DEVICE_WLC);
  check('WLC01 preflight → result present, not degraded', Boolean(wlcPf && !wlcPf.degraded), wlcPf);
  console.log(`     values: ${JSON.stringify(wlcPf?.values)}`);
  const wlcIface = wlcPf?.values.find((v) => v.key === 'interface');
  check('WLC01 → interface suggested LAN-1 (plain port carrying L3)', String(wlcIface?.value ?? '') === 'LAN-1', wlcIface);
  check('WLC01 → confidence high (port carries L3 directly)', wlcIface?.confidence === 'high', wlcIface);
  check('WLC01 → disabled BUNDLE-1 NOT suggested', String(wlcIface?.value ?? '') !== 'BUNDLE-1', wlcIface);

  await pool.end();
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('E2E crashed:', err);
  process.exit(1);
});
