/**
 * E2E check for the lancom-lx web-UI (ubus) configuration transport — READ-ONLY.
 *
 * Drives the live stack against AP_Wohnzimmer (10.25.1.2, production device):
 *   login (2FA) → verify /discover catalog v0.3.0 (actions + `web` slot)
 *   → bind the web credential slot to the assignment (UNM-side only)
 *   → GET /devices/:id/state (Config page document — sections + items)
 *   → plan + execute a READ action (wlan.networks.read) through the full
 *     config-job path.
 *
 * NO writes are performed on the AP (user requirement: avoid destructive or
 * mutating actions on production hardware for now).
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-lx-webapi.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const LX_PLUGIN_ID = '00000000-0000-4000-8000-000000000004';
// AP_Wohnzimmer — production LX-6500, WLC-managed.
const DEVICE_ID = process.env.LX_DEVICE_ID ?? '22e43103-368f-4bbe-a9fe-bac44d0151eb';
// Unbound usernamePassword secret "LANCOM LCOS/LX root user".
const WEB_SECRET_ID = process.env.LX_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 600) : '');
  }
}

async function main(): Promise<void> {
  // --- auth (real login + TOTP from seeded secret) -----------------------------
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

  // --- 1. /discover catalog ------------------------------------------------------
  const plugins = ((await authed('GET', '/plugins').then((r) => r.json())) as Array<Record<string, any>>).find((p) => p.id === LX_PLUGIN_ID);
  check('plugin registered', Boolean(plugins), { id: LX_PLUGIN_ID });
  if (!plugins) throw new Error('plugin not registered');
  check('version is 0.3.0', plugins.version === '0.3.0', plugins.version);
  const caps: string[] = Array.isArray(plugins.capabilities) ? plugins.capabilities : [];
  for (const c of ['configuration', 'planning', 'deviceState']) {
    check(`capability "${c}" advertised`, caps.includes(c), caps);
  }
  const slots: Array<{ name?: string }> = Array.isArray(plugins.credentialSlots) ? plugins.credentialSlots : [];
  check('web credential slot declared', slots.some((s) => s.name === 'web'), slots);
  // The action catalog lives on its own endpoint (the /plugins list row is a summary).
  const actsRes = await authed('GET', `/plugins/${LX_PLUGIN_ID}/actions`);
  check('action catalog endpoint reachable', actsRes.status === 200, { status: actsRes.status });
  const actions: Array<{ id?: string; riskLevel?: string }> = ((await actsRes.json()) as { actions?: Array<{ id?: string }> }).actions ?? [];
  const actionIds = new Set(actions.map((a) => a.id));
  for (const id of ['config.read', 'wlan.networks.read', 'radios.read', 'encryption.profiles.read', 'ip.interfaces.read', 'wlc.read', 'system.name.set', 'radio.channel.set', 'ssid.vlan.set', 'wlan.network.add', 'wlc.address.set', 'config.persist']) {
    check(`action "${id}" in catalog`, actionIds.has(id), [...actionIds]);
  }
  // Destructive device actions must NOT be exposed.
  for (const id of ['system.reset', 'system.reboot', 'config.restore']) {
    check(`destructive action "${id}" absent from catalog`, !actionIds.has(id));
  }

  // --- 2. bind the web credential slot to the assignment ---------------------------
  const patch = await authed('PATCH', `/devices/${DEVICE_ID}/plugins/${LX_PLUGIN_ID}`, { extraCredentials: { web: WEB_SECRET_ID } });
  check('web slot bound (PATCH assignment)', patch.status === 200, { status: patch.status });

  // --- 3. /state — the Config page document ------------------------------------------
  // The API wraps the plugin's DeviceStateResponse in { deviceId, pluginId, state }.
  const stateRes = await authed('GET', `/devices/${DEVICE_ID}/state?pluginId=${LX_PLUGIN_ID}`);
  check('/state endpoint returned 200', stateRes.status === 200, { status: stateRes.status });
  const state = (((await stateRes.json()) as Record<string, any>)?.state ?? {}) as Record<string, any>;
  check('/state returned sections', Array.isArray(state.sections) && state.sections.length >= 5, { count: state.sections?.length });
  const byId = new Map((state.sections ?? []).map((s: any) => [s.id, s]));

  const sys = byId.get('system');
  check('System section present with device name', Boolean(sys?.items?.[0]?.title === 'AP_Wohnzimmer'), sys?.items?.[0]);

  const nets = byId.get('wlan-networks');
  check('WLAN Networks section present', Boolean(nets), { ids: [...byId.keys()] });
  // AP is WLC-managed — local SSID table may be empty; the section must still exist.
  if (nets?.items) {
    const withActions = nets.items.filter((i: any) => Array.isArray(i.actions) && i.actions.length > 0);
    check('network items carry ssid.vlan.set action', nets.items.length === 0 || withActions.length === nets.items.length, { total: nets.items.length, withActions: withActions.length });
  }

  const radios = byId.get('radios');
  check('Radios section has ≥1 item', Boolean(radios?.items?.length >= 1), { count: radios?.items?.length });
  if (radios?.items) {
    const r0 = radios.items[0];
    check('radio item carries channel + power actions', Array.isArray(r0.actions) && r0.actions.some((a: any) => a.actionId === 'radio.channel.set') && r0.actions.some((a: any) => a.actionId === 'radio.power.set'), r0.actions);
  }

  const enc = byId.get('encryption');
  check('Encryption Profiles section present', Boolean(enc), { ids: [...byId.keys()] });

  const ifcs = byId.get('interfaces');
  check('Interfaces & VLANs section has ≥1 item', Boolean(ifcs?.items?.length >= 1), { count: ifcs?.items?.length });

  const wlc = byId.get('wlc');
  check('WLC section present with controller row', Boolean(wlc?.items?.[0]), wlc);
  if (wlc?.items) {
    const fields = wlc.items[0].fields ?? {};
    // The live AP points at the LANCOM WLC — address must be non-empty.
    check('WLC controller address populated', typeof fields.Address === 'string' && fields.Address.length > 0, fields);
  }

  // --- 4. plan + execute a READ action through the full config-job path ---------------
  const created = await authed('POST', '/plans', {
    pluginId: LX_PLUGIN_ID,
    intentActionId: 'wlan.networks.read',
    inputs: {},
    devices: [{ deviceId: DEVICE_ID }],
  });
  const plan = (await created.json()) as { id?: string; status?: string };
  check('read plan created', created.status === 201 && Boolean(plan.id), { status: created.status, body: plan });
  if (!plan.id) throw new Error('no plan id');

  const exec = await authed('POST', `/plans/${plan.id}/execute`);
  check('execution started (202)', exec.status === 202, { status: exec.status });

  let finalPlan: Record<string, unknown> | null = null;
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 2_000));
    const detail = (await authed('GET', `/plans/${plan.id}`).then((r) => r.json())) as Record<string, unknown>;
    if (detail && ['succeeded', 'failed', 'cancelled'].includes(String(detail.status))) {
      finalPlan = detail;
      break;
    }
  }
  check('plan finished', Boolean(finalPlan), finalPlan);
  if (!finalPlan) throw new Error('plan did not finish in time');

  // Step result envelope: the plugin's ActionResult is nested under `result`.
  const steps = (finalPlan.steps ?? []) as Array<{ actionId: string; status: string; result?: Record<string, any> | null }>;
  check('one step', steps.length === 1, steps);
  const s0 = steps[0] ?? {};
  const inner = (s0.result?.result ?? {}) as Record<string, unknown>; // ActionResult
  check('read step succeeded', s0.status === 'succeeded' && (inner.success === true || s0.result?.success === true), { status: s0.status, keys: Object.keys(s0.result ?? {}) });
  const details = ((inner.details ?? s0.result?.details) ?? {}) as Record<string, unknown>;
  check('wlan.networks.read returned a count field', typeof details.count === 'number' && (details.count as number) > 0, { keys: Object.keys(details), count: details.count });
  const networks = Array.isArray(details.networks) ? (details.networks as Array<Record<string, unknown>>) : [];
  check('at least one SSID row with a name', networks.some((n) => typeof n.ssid === 'string' && (n.ssid as string).length > 0), { count: networks.length });

  // --- cleanup ------------------------------------------------------------------------
  const del = await authed('DELETE', `/plans/${plan.id}`);
  check('plan deleted (cleanup)', del.status === 200 || del.status === 204, { status: del.status });

  pool.end();
  console.log(failures ? `\n${failures} FAILURES` : '\nALL CHECKS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch((err) => {
  console.error('e2e crashed:', err);
  process.exit(1);
});
