/**
 * E2E check for the lancom-lx web-UI (ubus) configuration transport.
 *
 * Drives the live stack against AP_Wohnzimmer (10.25.1.2, production device):
 *   login (2FA) → verify /discover catalog v0.4.0 (actions + `web` slot)
 *   → bind the web credential slot to the assignment (UNM-side only)
 *   → GET /devices/:id/state (Config page document — sections + items)
 *   → plan + execute a READ action (wlan.networks.read) through the full
 *     config-job path (no rollback step for read-only plans)
 *   → plan + execute a MINIMAL write (system.name.set to the device's CURRENT
 *     name — effectively a no-op on the AP) to verify that every mutating
 *     plan gets a best-effort config.backup.download step prepended and that
 *     the backup lands in UNM's central file repository.
 *
 * NO destructive actions are performed (no restore, no reset/reboot).
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
  check('version is 0.4.0', plugins.version === '0.4.0', plugins.version);
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
  for (const id of ['config.read', 'wlan.networks.read', 'radios.read', 'encryption.profiles.read', 'ip.interfaces.read', 'wlc.read', 'system.name.set', 'radio.channel.set', 'ssid.vlan.set', 'wlan.network.add', 'wlc.address.set', 'config.persist', 'config.backup.download', 'config.restore']) {
    check(`action "${id}" in catalog`, actionIds.has(id), [...actionIds]);
  }
  // config.restore must be flagged dangerous (explicit user choice only).
  const restoreAction = actions.find((a) => a.id === 'config.restore');
  check('config.restore is riskLevel dangerous', restoreAction?.riskLevel === 'dangerous', restoreAction);
  // Destructive device actions must NOT be exposed.
  for (const id of ['system.reset', 'system.reboot']) {
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
  const steps = (finalPlan.steps ?? []) as Array<{ actionId: string; status: string; bestEffort?: boolean; result?: Record<string, any> | null }>;
  check('read plan has exactly one step (no rollback for read-only)', steps.length === 1, steps);
  const s0 = steps[0] ?? {};
  const inner = (s0.result?.result ?? {}) as Record<string, unknown>; // ActionResult
  check('read step succeeded', s0.status === 'succeeded' && (inner.success === true || s0.result?.success === true), { status: s0.status, keys: Object.keys(s0.result ?? {}) });
  const details = ((inner.details ?? s0.result?.details) ?? {}) as Record<string, unknown>;
  check('wlan.networks.read returned a count field', typeof details.count === 'number' && (details.count as number) > 0, { keys: Object.keys(details), count: details.count });
  const networks = Array.isArray(details.networks) ? (details.networks as Array<Record<string, unknown>>) : [];
  check('at least one SSID row with a name', networks.some((n) => typeof n.ssid === 'string' && (n.ssid as string).length > 0), { count: networks.length });

  // --- 5. mutating plan → best-effort backup step + file-repo round-trip -----------------
  // system.name.set to the AP's CURRENT name — a write transaction that LCOS
  // accepts as a no-op (per-command errortag 1020, top-level ErrorTag 0), so
  // nothing actually changes on the production device.
  const liveName = String(sys?.items?.[0]?.fields?.Name ?? '');
  check('live device name known from /state', liveName.length > 0 && liveName !== '—', { name: liveName });
  if (liveName.length === 0 || liveName === '—') throw new Error('could not determine the current device name');

  const created2 = await authed('POST', '/plans', {
    pluginId: LX_PLUGIN_ID,
    intentActionId: 'system.name.set',
    inputs: { name: liveName },
    devices: [{ deviceId: DEVICE_ID }],
  });
  const plan2Body = (await created2.json()) as Record<string, any>;
  check('write plan created', created2.status === 201 && Boolean(plan2Body.id), { status: created2.status, body: plan2Body?.error ?? null });
  if (!plan2Body.id) throw new Error('no write plan id');

  const plan2 = (await authed('GET', `/plans/${plan2Body.id}`).then((r) => r.json())) as Record<string, any>;
  const steps2: Array<{ actionId?: string; bestEffort?: boolean }> = plan2.steps ?? [];
  check('write plan has two steps (backup + write)', steps2.length === 2, { count: steps2.length });
  check('step 0 is the best-effort config.backup.download', steps2[0]?.actionId === 'config.backup.download' && steps2[0]?.bestEffort === true, steps2[0]);
  check('step 1 is system.name.set', steps2[1]?.actionId === 'system.name.set', steps2[1]);

  const exec2 = await authed('POST', `/plans/${plan2Body.id}/execute`);
  check('write plan execution started (202)', exec2.status === 202, { status: exec2.status });

  let finalPlan2: Record<string, unknown> | null = null;
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 2_000));
    const detail = (await authed('GET', `/plans/${plan2Body.id}`).then((r) => r.json())) as Record<string, unknown>;
    if (detail && ['succeeded', 'failed', 'cancelled'].includes(String(detail.status))) {
      finalPlan2 = detail;
      break;
    }
  }
  check('write plan finished', Boolean(finalPlan2), finalPlan2?.status);
  const steps2f = ((finalPlan2?.steps ?? []) as Array<{ actionId: string; status: string; result?: Record<string, any> | null }>);
  const backupStep = steps2f.find((s) => s.actionId === 'config.backup.download') ?? {};
  check('backup step succeeded', backupStep.status === 'succeeded', { status: backupStep.status, result: backupStep.result });
  const backupInner = ((backupStep.result?.result ?? backupStep.result) ?? {}) as Record<string, unknown>;
  const repoFileId = typeof backupInner.details?.repoFileId === 'string' ? (backupInner.details.repoFileId as string) : null;
  check('backup step returned a file-repo id', Boolean(repoFileId), { keys: Object.keys(backupInner.details ?? {}) });
  const writeStep = steps2f.find((s) => s.actionId === 'system.name.set') ?? {};
  check('write step succeeded (no-op name set)', writeStep.status === 'succeeded', { status: writeStep.status, result: writeStep.result });

  // The backup must be visible in UNM's central file repository (Files page).
  if (repoFileId) {
    const filesRes = await authed('GET', '/files?category=config-backup');
    check('file repo lists config backups', filesRes.status === 200, { status: filesRes.status });
    const files: Array<{ id?: string; name?: string }> = (((await filesRes.json()) as Record<string, any>)?.files ?? []);
    const entry = files.find((f) => f.id === repoFileId);
    check('backup file present in repo with canonical name', Boolean(entry) && typeof entry.name === 'string' && /__config-backup-\d{8}-\d{6}\.cfg$/.test(entry.name), { found: entry?.name ?? null, expectedId: repoFileId });
  }

  // --- cleanup ------------------------------------------------------------------------
  const del = await authed('DELETE', `/plans/${plan.id}`);
  check('read plan deleted (cleanup)', del.status === 200 || del.status === 204, { status: del.status });
  const del2 = await authed('DELETE', `/plans/${plan2Body.id}`);
  check('write plan deleted (cleanup)', del2.status === 200 || del2.status === 204, { status: del2.status });
  if (repoFileId) {
    const delFile = await authed('DELETE', `/files/${repoFileId}`);
    check('backup file deleted from repo (cleanup)', delFile.status === 200 || delFile.status === 204, { status: delFile.status });
  }

  pool.end();
  console.log(failures ? `\n${failures} FAILURES` : '\nALL CHECKS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch((err) => {
  console.error('e2e crashed:', err);
  process.exit(1);
});
