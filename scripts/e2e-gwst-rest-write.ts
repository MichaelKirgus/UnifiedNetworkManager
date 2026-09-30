/**
 * E2E for the OPNsense 26.7+ REST write path on GWST04 (api-only device — no
 * `ssh` slot bound, so the SSH profile is inactive and the REST model is the
 * only assignment path). Companion to e2e-gwbn-ssh-write.ts (≤26.4 / SSH).
 *
 * WHY THIS SCRIPT ASSERTS A GRACEFUL REFUSAL (not a round-trip):
 *   GWST04 runs OPNsense 26.7.1-amd64. The assignment REST endpoint EXISTS on
 *   this firmware, but its NetworkInterface model only carries
 *   `descr/identifier/icon/optgroup/if/lock` — NO type4/ipaddr/subnet fields
 *   (verified against tag 26.7.1 source AND live: set_item with an IP returns
 *   {"result":"saved"} yet the address never reaches config.xml). The full
 *   IP-capable model exists only on master/nightly builds. So the CORRECT
 *   behavior for network.create here is: detect 'rest', probe the model, and
 *   REFUSE with a clear capability error BEFORE writing any device state —
 *   no silent IP drop, no orphaned VLAN. That refusal IS the green outcome;
 *   forcing a fake round-trip would be dishonest. On a full-model build this
 *   same script's step [2] would instead assert "via REST (full assignment
 *   model)" + live read-back of the address.
 *
 *   1. Preflight network.create → _writePath must be 'rest' with a capability
 *      warning note (model has no IP fields).
 *   2. Plan network.create (VLAN 3998 + L3) → execute → assert the step FAILED
 *      with /CANNOT hold an L3 address/, AND a live read-back shows NO network
 *      and preflight's vlanId hint confirms NO VLAN was created either — zero
 *      partial state.
 *   3. Plan network.delete by name → must be a no-op `skipped` (nothing to
 *      remove) — proves the device is left exactly as found.
 *
 * SAFETY: GWST04's WAN is vtnet0 (public /22) — NEVER an attach target. The
 * attach point is pinned to `interface: 'vtnet1'` (LAN 10.3.1.5/24). VLAN id
 * 3998 (schema max 4094) + CIDR 10.43.98.0/28 keep the test off any real
 * traffic; nothing is ever written on this firmware, but if a future build
 * gains the full model and something leaks, clean up with a network.delete
 * plan for name 'e2e-rest-net'.
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-gwst-rest-write.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const OPN_PLUGIN_ID = 'b0e6c8a2-4f1e-4a3d-9c7b-1a2b3c4d5e6f'; // OPNsense Plugin
// GWST04 — 10.1.1.98, OPNsense 26.7.1-amd64 (WRITE-TEST device for the REST path; api-only).
const DEVICE_GWST = 'd1f67933-f383-4cbc-83d8-531bd31af6be';
const NET_NAME = 'e2e-rest-net';
// Pinned attach point: the LAN port. vtnet0 is WAN (public /22) — NEVER an attach target.
const ATTACH_POINT = 'vtnet1';
const VLAN_ID = 3998;
const CIDR = '10.43.98.1/28';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

// 'unverified' = applied but not confirmed (a valid terminal state for write
// intents that have no read-back verification) — treat it as reached-terminal.
const TERMINAL_STATES = ['succeeded', 'failed', 'cancelled', 'skipped', 'unverified'];
let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 1200) : '');
  }
}

interface PlanStepRow { id: string; stepIndex: number; deviceId: string; actionId: string; status: string; result?: Record<string, unknown> | null }
interface PreflightValueDto { key: string; value: unknown; confidence: 'high' | 'medium' | 'low'; note?: string }

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
  await pool.end();
  check('authenticated (2FA flow)', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // --- helper: create + execute a single-device intent plan -------------------
  const runIntent = async (actionId: string, inputs: Record<string, unknown>): Promise<{ status?: string; steps?: PlanStepRow[] }> => {
    const c = await authed('POST', '/plans', { pluginId: OPN_PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId: DEVICE_GWST }] });
    const planBody = (await c.json()) as { id?: string; status?: string } | null;
    check(`POST /plans ${actionId} → 201`, c.status === 201, planBody);
    if (!planBody?.id) throw new Error('no plan id');
    const e = await authed('POST', `/plans/${planBody.id}/execute`);
    check(`execute ${actionId} → 202`, e.status === 202, await e.json());
    let final: { status?: string; steps?: PlanStepRow[] } = {};
    const deadline = Date.now() + 180_000;
    while (Date.now() < deadline) {
      const r = await authed('GET', `/plans/${planBody.id}`);
      final = (await r.json()) as typeof final;
      if (TERMINAL_STATES.includes(final.status ?? '')) break;
      await new Promise((res2) => setTimeout(res2, 1_000));
    }
    return final;
  };

  // --- helper: live read-back of interfaces_info via the read action ----------
  const readBack = async (): Promise<Array<{ identifier?: string; device?: string; description?: string; config?: { if?: string; descr?: string; ipaddr?: string } }>> => {
    const c = await authed('POST', '/plans', { pluginId: OPN_PLUGIN_ID, intentActionId: 'interfaces.read', inputs: {}, devices: [{ deviceId: DEVICE_GWST }] });
    const planBody = (await c.json()) as { id?: string } | null;
    if (!planBody?.id) return [];
    await authed('POST', `/plans/${planBody.id}/execute`);
    let rows: Array<{ identifier?: string; device?: string; description?: string; config?: { if?: string; descr?: string; ipaddr?: string } }> = [];
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline) {
      const r = await authed('GET', `/plans/${planBody.id}`);
      const p = (await r.json()) as { status?: string; steps?: PlanStepRow[] };
      if (TERMINAL_STATES.includes(p.status ?? '')) break;
      await new Promise((res2) => setTimeout(res2, 1_000));
    }
    // Re-fetch to be sure the result is persisted.
    const r = await authed('GET', `/plans/${planBody.id}`);
    const p = (await r.json()) as { steps?: PlanStepRow[] };
    for (const s of p.steps ?? []) {
      if (s.actionId !== 'interfaces.read' || !s.result) continue;
      const details = ((s.result['result'] as Record<string, unknown> | undefined)?.details ?? {}) as { rows?: Array<{ identifier?: string; device?: string; description?: string; config?: { if?: string; descr?: string; ipaddr?: string } }> };
      if (Array.isArray(details.rows)) rows = details.rows;
    }
    return rows;
  };

  // --- helper: preflight values for network.create ----------------------------
  const preflightValues = async (inputs: Record<string, unknown>): Promise<PreflightValueDto[]> => {
    const pfRes = await authed('POST', '/plans/preflight', { pluginId: OPN_PLUGIN_ID, intentActionId: 'network.create', inputs, deviceIds: [DEVICE_GWST] });
    check(`preflight → 200`, pfRes.status === 200);
    const pfBody = (await pfRes.json()) as { results?: Array<{ deviceId: string; values?: PreflightValueDto[]; error?: string }> } | null;
    return pfBody?.results?.[0]?.values ?? [];
  };

  // --- 0. Idempotency guard: remove a leftover from an earlier failed run -----
  const preRows = await readBack();
  const leftover = preRows.find((r) => (r.description ?? '').toUpperCase() === NET_NAME.toUpperCase() || (r.config?.descr ?? '').toUpperCase() === NET_NAME.toUpperCase());
  if (leftover) {
    console.log(`\n[0] cleaning up leftover network "${NET_NAME}" (${leftover.identifier}) from an earlier run`);
    const cleanup = await runIntent('network.delete', { name: NET_NAME });
    check('cleanup delete reached terminal state', TERMINAL_STATES.includes(cleanup.status ?? ''), cleanup.status);
  } else {
    console.log('\n[0] no leftover network — clean start');
  }

  // --- 1. Preflight: the write path must be 'rest' + capability warning --------
  console.log('\n[1] preflight network.create — GWST04 (26.7.1)');
  const pfValues = await preflightValues({ name: NET_NAME, vlanId: VLAN_ID });
  const writePath = pfValues.find((v) => v.key === '_writePath');
  check('preflight reports _writePath', Boolean(writePath), pfValues.map((v) => v.key));
  check('_writePath is "rest" (26.7+ assignment API present)', writePath?.value === 'rest', writePath);
  // The endpoint existing ≠ IP-capable: the note must warn that a create will be refused.
  check('preflight warns the model cannot hold L3 addresses', /will be REFUSED|no IP fields/i.test(String(writePath?.note ?? '')), writePath);

  // --- 2. network.create — must FAIL GRACEFULLY with zero partial state -------
  console.log('\n[2] network.create — GWST04 (expect capability refusal, NOT a round-trip)');
  const created = await runIntent('network.create', { name: NET_NAME, vlanId: VLAN_ID, cidr: CIDR, interface: ATTACH_POINT });
  check('create plan reached terminal state', TERMINAL_STATES.includes(created.status ?? ''), created.status);
  const createSteps = (created.steps ?? []).filter((s) => s.actionId === 'network.create');
  check('one network.create step FAILED (not skipped, not silent success)', createSteps.length === 1 && createSteps[0].status === 'failed', createSteps.map((s) => `${s.actionId}:${s.status}`));
  // plan_steps.result = { success:false, result: { error } } for a hard failure.
  const createErr = String(((createSteps[0]?.result?.['result'] ?? {}) as Record<string, unknown>)['error'] ?? '');
  check('failure names the capability gap', /CANNOT hold an L3 address/i.test(createErr), createErr);
  check('failure points at a remedy (ssh slot or upgrade)', /bind an `ssh` credential slot|upgrade/i.test(createErr), createErr);

  // Zero partial state: no network in live interfaces_info…
  const afterCreate = await readBack();
  const createdRow = afterCreate.find((r) => (r.description ?? '').toUpperCase() === NET_NAME.toUpperCase() || (r.config?.descr ?? '').toUpperCase() === NET_NAME.toUpperCase());
  check('read-back: NO network present in interfaces_info', !createdRow, createdRow);
  // …and no orphaned VLAN either — the gate fires BEFORE vlan.add. Preflight's
  // vlanId hint is a read-only probe of vlan_settings.
  const pfAfter = await preflightValues({ name: NET_NAME, vlanId: VLAN_ID });
  const vlanHint = pfAfter.find((v) => v.key === 'vlanId');
  check(`read-back: NO orphaned VLAN ${VLAN_ID} (gate fired before vlan.add)`, /no VLAN/.test(String(vlanHint?.note ?? '')), vlanHint);

  // --- 3. network.delete — must be a no-op skip (nothing was created) ---------
  console.log('\n[3] network.delete — GWST04 (expect skipped: nothing to remove)');
  const deleted = await runIntent('network.delete', { name: NET_NAME });
  check('delete plan reached terminal state', TERMINAL_STATES.includes(deleted.status ?? ''), deleted.status);
  const deleteSteps = (deleted.steps ?? []).filter((s) => s.actionId === 'network.delete');
  const deleteDetails = ((deleteSteps[0]?.result?.['result'] ?? {}) as Record<string, unknown>) as { details?: Record<string, unknown> };
  check('delete is a no-op skip (device left exactly as found)', /already|not present|no network/i.test(String(deleteDetails.details?.['skipped'] ?? '')), deleteDetails.details);

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
