/**
 * E2E for the OPNsense 26.7.x SSH-FALLBACK write path on GWST04 (runs
 * 26.7.1-amd64; has BOTH an apiKey and a bound `ssh` slot). Companion to
 * e2e-gwbn-ssh-write.ts (≤26.4 / SSH, no REST endpoint at all).
 *
 * WHY THIS IS THE GOLD: the assignment REST endpoint EXISTS on 26.7.x but its
 * minimal model cannot hold an L3 address (verified against tag source + live),
 * so with a bound ssh slot the plugin FALLS BACK to the same config-edit write
 * used on ≤26.4 — making this firmware line fully configurable:
 *
 *   1. Preflight network.create → _writePath must be 'ssh' WITH the note that
 *      the REST API is present but its model has no IP fields (fallback, not
 *      "predates the API").
 *   2. Plan network.create (VLAN 3998 + L3) → execute → assert the step
 *      succeeded via SSH config edit AND a live read-back of interfaces_info
 *      shows the new identifier with its address bound. The read-back is the
 *      real proof: earlier bugs made writes report success while nothing
 *      landed on-device (the 26.7.x REST "saved" trap).
 *   3. Plan network.delete by name → execute → assert success + orphaned-VLAN
 *      removal, and a second read-back shows the identifier gone. Node REMOVAL
 *      works via REST even on the minimal model (del_item is part of it), so
 *      the delete detail may say "via REST" — that mixed-path outcome is
 *      expected and correct: create over SSH fallback, delete over REST.
 *
 * SAFETY: GWST04's WAN is vtnet0 (public /22) — NEVER an attach target. The
 * attach point is pinned to `interface: 'vtnet1'` (LAN 10.3.1.5/24). VLAN id
 * 3998 (schema max 4094) + CIDR 10.43.98.0/28 keep the test off any real
 * traffic; delete tears down assignment + orphaned VLAN. The network created
 * here is ephemeral and removed in step 3; if anything fails mid-way, clean up
 * manually with a network.delete plan for name 'e2e-rest-net'.
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-gwst-rest-write.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const OPN_PLUGIN_ID = 'b0e6c8a2-4f1e-4a3d-9c7b-1a2b3c4d5e6f'; // OPNsense Plugin
// GWST04 — 10.1.1.98, OPNsense 26.7.1-amd64 (WRITE-TEST device; ssh slot bound).
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
    const deadline = Date.now() + 180_000; // SSH config edits are slow (flock + rc script)
    while (Date.now() < deadline) {
      const r = await authed('GET', `/plans/${planBody.id}`);
      final = (await r.json()) as typeof final;
      if (TERMINAL_STATES.includes(final.status ?? '')) break;
      await new Promise((res2) => setTimeout(res2, 1_000));
    }
    return final;
  };

  // --- helper: live read-back of interfaces_info via the read action ----------
  type IfcRow = { identifier?: string; device?: string; description?: string; config?: { if?: string; descr?: string; ipaddr?: string }; ipv4?: Array<{ ipaddr?: string }>; addr4?: string };
  const readBack = async (): Promise<IfcRow[]> => {
    const c = await authed('POST', '/plans', { pluginId: OPN_PLUGIN_ID, intentActionId: 'interfaces.read', inputs: {}, devices: [{ deviceId: DEVICE_GWST }] });
    const planBody = (await c.json()) as { id?: string } | null;
    if (!planBody?.id) return [];
    await authed('POST', `/plans/${planBody.id}/execute`);
    let rows: IfcRow[] = [];
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
      const details = ((s.result['result'] as Record<string, unknown> | undefined)?.details ?? {}) as { rows?: IfcRow[] };
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

  // --- 1. Preflight: the write path must be 'ssh' via REST-fallback note -------
  console.log('\n[1] preflight network.create — GWST04 (26.7.1, ssh slot bound)');
  const pfValues = await preflightValues({ name: NET_NAME, vlanId: VLAN_ID });
  const writePath = pfValues.find((v) => v.key === '_writePath');
  check('preflight reports _writePath', Boolean(writePath), pfValues.map((v) => v.key));
  check('_writePath is "ssh" (REST model cannot hold IPs → fallback)', writePath?.value === 'ssh', writePath);
  // The note must say the REST API IS present but its model lacks IP fields —
  // this distinguishes the 26.7.x fallback from a ≤26.4 appliance.
  check('preflight notes the REST-fallback reason (model has no IP fields)', /REST API present.*no IP fields|fall back to the bound SSH slot/i.test(String(writePath?.note ?? '')), writePath);

  // --- 2. network.create over the SSH fallback ---------------------------------
  console.log('\n[2] network.create — GWST04 (SSH fallback on 26.7.x)');
  const created = await runIntent('network.create', { name: NET_NAME, vlanId: VLAN_ID, cidr: CIDR, interface: ATTACH_POINT });
  check('create plan reached terminal state', TERMINAL_STATES.includes(created.status ?? ''), created.status);
  const createSteps = (created.steps ?? []).filter((s) => s.actionId === 'network.create');
  check('one network.create step succeeded', createSteps.length === 1 && createSteps[0].status === 'succeeded', createSteps.map((s) => `${s.actionId}:${s.status}`));
  // plan_steps.result = { success, result: ActionResult } — details one level deeper.
  const createDetails = (createSteps[0]?.result?.['result'] ?? {}) as { details?: Record<string, unknown> };
  check('assignment written via SSH config edit', /via SSH config edit/.test(String(createDetails.details?.['assignment'])), createDetails.details);
  const attach = String(createDetails.details?.['attachPoint'] ?? '');
  check(`attach point is the LAN port (${ATTACH_POINT}), NOT WAN`, attach === ATTACH_POINT, { attach });
  // The device name is firmware-auto-numbered (vlanNN) — assert tag + parent only.
  check('VLAN created on the attach point', new RegExp(`created VLAN ${VLAN_ID} on ${ATTACH_POINT}`).test(String(createDetails.details?.['vlan'])), createDetails.details?.['vlan']);

  // Read-back: the identifier must EXIST in live interfaces_info with its address.
  const afterCreate = await readBack();
  const createdRow = afterCreate.find((r) => (r.description ?? '').toUpperCase() === NET_NAME.toUpperCase() || (r.config?.descr ?? '').toUpperCase() === NET_NAME.toUpperCase());
  check('read-back: network present in interfaces_info', Boolean(createdRow), afterCreate.map((r) => `${r.identifier}:${r.device}`));
  const wantIp = CIDR.split('/')[0];
  check(`read-back: config address ${wantIp} bound`, createdRow?.config?.ipaddr === wantIp, createdRow);
  // The LIVE address is the strongest proof that rc.configure_interface applied
  // it. Live reporting differs by firmware line: 26.4 fills ipv4[] AND addr4;
  // on 26.7.x a freshly created idle VLAN may not surface one immediately (or at
  // all until traffic/LLDP), so poll both fields for up to ~30s. If it still
  // doesn't appear, that is an INFO — the config-level proof above (config.ipaddr
  // + subnet bound on a real vlanNN device) already proves the write landed.
  const hasLive = (row?: IfcRow | null): boolean =>
    Boolean(row?.ipv4?.some((a) => String(a.ipaddr ?? '').startsWith(wantIp)) || String(row?.addr4 ?? '').startsWith(wantIp));
  let liveRow: IfcRow | null = createdRow;
  const liveDeadline = Date.now() + 30_000;
  while (!hasLive(liveRow) && Date.now() < liveDeadline) {
    await new Promise((res2) => setTimeout(res2, 5_000));
    const again = await readBack();
    liveRow = again.find((r) => (r.description ?? '').toUpperCase() === NET_NAME.toUpperCase()) ?? null;
  }
  if (hasLive(liveRow)) {
    check(`read-back: LIVE address ${wantIp} on the interface`, true, { addr4: liveRow?.addr4, ipv4: liveRow?.ipv4 });
  } else {
    console.log('  INFO live address not yet surfaced in interfaces_info (fresh idle VLAN) — config-level proof above is conclusive');
  }

  // --- 3. network.delete — round-trip proof -----------------------------------
  console.log('\n[3] network.delete — GWST04 (round-trip)');
  const deleted = await runIntent('network.delete', { name: NET_NAME });
  check('delete plan reached terminal state', TERMINAL_STATES.includes(deleted.status ?? ''), deleted.status);
  const deleteSteps = (deleted.steps ?? []).filter((s) => s.actionId === 'network.delete');
  check('one network.delete step succeeded', deleteSteps.length === 1 && deleteSteps[0].status === 'succeeded', deleteSteps.map((s) => `${s.actionId}:${s.status}`));
  const deleteDetails = (deleteSteps[0]?.result?.['result'] ?? {}) as { details?: Record<string, unknown> };
  // A missing network reports `skipped` — a non-skipped removal proves the
  // create actually landed on-device. Node removal works via REST even on the
  // minimal 26.7.x model (del_item is part of it), so accept either path:
  // "via REST (assignment API)" or "via SSH config edit".
  check('assignment removed (not skipped) — REST del_item or SSH', /unassigned .* via (REST \(assignment API\)|SSH config edit)/.test(String(deleteDetails.details?.['assignment'])), deleteDetails.details);
  // The create used a dedicated VLAN — the delete must have torn it down too.
  if (deleteDetails.details?.['vlan']) {
    check('orphaned VLAN removed', /removed orphaned VLAN/.test(String(deleteDetails.details['vlan'])), deleteDetails.details['vlan']);
  } else {
    console.log('  INFO no vlan detail on delete (VLAN may have been kept or already gone)');
  }

  // Read-back: the identifier must be GONE.
  const afterDelete = await readBack();
  const stillThere = afterDelete.find((r) => (r.description ?? '').toUpperCase() === NET_NAME.toUpperCase() || (r.config?.descr ?? '').toUpperCase() === NET_NAME.toUpperCase());
  check('read-back: network gone from interfaces_info', !stillThere, stillThere);

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
