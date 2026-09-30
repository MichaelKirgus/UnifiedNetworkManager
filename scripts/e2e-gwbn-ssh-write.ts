/**
 * E2E for the OPNsense ≤26.4 SSH write path on GWBN01 (the device that now has
 * a bound `ssh` slot). Unblocks the Phase J item "GWBN01 write E2E blocked
 * pending SSH slot binding".
 *
 *   1. Preflight network.create → _writePath must be 'ssh' (was null /
 *      "no write path" before the slot was bound).
 *   2. Plan network.create (VLAN 3999 + L3 — a fresh optN on a dedicated
 *      vlan3999 device) → execute → assert the step succeeded AND its result
 *      details say the assignment went via SSH config edit.
 *   3. Plan network.delete by name → execute → assert success + "via SSH".
 *      A delete that finds nothing reports `skipped` — so a successful
 *      non-skipped delete proves the create actually landed on-device.
 *
 * SAFETY: GWBN01's WAN is vtnet0 (DHCP /22) and its LAN is vtnet1. The attach
 * point is therefore pinned to `interface: 'vtnet1'` — never left to the
 * suggestion, which on this device would pick vtnet0 alphabetically and risk
 * breaking the appliance's own uplink (and our management path). The VLAN id
 * 3999 (schema max is 4094) keeps the test off any real traffic; delete tears
 * down assignment + orphaned VLAN.
 *
 * GWBN01 is the designated write-test device (OPNSENSE01 stays reads-only).
 * The network created here is ephemeral and removed in step 3; if anything
 * fails mid-way, clean up manually with a network.delete plan for name
 * 'e2e-ssh-net'.
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-gwbn-ssh-write.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const OPN_PLUGIN_ID = 'b0e6c8a2-4f1e-4a3d-9c7b-1a2b3c4d5e6f'; // OPNsense Plugin
// GWBN01 — 10.1.1.46, OPNsense 26.4.1p2 (WRITE-TEST device; ssh slot bound).
const DEVICE_GWBN = '0add51bf-165f-461c-ad38-935b5f9eb1b3';
const NET_NAME = 'e2e-ssh-net';
// Pinned attach point: the LAN port. vtnet0 is WAN — NEVER an attach target.
const ATTACH_POINT = 'vtnet1';
const VLAN_ID = 3999;

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

  // --- 1. Preflight: the write path must now be 'ssh' --------------------------
  console.log('\n[1] preflight network.create — GWBN01');
  const pfRes = await authed('POST', '/plans/preflight', { pluginId: OPN_PLUGIN_ID, intentActionId: 'network.create', inputs: { name: NET_NAME }, deviceIds: [DEVICE_GWBN] });
  const pfBody = (await pfRes.json()) as { results?: Array<{ deviceId: string; values?: PreflightValueDto[]; error?: string }> } | null;
  check('preflight → 200', pfRes.status === 200, pfBody);
  const pfValues: PreflightValueDto[] = pfBody?.results?.[0]?.values ?? [];
  const writePath = pfValues.find((v) => v.key === '_writePath');
  check('preflight reports _writePath', Boolean(writePath), pfValues.map((v) => v.key));
  check('_writePath is "ssh" (slot bound, ≤26.4)', writePath?.value === 'ssh', writePath);

  // --- helper: create + execute a single-device intent plan -------------------
  const runIntent = async (actionId: string, inputs: Record<string, unknown>): Promise<{ status?: string; steps?: PlanStepRow[] }> => {
    const c = await authed('POST', '/plans', { pluginId: OPN_PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId: DEVICE_GWBN }] });
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

  // --- 2. network.create over the SSH path ------------------------------------
  console.log('\n[2] network.create — GWBN01 (SSH write path)');
  const created = await runIntent('network.create', { name: NET_NAME, vlanId: VLAN_ID, cidr: '10.42.99.1/28', interface: ATTACH_POINT });
  check('create plan reached terminal state', TERMINAL_STATES.includes(created.status ?? ''), created.status);
  const createSteps = (created.steps ?? []).filter((s) => s.actionId === 'network.create');
  check('one network.create step succeeded', createSteps.length === 1 && createSteps[0].status === 'succeeded', createSteps.map((s) => `${s.actionId}:${s.status}`));
  // plan_steps.result = { success, result: ActionResult } — details one level deeper.
  const createDetails = (createSteps[0]?.result?.['result'] ?? {}) as { details?: Record<string, unknown> };
  check('assignment written via SSH', /via SSH config edit/.test(String(createDetails.details?.['assignment'])), createDetails.details);
  const attach = String(createDetails.details?.['attachPoint'] ?? '');
  check(`attach point is the LAN port (${ATTACH_POINT}), NOT WAN`, attach === ATTACH_POINT, { attach });
  // Note: regex LITERALS do not interpolate ${} — build with new RegExp(). The
  // device name is firmware-auto-numbered (vlan01…), so only assert the tag +
  // parent, not the exact vlanif.
  check('VLAN created on the attach point', new RegExp(`created VLAN ${VLAN_ID} on ${ATTACH_POINT}`).test(String(createDetails.details?.['vlan'])), createDetails.details?.['vlan']);

  // --- 3. network.delete — round-trip proof -----------------------------------
  console.log('\n[3] network.delete — GWBN01 (round-trip)');
  const deleted = await runIntent('network.delete', { name: NET_NAME });
  check('delete plan reached terminal state', TERMINAL_STATES.includes(deleted.status ?? ''), deleted.status);
  const deleteSteps = (deleted.steps ?? []).filter((s) => s.actionId === 'network.delete');
  check('one network.delete step succeeded', deleteSteps.length === 1 && deleteSteps[0].status === 'succeeded', deleteSteps.map((s) => `${s.actionId}:${s.status}`));
  const deleteDetails = (deleteSteps[0]?.result?.['result'] ?? {}) as { details?: Record<string, unknown> };
  // A missing network reports `skipped` — a non-skipped "via SSH" removal proves
  // the create actually landed on-device.
  check('assignment removed via SSH (not skipped)', /unassigned .* via SSH config edit/.test(String(deleteDetails.details?.['assignment'])), deleteDetails.details);
  // The create used a dedicated VLAN — the delete must have torn it down too.
  if (deleteDetails.details?.['vlan']) {
    check('orphaned VLAN removed', /removed orphaned VLAN/.test(String(deleteDetails.details['vlan'])), deleteDetails.details['vlan']);
  } else {
    console.log('  INFO no vlan detail on delete (VLAN may have been kept or already gone)');
  }

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
