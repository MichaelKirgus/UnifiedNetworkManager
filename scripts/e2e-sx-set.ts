/**
 * E2E check for the native SNMP transport's SET path (Round 1 verification).
 *
 * Drives a REAL lancom-sx set action end-to-end through the live stack:
 *   login (2FA) → POST /plans (port.speedMode.set, mode=auto on Switch01 port 1 —
 *   an administratively DOWN port, so auto-negotiation is a no-op in practice)
 *   → execute → poll until done → assert step success + re-read verification.
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-sx-set.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const SX_PLUGIN_ID = '00000000-0000-4000-8000-000000000007';
// Switch01.management.kirgus.intra — port 1 "Intranet" is link-down.
const DEVICE_ID = '9e32e21c-44af-4535-8d5f-91efc11ac66c';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 500) : '');
  }
}

async function main(): Promise<void> {
  // --- auth (same flow as e2e-plans.ts: real login + TOTP from seeded secret) --
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

  // --- create the plan ---------------------------------------------------------
  const created = await authed('POST', '/plans', {
    pluginId: SX_PLUGIN_ID,
    intentActionId: 'port.speedMode.set',
    inputs: { port: 1, mode: 1 }, // auto — no-op on a down port
    devices: [{ deviceId: DEVICE_ID }],
  });
  const plan = (await created.json()) as { id?: string; status?: string; steps?: Array<{ id: string; actionId: string }> };
  check('plan created', created.status === 201 && Boolean(plan.id), { status: created.status, body: plan });
  if (!plan.id) throw new Error('no plan id');

  // --- execute + poll ----------------------------------------------------------
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

  const steps = (finalPlan.steps ?? []) as Array<{ actionId: string; status: string; result?: { success?: boolean; result?: Record<string, unknown> } | null }>;
  check('one step', steps.length === 1, steps);
  const s0 = steps[0] ?? {};
  check('step succeeded', s0.status === 'succeeded', s0.result);
  const inner = s0.result?.result ?? {};
  check('action reported success + re-read verification', s0.result?.success === true && (inner.success === true || inner.verified === true), inner);

  // --- cleanup -----------------------------------------------------------------
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
