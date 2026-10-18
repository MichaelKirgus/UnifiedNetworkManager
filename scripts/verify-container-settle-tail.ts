/**
 * Verifies the container-lifecycle settle+refresh plan tail (ix-truenas 0.28.0):
 *   1. logs in via the real auth flow (TOTP minted from the seeded admin secret)
 *   2. creates a containers.restart plan for chrony05 on KIRGUSBANDE WITHOUT executing it
 *   3. asserts the plan ends with unm.wait {ms:15000} + unm.inventory.refresh {}
 *   4. deletes the draft plan again (cleanup)
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/verify-container-settle-tail.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const DEVICE_ID = process.env.DEVICE_ID ?? 'd124978b-2c22-40b5-a17c-b35e7de9d937'; // KIRGUSBANDE
const PLUGIN_ID = '00000000-0000-4000-8000-000000000009'; // ix-truenas (primary)
const CONTAINER = process.env.CONTAINER ?? 'chrony05';
// The admin password is NOT the dev default on this stack — override via env.
const ADMIN_USER = process.env.ADMIN_USERNAME ?? 'admin';
const ADMIN_PASS = process.env.ADMIN_PASSWORD ?? 'admin';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

async function main(): Promise<void> {
  // --- Login (admin/admin; TOTP when enabled) ---------------------------------
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };

  let token: string | null = null;
  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: ADMIN_USER, password: ADMIN_PASS }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  } else {
    const otplib = apiRequire('otplib');
    const code = await otplib.generate({ secret: adminRow.totpSecret });
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: ADMIN_USER, password: ADMIN_PASS }) });
    const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
  }
  check('authenticated (2FA session)', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, init?: RequestInit): Promise<Response> =>
    fetch(`${API}${p}`, {
      method,
      body: init?.body,
      headers: { Authorization: `Bearer ${token}`, ...(init?.headers as Record<string, unknown> | undefined) },
    });

  // --- Create the restart plan WITHOUT executing it ----------------------------
  const createRes = await authed('POST', '/plans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pluginId: PLUGIN_ID, intentActionId: 'containers.restart', inputs: { name: CONTAINER }, devices: [{ deviceId: DEVICE_ID }] }),
  });
  const created = (await createRes.json().catch(() => null)) as { id?: string; error?: string } | null;
  check(`POST /plans containers.restart → 201/200`, createRes.status === 200 || createRes.status === 201, created);
  if (!created?.id) throw new Error('plan creation failed');

  const planId = created.id!;
  try {
    // --- Assert the settle+refresh tail ----------------------------------------
    const getRes = await authed('GET', `/plans/${planId}`);
    const plan = (await getRes.json()) as { status: string; steps: Array<{ stepIndex: number | string; actionId: string; input?: Record<string, unknown>; bestEffort?: boolean }> };
    check(`plan ${plan.status} has ≥3 steps`, (plan.steps ?? []).length >= 3, plan.steps);

    const tail = (plan.steps ?? []).slice(-2);
    check('tail step -1 is unm.wait', tail[0]?.actionId === 'unm.wait', tail[0]);
    check('unm.wait input.ms = 15000', Number(tail[0]?.input?.['ms']) === 15_000, tail[0]?.input);
    check('tail step -2 is unm.inventory.refresh', tail[1]?.actionId === 'unm.inventory.refresh', tail[1]);
    check('both tail steps bestEffort', Boolean(tail[0]?.bestEffort) && Boolean(tail[1]?.bestEffort), tail);

    // The restart intent step itself must come BEFORE the tail.
    const restartIdx = (plan.steps ?? []).findIndex((s) => s.actionId === 'containers.restart');
    check('containers.restart step precedes the tail', restartIdx >= 0 && restartIdx < (plan.steps?.length ?? 0) - 2, plan.steps);

    console.log('\nPlan steps:');
    for (const s of plan.steps ?? []) {
      console.log(`  ${s.stepIndex}: ${s.actionId} ${JSON.stringify(s.input ?? {})}${s.bestEffort ? ' (best-effort)' : ''}`);
    }
  } finally {
    // --- Cleanup: delete the draft plan ----------------------------------------
    const delRes = await authed('DELETE', `/plans/${planId}`);
    check(`cleanup DELETE /plans/${planId} → 2xx`, delRes.status >= 200 && delRes.status < 300, delRes.status);
  }

  pool.end();
  if (failures > 0) {
    console.error(`\n${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('\nAll checks passed.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
