/**
 * E2E for the server-side bulk endpoints (Request E — N+1 audit).
 *
 * Verifies, against the live dev stack:
 *   - POST /plans/bulk-execute      (2FA-gated; API token must be rejected 401)
 *   - POST /plans/bulk-unschedule   (scheduled → restored to pre-schedule status)
 *   - POST /plans/bulk-delete       (steps + plan rows removed, per-id errors)
 *
 * Uses two DISPOSABLE draft plans seeded directly in Postgres (ids
 * bulk-test-plan-1/2, actionId test.noop on the system device) — no real user
 * data is ever executed or deleted. Run from the repo root:
 *   ./node_modules/.bin/tsx scripts/e2e-bulk-endpoints.ts
 */

import path from 'node:path';
import * as fs from 'node:fs';
import { createRequire } from 'node:module';
// pg + jsonwebtoken live in the API package's node_modules — resolve them there.
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

const BASE = process.env.UNM_BASE_URL ?? 'http://localhost:3000/v1';

/** Read a value from the repo .env (falls back to process.env). */
function envValue(key: string): string | null {
  if (process.env[key]) return process.env[key];
  try {
    const m = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8').match(new RegExp(`^${key}=(.+)$`, 'm'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

const API_TOKEN = envValue('UNM_API_TOKEN');
if (!API_TOKEN) throw new Error('UNM_API_TOKEN missing from .env');

const pg = apiRequire('pg');
const pool = new pg.Pool({ connectionString: envValue('DATABASE_URL') ?? process.env.DATABASE_URL });

async function main(): Promise<void> {
  const adminRes = await pool.query("select id from users where username = 'admin' limit 1");
if (adminRes.rows.length === 0) throw new Error('no admin user found');
const ADMIN_ID = adminRes.rows[0].id as string;

/** Mint a short-lived admin JWT with the TOTP amr — passes require2FA. */
function mintJwt(): string {
  const jwt = apiRequire('jsonwebtoken'); // v9 sync API
  return jwt.sign(
    { sub: ADMIN_ID, username: 'admin', roles: [], permissions: ['configs:apply', 'plans:read'], amr: ['totp'] },
    envValue('JWT_SECRET') ?? 'dev-secret',
    { expiresIn: '5m' },
  );
}

let failures = 0;
function check(name: string, cond: boolean, detail?: unknown) {
  if (cond) console.log(`  ok   ${name}`);
  else {
    failures += 1;
    console.error(`  FAIL ${name}${detail !== undefined ? ` — ${JSON.stringify(detail)}` : ''}`);
  }
}

async function call(
  token: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; json: any }> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json: any = null;
  try {
    json = await res.json();
  } catch {
    /* 204 etc. */
  }
  return { status: res.status, json };
}

const P1 = 'bulk-test-plan-1';
const P2 = 'bulk-test-plan-2';

// --- Seed two disposable draft plans (idempotent) ---------------------------
// Wipe any leftovers from a previous run first.
await pool.query(`delete from "plan_steps" where "planId" like 'bulk-test-plan-%'`);
await pool.query(`delete from plans where id like 'bulk-test-plan-%'`);

await pool.query(
  `insert into plans (id, "pluginId", "intentActionId", "intentInputs", status, "provisionedSecrets", error, "createdBy", "executedBy", "cancelledAt", "createdAt", "updatedAt", "startedAt", "finishedAt", "recentlyFinishedAt", "retriedFrom", "scheduledAt", "schedulePolicy", "preScheduleStatus", "scheduleAttempts", "retryPolicy")
   values ($1, '__unm-system__', 'test.noop', '{}', 'draft', '{}', null, $2, null, null, now(), now(), null, null, null, null, null, null, null, 0, null),
          ($3, '__unm-system__', 'test.noop', '{}', 'draft', '{}', null, $2, null, null, now(), now(), null, null, null, null, null, null, null, 0, null)
   on conflict (id) do nothing`,
  [P1, ADMIN_ID, P2],
);
await pool.query(
  `insert into "plan_steps" (id, "planId", "stepIndex", "deviceId", "actionId", input, "dependsOn", "secretRefs", "bestEffort", status, result, "startedAt", "finishedAt")
   values ($1 || '-s', $1, 0, '__unm-system__', 'test.noop', '{}', '[]', '[]', false, 'pending', null, null, null),
          ($2 || '-s', $2, 0, '__unm-system__', 'test.noop', '{}', '[]', '[]', false, 'pending', null, null, null)
   on conflict (id) do nothing`,
  [P1, P2],
);

const token = API_TOKEN; // long-lived API token — must FAIL the 2FA gate
const jwtTok = mintJwt();

console.log('== bulk-execute: 2FA gate ==');
{
  const r = await call(token, 'POST', '/plans/bulk-execute', { ids: [P1] });
  check('API token (amr=token) rejected with 401', r.status === 401, r);
}

console.log('== bulk-unschedule: draft plans are skipped ==');
{
  const r = await call(jwtTok, 'POST', '/plans/bulk-unschedule', { ids: [P1, P2, 'nope-unknown'] });
  check('status 200', r.status === 200, r);
  check('nothing unscheduled (both draft)', Array.isArray(r.json?.unscheduled) && r.json.unscheduled.length === 0, r.json);
  const skippedIds = (r.json?.skipped ?? []).map((s: any) => s.id).sort();
  check('both drafts reported in skipped', JSON.stringify(skippedIds) === JSON.stringify([P1, P2]), r.json);
  check('unknown id reported in errors', (r.json?.errors ?? []).some((e: any) => e.id === 'nope-unknown'), r.json);
}

console.log('== schedule one plan, then bulk-unschedule ==');
{
  const sched = await call(jwtTok, 'POST', `/plans/${P1}/schedule`, { inMinutes: 60 });
  check('single-route schedule ok (200)', sched.status === 200, sched);

  const r = await call(jwtTok, 'POST', '/plans/bulk-unschedule', { ids: [P1, P2] });
  check('status 200', r.status === 200, r);
  check('scheduled plan unscheduled', JSON.stringify(r.json?.unscheduled) === JSON.stringify([P1]), r.json);
  check('draft plan skipped', (r.json?.skipped ?? []).some((s: any) => s.id === P2 && s.status === 'draft'), r.json);

  const row = await pool.query('select status, "scheduledAt" from plans where id=$1', [P1]);
  check(
    'plan restored to draft with schedule cleared (pre-schedule status)',
    row.rows[0]?.status === 'draft' && row.rows[0]?.scheduledAt === null,
    row.rows[0],
  );
}

console.log('== bulk-execute: enqueues the disposable plan ==');
{
  const r = await call(jwtTok, 'POST', '/plans/bulk-execute', { ids: [P1, P2] });
  check('status 200', r.status === 200, r);
  check(
    'both draft plans started',
    JSON.stringify([...(r.json?.started ?? [])].sort()) === JSON.stringify([P1, P2]),
    r.json,
  );

  // Give the executor a moment to fail the unknown action (test.noop is not in
  // any catalog) — the plan must end up failed, never stuck executing.
  let status: string | null = null;
  for (let i = 0; i < 20; i++) {
    const row = await pool.query('select status from plans where id=$1', [P1]);
    status = row.rows[0]?.status ?? null;
    if (status === 'failed' || status === 'succeeded') break;
    await new Promise((res) => setTimeout(res, 500));
  }
  check('executor ran + failed the unknown action (not stuck)', status === 'failed', { P1: status });
}

console.log('== bulk-delete ==');
{
  const r = await call(jwtTok, 'POST', '/plans/bulk-delete', { ids: [P1, P2, 'nope-unknown'] });
  check('status 200', r.status === 200, r);
  check(
    'both plans deleted',
    JSON.stringify([...(r.json?.deleted ?? [])].sort()) === JSON.stringify([P1, P2]),
    r.json,
  );
  check('unknown id reported in errors', (r.json?.errors ?? []).some((e: any) => e.id === 'nope-unknown'), r.json);

  const plansLeft = await pool.query('select count(*)::int as n from plans where id like $1', ['bulk-test-plan-%']);
  const stepsLeft = await pool.query(
    `select count(*)::int as n from "plan_steps" s join plans p on p.id = s."planId" where p.id like 'bulk-test-plan-%'`,
  );
  check('no plan rows remain', plansLeft.rows[0]?.n === 0, plansLeft.rows[0]);
  check('no step rows remain (cascade)', stepsLeft.rows[0]?.n === 0, stepsLeft.rows[0]);
}

  await pool.end();

  if (failures > 0) {
    console.error(`\n${failures} CHECK(S) FAILED`);
    process.exit(1);
  }
  console.log('\nALL BULK-ENDPOINT CHECKS PASSED');
}

main().catch((e) => {
  console.error('E2E run crashed:', e);
  process.exit(1);
});
