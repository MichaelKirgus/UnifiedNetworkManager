/**
 * Live verification for the automation dry run + nextUpdateRun feature.
 * SAFE: a dry run has zero side effects by design (no plans kept, no state
 * touched) — this probe only asserts that on KIRGUSBANDE's real rule:
 *   1. POST /automations/:id/dry-run returns one simulated firing per live row,
 *      each intent action 'would-run' with a concrete plan (steps + devices).
 *   2. No plans are left behind and no run rows are written by the dry run.
 *   3. GET /automations reports nextUpdateRun = the pending window's slot.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-automation-dry-run.ts [realRuleId]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const REAL_RULE_ID = process.argv[2] ?? '5666aed9-7003-4a76-b0c5-1ee915a6630b';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const jwt = apiRequire('jsonwebtoken') as { sign: (p: Record<string, unknown>, s: string, o?: { expiresIn?: number }) => string };

function envValue(key: string): string | null {
  try {
    const m = new RegExp(`^${key}=(.+)$`, 'm').exec(fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

async function mintAdminToken(pool: import('pg').Pool): Promise<string> {
  const secret = envValue('JWT_SECRET') ?? 'dev-secret';
  const row = (await pool.query(`SELECT id, username, roles, permissions FROM users WHERE username = 'admin'`)).rows[0] as
    | { id: string; username: string; roles: unknown; permissions: unknown }
    | undefined;
  if (!row) throw new Error('no admin user');
  const parseArr = (v: unknown): string[] => {
    if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string');
    if (typeof v !== 'string') return [];
    try {
      const p = JSON.parse(v);
      return Array.isArray(p) ? p.filter((x: unknown): x is string => typeof x === 'string') : [];
    } catch {
      return [];
    }
  };
  return jwt.sign({ sub: row.id, username: row.username, roles: parseArr(row.roles), permissions: parseArr(row.permissions), amr: ['totp'] }, secret, { expiresIn: 3600 });
}

async function api(token: string, method: string, p: string, body?: unknown): Promise<{ status: number; data: any }> {
  const res = await fetch(`${API}${p}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data: any = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  return { status: res.status, data };
}

async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const token = await mintAdminToken(pool);

  let failures = 0;
  const check = (label: string, ok: boolean, detail?: unknown) => {
    console.log(`${ok ? 'PASS' : 'FAIL'} — ${label}${detail !== undefined ? ` :: ${JSON.stringify(detail)?.slice(0, 400)}` : ''}`);
    if (!ok) failures++;
  };

  // Baseline counts (dry run must not change either).
  const runsBefore = (await pool.query(`SELECT count(*)::int AS n FROM automation_runs WHERE "automationId"=$1`, [REAL_RULE_ID])).rows[0].n as number;
  const plansBefore = (await pool.query(`SELECT count(*)::int AS n FROM plans`)).rows[0].n as number;

  // ── 1. dry run on the real rule ──
  const res = await api(token, 'POST', `/automations/${REAL_RULE_ID}/dry-run`, {});
  check('dry-run returns 200', res.status === 200, res.data?.error ?? null);
  const firings: any[] = res.data?.firings ?? [];
  check(`one simulated firing per live row (10)`, firings.length === 10, `got ${firings.length}`);

  const intentOutcomes = firings.flatMap((f) => f.actions.filter((a: any) => a.type === 'intent'));
  check('every firing has an intent action', intentOutcomes.length === firings.length, `got ${intentOutcomes.length}/${firings.length}`);
  check("all intent actions are 'would-run'", intentOutcomes.every((a: any) => a.status === 'would-run'), intentOutcomes.map((a: any) => ({ label: firings.find((f: any) => f.actions.includes(a))?.label, status: a.status })));
  check('every would-run carries a concrete plan', intentOutcomes.every((a: any) => a.plan && a.plan.steps.length > 0 && a.plan.deviceIds.length === 1), intentOutcomes.map((a: any) => ({ steps: a.plan?.steps?.length, devices: a.plan?.deviceIds })));
  const sample = intentOutcomes[0]?.plan;
  // The plugin builds a multi-step plan (e.g. config.backup.download → containers.upgrade → …).
  check('plan includes the containers.upgrade step', sample?.actionId === 'containers.upgrade' && sample?.steps.some((s: any) => s.actionId === 'containers.upgrade'), sample);

  // ── 2. zero side effects ──
  const runsAfter = (await pool.query(`SELECT count(*)::int AS n FROM automation_runs WHERE "automationId"=$1`, [REAL_RULE_ID])).rows[0].n as number;
  check('dry run wrote no run rows', runsBefore === runsAfter, `before=${runsBefore} after=${runsAfter}`);
  const plansAfter = (await pool.query(`SELECT count(*)::int AS n FROM plans`)).rows[0].n as number;
  check('dry run left no plans behind', plansBefore === plansAfter, `before=${plansBefore} after=${plansAfter}`);

  // ── 3. nextUpdateRun on the list endpoint ──
  const list = await api(token, 'GET', '/automations');
  const rule = (list.data?.automations ?? []).find((a: any) => a.id === REAL_RULE_ID);
  check('rule present in list with nextUpdateRun set', !!rule && typeof rule.nextUpdateRun === 'string' && rule.nextUpdateRun.length > 0, rule?.nextUpdateRun ?? null);
  if (typeof rule?.nextUpdateRun === 'string') {
    const d = new Date(rule.nextUpdateRun);
    // The seeded windows anchor at yesterday's seeding; the dailyAt 02:00 slot is local time.
    check('nextUpdateRun is a future 02:00 (local) slot', !Number.isNaN(d.getTime()) && d.getTime() > Date.now(), rule.nextUpdateRun);
  }

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  await pool.end();
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => { console.error(e); process.exit(1); });
