/**
 * Live verification for the manual automation trigger + window seeding fix.
 * SAFE: creates a TEMPORARY notification-only rule (no intent actions → no plans,
 * nothing applied on any device), exercises both test modes against it, then
 * deletes it and its state rows. Finally seeds the REAL rule's deferral windows
 * via PATCH (idempotent — open windows keep their anchor).
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-automation-manual-trigger.ts [realRuleId]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const REAL_RULE_ID = process.argv[2] ?? '5666aed9-7003-4a76-b0c5-1ee915a6630b';
const DEVICE_ID = 'd124978b-2c22-40b5-a17c-b35e7de9d937'; // KIRGUSBANDE
const PLUGIN_ID = '00000000-0000-4000-8000-000000000009'; // TrueNAS Plugin

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

const NAME_PATTERN = '^(web(0[7-9]|1[01])|synapse0[3-5]-(master|nginx-lb|unbound|web|worker0[1-3])|mastodon0[1-2]|nextcloud0[1-2](-cron)?)$';

async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const token = await mintAdminToken(pool);

  // ── 1. Temporary notification-only rule (same trigger shape as the real one) ──
  const tempRule = {
    name: 'TEMP manual-trigger verification',
    description: 'auto-created by probe-automation-manual-trigger.ts — safe to delete',
    enabled: true,
    triggers: [{
      id: 't-temp1', type: 'updateAvailable', condition: 'available', kinds: ['app'],
      pluginId: PLUGIN_ID, namePattern: NAME_PATTERN, scope: {}, rebootRequired: false,
      defer: { schedule: { kind: 'dailyAt', time: '02:00' } },
    }],
    actions: [{ id: 'a-temp1', type: 'notification', severity: 'info', titleTemplate: 'TEMP verify {{update.name}}', messageTemplate: 'manual trigger probe — no action taken' }],
  };
  const created = await api(token, 'POST', '/automations', tempRule);
  if (created.status !== 201) throw new Error(`temp rule create failed: ${created.status} ${JSON.stringify(created.data)}`);
  const tempId: string = created.data.automation.id;
  console.log(`[1] temp rule created: ${tempId}`);

  let failures = 0;
  const check = (label: string, ok: boolean, detail?: unknown) => {
    console.log(`${ok ? 'PASS' : 'FAIL'} — ${label}${detail !== undefined ? ` :: ${JSON.stringify(detail)?.slice(0, 400)}` : ''}`);
    if (!ok) failures++;
  };

  try {
    // ── 2. seeding on create: temp rule (deferred trigger) got windows for all 10 rows ──
    const state = (await pool.query(`SELECT "stateKey", value FROM automation_state WHERE "automationId"=$1`, [tempId])).rows as { stateKey: string; value: string }[];
    check('create seeded 10 pending windows', state.length === 10, `got ${state.length}`);
    const anchors = new Set(state.map((s) => JSON.parse(s.value).sinceIso));
    check('all windows share one anchor (seeded at create)', anchors.size === 1, [...anchors]);

    // ── 3. mode=apply → one run per live row (10 expected), all succeeded ──
    const apply = await api(token, 'POST', `/automations/${tempId}/test`, { mode: 'apply' });
    check('mode=apply returns 200', apply.status === 200, apply.data);
    const runs: any[] = apply.data?.runs ?? [];
    check(`one run per live row (10)`, runs.length === 10, `got ${runs.length}`);
    check('all runs succeeded', runs.every((r) => r.status === 'succeeded'), runs.map((r) => ({ name: r.context?.update?.name, status: r.status, error: r.error })));
    const names = new Set(runs.map((r) => String(r.context?.update?.name ?? '')));
    check('run contexts carry update rows', names.size === 10 && [...names].every((n) => n.length > 0), [...names]);

    // ── 4. mode=test (legacy wiring check) → single bare-context run (context.kind='test') ──
    const test = await api(token, 'POST', `/automations/${tempId}/test`, { mode: 'test' });
    check('mode=test returns 200', test.status === 200, test.data);
    const testRuns = (test.data?.runs ?? []).filter((r: any) => r.context?.kind === 'test');
    check('mode=test wrote exactly one bare-context run', testRuns.length === 1 && testRuns[0].status === 'succeeded', `got ${testRuns.length}`);

    // ── 5. invalid mode rejected ──
    const bad = await api(token, 'POST', `/automations/${tempId}/test`, { mode: 'bogus' });
    check('invalid mode → 400', bad.status === 400, bad.data);

    // ── 6. manual apply cleared the temp rule's windows (no double-apply later) ──
    const stateAfter = (await pool.query(`SELECT count(*)::int AS n FROM automation_state WHERE "automationId"=$1`, [tempId])).rows[0] as { n: number };
    check('manual apply cleared pending windows', stateAfter.n === 0, `got ${stateAfter.n}`);

    // ── 7. real rule: PATCH (no-op re-save) seeds its windows for the 10 live rows ──
    const list = await api(token, 'GET', '/automations');
    if (list.status !== 200 || !Array.isArray(list.data?.automations)) throw new Error(`cannot list automations: ${list.status}`);
    const realRule = list.data.automations.find((a: any) => a.id === REAL_RULE_ID);
    if (!realRule) throw new Error(`real rule ${REAL_RULE_ID} not found`);
    const patch = await api(token, 'PATCH', `/automations/${REAL_RULE_ID}`, { name: realRule.name }); // no-op re-save → seeding hook
    check('real rule PATCH 200', patch.status === 200, patch.data?.error ?? null);
    const realState = (await pool.query(`SELECT "stateKey", value FROM automation_state WHERE "automationId"=$1 AND "stateKey" LIKE 'pending:%'`, [REAL_RULE_ID])).rows as { stateKey: string; value: string }[];
    check('real rule seeded 10 pending windows', realState.length === 10, `got ${realState.length}`);
    const sample = realState[0] ? JSON.parse(realState[0].value) : null;
    check('window snapshot carries apply path', !!sample?.snapshot?.applyActionId, sample?.snapshot ?? null);

    // ── 8. idempotency: second PATCH does not duplicate or move anchors ──
    const before = realState.map((s) => `${s.stateKey}=${JSON.parse(s.value).sinceIso}`).sort().join('|');
    await api(token, 'PATCH', `/automations/${REAL_RULE_ID}`, { name: realRule.name });
    const afterRows = (await pool.query(`SELECT "stateKey", value FROM automation_state WHERE "automationId"=$1 AND "stateKey" LIKE 'pending:%'`, [REAL_RULE_ID])).rows as { stateKey: string; value: string }[];
    const after = afterRows.map((s) => `${s.stateKey}=${JSON.parse(s.value).sinceIso}`).sort().join('|');
    check('re-PATCH idempotent (same windows, same anchors)', before === after && afterRows.length === 10, `rows ${afterRows.length}`);

    console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  } finally {
    // ── cleanup: temp rule + its state rows (real rule's windows are KEPT on purpose) ──
    const del = await api(token, 'DELETE', `/automations/${tempId}`);
    console.log(`[cleanup] temp rule deleted: ${del.status === 200 ? 'ok' : `FAILED (${del.status})`}`);
    const st = (await pool.query(`DELETE FROM automation_state WHERE "automationId"=$1`, [tempId])).rowCount;
    console.log(`[cleanup] temp state rows removed: ${st ?? 0}`);
    await pool.end();
  }

  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => { console.error(e); process.exit(1); });
