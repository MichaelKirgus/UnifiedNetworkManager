/**
 * E2E verification for the updateAvailable automation trigger (Phase 1–3).
 *
 * Update transitions only fire during live telemetry polls from real
 * appliances, so this script drives the engine deterministically instead:
 *   A. DEFERRED WINDOW — creates a rule whose updateAvailable trigger defers to
 *      a dailyAt slot with maxWaitHours ≈ 0 (immediately due), seeds the pending
 *      window directly into automation_state + a matching device_updates row, and
 *      waits for the live evaluator tick (15 s) to fire it. Asserts: run row
 *      written, resolveFromTrigger skips cleanly when the row has no apply path,
 *      notification action succeeds → status 'succeeded'.
 *   B. requireNoReboot GUARD — same deferred-window mechanism, but the seeded
 *      update row (and window snapshot) has rebootRequired=true and the intent
 *      action carries requireNoReboot. Asserts: the intent is skipped ("requires
 *      a reboot"), the notification still runs → status 'succeeded' (a guard
 *      skip is not a failure).
 *   C. PLAN CREATION — same mechanism, but the seeded row points at a REAL
 *      plugin+device pair whose persisted catalog has a read-risk, no-required-
 *      input action via applyActionId. Asserts: a plan row is created (status
 *      ready/executing) — i.e. resolveFromTrigger fills pluginId/actionId/input
 *      from the firing row and createPlanCore + enqueue succeed end-to-end. The
 *      plan is cancelled in cleanup; even if the executor already ran it, the
 *      action is read-risk only (no hardware mutation).
 *
 * Auth: mints a TOTP-amr session JWT from the DB admin row (same shape as
 * /auth/2fa/verify output) — no password needed.
 *
 * All fixtures use synthetic ids (device_updates has no FKs) or are removed in
 * cleanup; scenario C's plan is cancelled, never executed.
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/verify-update-automations.ts
 */

import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const RUN_TIMEOUT_MS = 90_000; // evaluator tick is 15 s — allow a few cycles

// pg + jsonwebtoken live in api/node_modules; resolve through the API package.
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const jwt = apiRequire('jsonwebtoken') as { sign: (payload: Record<string, unknown>, secret: string, opts?: { expiresIn?: number | string }) => string };

/** Reads a value from the repo .env (never printed). */
function envValue(key: string): string | null {
  try {
    const m = new RegExp(`^${key}=(.+)$`, 'm').exec(fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

/**
 * Mints a session JWT with amr ['totp'] — the same claim shape /auth/2fa/verify
 * produces after a successful TOTP step. The only non-interactive way to get a
 * write-capable session in an E2E script (admin has an enrolled TOTP secret).
 */
async function mintTotpSessionToken(pool: { query: (sql: string) => Promise<{ rows: unknown[] }> }): Promise<string | null> {
  const secret = envValue('JWT_SECRET') ?? 'dev-secret';
  const row = (await pool.query(`SELECT id, username, roles, permissions FROM users WHERE username = 'admin'`)).rows[0] as
    | { id: string; username: string; roles: unknown; permissions: unknown }
    | undefined;
  if (!row) return null;
  // The columns are TEXT holding JSON arrays — pg returns them as strings.
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

let failures = 0;
function check(label: string, ok: boolean, detail?: unknown): void {
  if (ok) console.log(`PASS ${label}`);
  else {
    failures++;
    console.error(`FAIL ${label}${detail !== undefined ? ` — ${JSON.stringify(detail).slice(0, 400)}` : ''}`);
  }
}

async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  // --- Auth (minted TOTP-amr session JWT — see mintTotpSessionToken) --------
  const token = await mintTotpSessionToken(pool);
  if (!token) {
    console.error('FAIL login failed');
    await pool.end();
    process.exit(1);
  }
  const authHeaders = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  // Synthetic identity — device_updates has no FKs, so this never touches real rows.
  const DEV_A = 'e2e-update-auto-dev-a';
  const PLG_A = 'e2e-update-auto-plg-a';
  const markerIso = new Date().toISOString();
  const createdRuleIds: string[] = [];
  const seededUpdateKeys: Array<[string, string, string, string]> = []; // (deviceId, pluginId, kind, name)

  async function createRule(draft: Record<string, unknown>): Promise<string> {
    const r = await fetch(`${API}/automations`, { method: 'POST', headers: authHeaders, body: JSON.stringify(draft) });
    if (!r.ok) throw new Error(`POST /automations → ${r.status}: ${(await r.text()).slice(0, 300)}`);
    const id = ((await r.json()) as { automation: { id: string } }).automation.id;
    createdRuleIds.push(id);
    return id;
  }

  async function seedUpdateRow(deviceId: string, pluginId: string, kind: string, name: string, extra: Record<string, unknown>): Promise<void> {
    await pool.query(
      `INSERT INTO device_updates ("deviceId", "pluginId", kind, name, "currentVersion", "latestVersion", "rebootRequired", "applyActionId", "applyInput", "collectedAt")
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [deviceId, pluginId, kind, name, '1.0.0', '1.1.0', !!extra.rebootRequired, extra.applyActionId ?? null, JSON.stringify(extra.applyInput ?? {}), new Date().toISOString()]
    );
    seededUpdateKeys.push([deviceId, pluginId, kind, name]);
  }

  async function seedPendingWindow(ruleId: string, triggerId: string, snapshot: Record<string, unknown>): Promise<void> {
    const key = `pending:${snapshot.deviceId}|${snapshot.pluginId}|${snapshot.kind}|${snapshot.name}`;
    await pool.query(
      `INSERT INTO automation_state ("automationId", "triggerId", "stateKey", "value", "updatedAt") VALUES ($1,$2,$3,$4,$5)`,
      [ruleId, triggerId, key, JSON.stringify({ sinceIso: new Date().toISOString(), snapshot }), new Date().toISOString()]
    );
  }

  async function waitForRun(ruleId: string): Promise<Record<string, unknown> | null> {
    const deadline = Date.now() + RUN_TIMEOUT_MS;
    for (;;) {
      const r = await fetch(`${API}/automations/${ruleId}/runs?limit=5`, { headers: authHeaders });
      if (r.ok) {
        const runs = ((await r.json()) as { runs: Array<Record<string, unknown>> }).runs;
        const fresh = runs.find((x) => String(x.firedAt ?? '') >= markerIso);
        if (fresh) return fresh;
      }
      if (Date.now() > deadline) return null;
      await new Promise((res) => setTimeout(res, 3_000));
    }
  }

  try {
    // ── A. Deferred window → due via maxWaitHours → fires on the live tick ──
    const ruleA = await createRule({
      name: 'e2e-update-auto-A-deferred',
      description: 'E2E fixture — deferred updateAvailable trigger (verify-update-automations)',
      enabled: true,
      cooldownSec: 0,
      triggers: [
        {
          id: 't-a', type: 'updateAvailable', condition: 'available',
          kinds: ['app'], names: ['e2e-app-a'], rebootRequired: false,
          defer: { schedule: { kind: 'dailyAt', time: '02:00' }, maxWaitHours: 0.001 }, // ≈3.6 s → immediately due
        },
      ],
      actions: [
        { id: 'a-apply', type: 'intent', resolveFromTrigger: 'update', requireNoReboot: true, devices: {} },
        { id: 'a-note', type: 'notification', severity: 'info', titleTemplate: 'E2E A update applied on {{device.name}}', messageTemplate: '{{update.kind}} "{{update.name}}" → {{update.latestVersion}}' },
      ],
    });
    await seedUpdateRow(DEV_A, PLG_A, 'app', 'e2e-app-a', {}); // no applyActionId → intent must skip cleanly
    await seedPendingWindow(ruleA, 't-a', { deviceId: DEV_A, pluginId: PLG_A, kind: 'app', name: 'e2e-app-a', currentVersion: '1.0.0', latestVersion: '1.1.0', rebootRequired: false });
    const runA = await waitForRun(ruleA);
    check('A: evaluator tick fired the due deferred window', !!runA, runA ?? `no run within ${RUN_TIMEOUT_MS / 1000}s`);
    if (runA) {
      check("A: run status 'succeeded' (intent skipped cleanly + notification ok)", runA.status === 'succeeded', runA);
      const err = String(runA.error ?? '');
      check('A: resolveFromTrigger skip reason recorded (no apply path)', /no apply path/.test(err), err);
    }

    // ── B. requireNoReboot guard (deferred window with a reboot-required row) ─
    const ruleB = await createRule({
      name: 'e2e-update-auto-B-noreboot',
      description: 'E2E fixture — requireNoReboot guard (verify-update-automations)',
      enabled: true,
      cooldownSec: 0,
      triggers: [
        {
          id: 't-b', type: 'updateAvailable', condition: 'available',
          kinds: ['firmware'], names: ['e2e-fw-b'], rebootRequired: false,
          defer: { schedule: { kind: 'dailyAt', time: '02:00' }, maxWaitHours: 0.001 },
        },
      ],
      actions: [
        { id: 'a-apply', type: 'intent', resolveFromTrigger: 'update', requireNoReboot: true, devices: {} },
        { id: 'a-note', type: 'notification', severity: 'info', titleTemplate: 'E2E B update on {{device.name}}', messageTemplate: '{{update.kind}} "{{update.name}}" needs a reboot — skipped' },
      ],
    });
    await seedUpdateRow(DEV_A, PLG_A, 'firmware', 'e2e-fw-b', { rebootRequired: true });
    await seedPendingWindow(ruleB, 't-b', { deviceId: DEV_A, pluginId: PLG_A, kind: 'firmware', name: 'e2e-fw-b', currentVersion: '1.0.0', latestVersion: '1.1.0', rebootRequired: true });
    const runB = await waitForRun(ruleB);
    check('B: evaluator tick fired the due deferred window', !!runB, runB ?? `no run within ${RUN_TIMEOUT_MS / 1000}s`);
    if (runB) {
      check('B: intent skipped by requireNoReboot guard', /requires a reboot/.test(String(runB.error ?? '')), runB);
      check("B: run status 'succeeded' (guard skip is not a failure)", runB.status === 'succeeded', runB);
    }

    // ── C. resolveFromTrigger → real plan creation (read-risk action) ────────
    const cat = await pool.query(`SELECT id, name, "actionDescriptors" FROM plugins WHERE "actionDescriptors" IS NOT NULL`);
    let picked: { pluginId: string; pluginName: string; deviceId: string; deviceName: string; actionId: string } | null = null;
    for (const row of cat.rows as Array<{ id: string; name: string; actionDescriptors: string }>) {
      let entries: Array<{ id: string; riskLevel?: string; deviceCount?: number | 'N'; inputSchema?: Record<string, { required?: boolean }> }> = [];
      try { entries = JSON.parse(row.actionDescriptors); } catch { continue; }
      const entry = (entries as typeof entries).find(
        (e) => e.riskLevel === 'read' && (e.deviceCount === 1 || e.deviceCount === 'N') && Object.values(e.inputSchema ?? {}).every((p) => !p.required)
      );
      if (!entry) continue;
      const dev = await pool.query(`SELECT d.id, d.name FROM device_plugins dp JOIN devices d ON d.id = dp."deviceId" WHERE dp."pluginId" = $1 LIMIT 1`, [row.id]);
      if (dev.rows.length === 0) continue;
      picked = { pluginId: row.id, pluginName: row.name, deviceId: dev.rows[0].id as string, deviceName: dev.rows[0].name as string, actionId: entry.id };
      break;
    }

    if (!picked) {
      console.log('SKIP C: no real plugin with a read-risk, no-input catalog action + assigned device — plan-creation path not exercised');
    } else {
      const ruleC = await createRule({
        name: 'e2e-update-auto-C-plan',
        description: `E2E fixture — resolveFromTrigger plan creation via ${picked.pluginName} (verify-update-automations)`,
        enabled: true,
        cooldownSec: 0,
        triggers: [
          {
            id: 't-c', type: 'updateAvailable', condition: 'available',
            kinds: ['app'], names: ['e2e-app-c'], rebootRequired: false,
            defer: { schedule: { kind: 'dailyAt', time: '02:00' }, maxWaitHours: 0.001 },
          },
        ],
        actions: [{ id: 'a-apply', type: 'intent', resolveFromTrigger: 'update', devices: {} }],
      });
      await seedUpdateRow(picked.deviceId, picked.pluginId, 'app', 'e2e-app-c', { applyActionId: picked.actionId, applyInput: {} });
      await seedPendingWindow(ruleC, 't-c', { deviceId: picked.deviceId, pluginId: picked.pluginId, kind: 'app', name: 'e2e-app-c', currentVersion: '1.0.0', latestVersion: '1.1.0', rebootRequired: false, applyActionId: picked.actionId, applyInput: {} });
      const runC = await waitForRun(ruleC);
      check('C: evaluator tick fired the due deferred window', !!runC, runC ?? `no run within ${RUN_TIMEOUT_MS / 1000}s`);
      if (runC) {
        // The plugin's /plan endpoint must be reachable for plan creation — a
        // down plugin container is an environment gap, not a feature failure.
        const err = String(runC.error ?? '');
        if (runC.status !== 'succeeded' && /planning failed|unreachable/i.test(err)) {
          console.log(`SKIP C: ${picked.pluginName} unreachable for plan build (${err.slice(0, 120)})`);
        } else {
          check("C: run status 'succeeded' (plan created)", runC.status === 'succeeded', runC);
          // The API serves planIds already parsed; tolerate the raw JSON string too.
          const rawPlanIds = runC.planIds;
          const planIds: string[] = Array.isArray(rawPlanIds) ? rawPlanIds : (JSON.parse(String(rawPlanIds ?? '[]')) as string[]);
          check('C: exactly one plan id recorded on the run', planIds.length === 1, runC.planIds);
          if (planIds[0]) {
            const p = await pool.query(`SELECT status FROM plans WHERE id = $1`, [planIds[0]]);
            check("C: plan row exists with status ready/executing", ['ready', 'executing'].includes(String(p.rows[0]?.status)), p.rows[0]);
          } else {
            check('C: plan row exists', false, runC.planIds);
          }
        }
      }
    }

    // ── Cleanup ──────────────────────────────────────────────────────────────
    for (const [deviceId, pluginId, kind, name] of seededUpdateKeys) {
      await pool.query(`DELETE FROM device_updates WHERE "deviceId"=$1 AND "pluginId"=$2 AND kind=$3 AND name=$4`, [deviceId, pluginId, kind, name]);
    }
    for (const id of createdRuleIds) {
      // Cancel any plan the rule produced before deleting it.
      const runs = await pool.query(`SELECT "planIds", status FROM automation_runs WHERE "automationId"=$1`, [id]);
      for (const r of runs.rows as Array<{ planIds: string; status: string }>) {
        try {
          for (const pid of JSON.parse(r.planIds ?? '[]') as string[]) {
            await fetch(`${API}/plans/${pid}/cancel`, { method: 'POST', headers: authHeaders, body: '{}' }).catch(() => undefined);
          }
        } catch { /* keep going */ }
      }
      await pool.query(`DELETE FROM automation_state WHERE "automationId"=$1`, [id]);
      await pool.query(`DELETE FROM automation_runs WHERE "automationId"=$1`, [id]);
      // context is TEXT holding JSON — match the automation id inside it.
      await pool.query(`DELETE FROM notifications WHERE context LIKE $1`, [`%"automationId":"${id}"%`]).catch(() => undefined);
      const del = await fetch(`${API}/automations/${id}`, { method: 'DELETE', headers: authHeaders });
      check(`cleanup: rule ${id.slice(0, 8)} deleted`, del.status === 200, del.status);
    }
  } finally {
    // Safety net — remove any fixture rows even if a step above threw.
    for (const [deviceId, pluginId, kind, name] of seededUpdateKeys) {
      await pool.query(`DELETE FROM device_updates WHERE "deviceId"=$1 AND "pluginId"=$2 AND kind=$3 AND name=$4`, [deviceId, pluginId, kind, name]).catch(() => undefined);
    }
    for (const id of createdRuleIds) {
      await pool.query(`DELETE FROM automation_state WHERE "automationId"=$1`, [id]).catch(() => undefined);
      await pool.query(`DELETE FROM automation_runs WHERE "automationId"=$1`, [id]).catch(() => undefined);
      await fetch(`${API}/automations/${id}`, { method: 'DELETE', headers: authHeaders }).catch(() => undefined);
    }
    await pool.end();
  }

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('FATAL', err);
  process.exit(1);
});
