/**
 * verify-lcos-dns-dual.ts — LIVE verification of the merge-aware LCOS dns.set /
 * dns.delete intents on WLC01 (the safe test vRouter, 10.25.0.20):
 *   1. dns.set with BOTH `ip` (v4) and `ipv6` → one DNS-List row carrying both
 *      families; GET /dns must show the name with BOTH addresses.
 *   2. Idempotent re-set of the same v4 (no ipv6) → clean skip — the intent's
 *      sibling-preservation makes desired == existing, so nothing is rewritten.
 *   3. dns.set with a NEW v4 only (no ipv6) → applied; the row's v6 must be
 *      PRESERVED (the whole point of merge-awareness: LCOS `add` replaces the
 *      entire single-keyed row, verified live via probe-lcos-dns-dual.ts).
 *   4. dns.delete scoped to the v4 → family-scoped removal; the v6 SURVIVOR is
 *      re-added by the intent and must still be present in GET /dns.
 *   5. Cleanup: dns.delete without `ip` removes the whole row; entry gone.
 *
 * Addresses are RFC 5737 / ULA documentation ranges — they never collide with
 * real fleet entries, and WLC01 is a test device (writes OK). Every write has
 * its cleanup counterpart; on success the device ends in its pre-test state.
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/verify-lcos-dns-dual.ts
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';

// WLC01 — LCOS vRouter test device (writes OK).
const DEVICE_ID = process.env.LCOS_DEVICE_ID ?? '38cf30d7-e53e-47ae-9545-c79af2270751';
const PLUGIN_ID = process.env.LCOS_PLUGIN_ID ?? '00000000-0000-4000-8000-000000000006';

// Distinct test entry — never collides with real fleet entries.
const TEST_NAME = 'unm-dns-dual';
const V4_A = '192.0.2.77'; // RFC 5737 documentation range
const V6 = 'fd00::77';     // ULA — never routable outside the site
const V4_B = '192.0.2.78';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const { Pool } = apiRequire('pg');
// otplib@13 — functional API (no `authenticator` instance).
const { generate: otpGenerate } = apiRequire('otplib') as { generate: (opts: { strategy: string; secret: string }) => Promise<string> };
const jwt = apiRequire('jsonwebtoken') as { sign: (payload: Record<string, unknown>, secret: string, opts?: { expiresIn?: number | string }) => string };

function envValue(key: string): string | null {
  try {
    const m = new RegExp(`^${key}=(.+)$`, 'm').exec(fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

/** Mints a totp-amr session JWT (plan writes are require2FA-gated). */
async function mintTotpSessionToken(pool: Pool): Promise<string | null> {
  const secret = envValue('JWT_SECRET') ?? 'dev-secret';
  const row = (await pool.query(`SELECT id, username, roles, permissions FROM users WHERE username = 'admin'`)).rows[0] as
    | { id: string; username: string; roles: unknown; permissions: unknown }
    | undefined;
  if (!row) return null;
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
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 600) : '');
  }
}

interface StepRow { id: string; stepIndex: number; deviceId: string; actionId: string; status: string; result?: Record<string, unknown> | null; }
interface PlanDto { id?: string; status?: string; steps?: StepRow[]; error?: string | null; }

function actionResult(step: StepRow): { success?: boolean; applied?: boolean; details?: Record<string, unknown>; error?: string } | null {
  const outer = step.result ?? null;
  if (!outer || typeof outer !== 'object') return null;
  const inner = (outer as Record<string, unknown>)['result'];
  const src: Record<string, unknown> = (inner && typeof inner === 'object' ? inner : outer) as Record<string, unknown>;
  return { success: src['success'] as boolean | undefined, applied: src['applied'] as boolean | undefined, details: src['details'] as Record<string, unknown> | undefined, error: src['error'] as string | undefined };
}

async function main(): Promise<void> {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  let token: string | null = await mintTotpSessionToken(pool);
  if (!token) {
    try {
      const envFile = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
      token = (/^UNM_API_TOKEN=(.+)$/m.exec(envFile)?.[1] ?? '').trim() || null;
    } catch { /* no .env */ }
  }
  if (!token) throw new Error('no usable auth (mint failed and no UNM_API_TOKEN in .env)');
  check('authenticated', true);

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  const TERMINAL = ['succeeded', 'failed', 'cancelled', 'unverified'];
  async function runAction(actionId: string, inputs: Record<string, unknown>, timeoutMs = 300_000): Promise<{ planStatus?: string; step?: StepRow }> {
    const createRes = await authed('POST', '/plans', { pluginId: PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId: DEVICE_ID }] });
    if (createRes.status !== 201) {
      console.error(`  !! plan creation for ${actionId} → ${createRes.status}:`, JSON.stringify(await createRes.json()).slice(0, 300));
      return {};
    }
    const created = (await createRes.json()) as PlanDto;
    const execRes = await authed('POST', `/plans/${created.id}/execute`);
    if (execRes.status !== 202) {
      console.error(`  !! execute for ${actionId} → ${execRes.status}:`, JSON.stringify(await createRes.json()).slice(0, 300));
      return {};
    }
    const deadline = Date.now() + timeoutMs;
    let final: PlanDto = {};
    while (Date.now() < deadline) {
      const r = await authed('GET', `/plans/${created.id}`);
      final = (await r.json()) as PlanDto;
      if (TERMINAL.includes(final.status ?? '')) break;
      await new Promise((res2) => setTimeout(res2, 750));
    }
    return { planStatus: final.status, step: final.steps?.find((s) => s.actionId === actionId) ?? final.steps?.[final.steps.length - 1] };
  }

  async function refresh(): Promise<void> {
    for (let attempt = 1; attempt <= 5; attempt++) {
      const r = await authed('POST', '/devices/refresh', { deviceIds: [DEVICE_ID] });
      if (r.status !== 200) return;
      const body = (await r.json()) as { results?: Array<{ ok: boolean; results?: Array<{ pluginId: string; reachable: boolean; error?: string }> }> };
      const dev = body.results?.[0];
      const a = dev?.results?.find((x) => x.pluginId === PLUGIN_ID);
      if (a?.reachable) return;
      console.error(`  .. refresh attempt ${attempt}/5 not ok${a?.error ? ` (${a.error})` : ''} — retrying in 10s`);
      await new Promise((res2) => setTimeout(res2, 10_000));
    }
  }

  /** Polls GET /dns until the test name carries all of `expected` (empty list = gone). */
  async function waitForDns(expected: string[], timeoutMs = 90_000): Promise<boolean> {
    const end = Date.now() + timeoutMs;
    let lastRefresh = Date.now();
    for (;;) {
      const r = await authed('GET', `/dns?deviceId=${DEVICE_ID}`);
      if (r.status === 200) {
        const rows = (await r.json()) as Array<{ name: string; ips: string[] }>;
        const row = rows.find((x) => x.name === TEST_NAME);
        const ips = new Set(row?.ips ?? []);
        if (expected.every((ip) => ips.has(ip)) && expected.length > 0) return true;
        // For "gone" checks: the name must be absent entirely.
        if (expected.length === 0 && !row) return true;
      }
      if (Date.now() > end) break;
      if (Date.now() - lastRefresh >= 35_000) {
        lastRefresh = Date.now();
        await refresh(); // LCOS config mirror + TTL cache can lag a CLI write
      }
      await new Promise((res2) => setTimeout(res2, 3_000));
    }
    return false;
  }

  console.log(`\n== LCOS dual v4+v6 intents @ WLC01 (${TEST_NAME}) ==`);

  // --- 0. Precondition: the test name must not exist ---------------------------
  await refresh();
  const pre = (await (await authed('GET', `/dns?deviceId=${DEVICE_ID}`)).json()) as Array<{ name: string; ips: string[] }>;
  if (pre.some((x) => x.name === TEST_NAME)) {
    console.error(`  !! ${TEST_NAME} already exists on WLC01 — cleaning up first`);
    await runAction('dns.delete', { name: TEST_NAME });
    await refresh();
  }

  // --- 1. Dual set (v4 + v6 in ONE row) ----------------------------------------
  const dual = await runAction('dns.set', { name: TEST_NAME, ip: V4_A, ipv6: V6 });
  const dualRes = dual.step ? actionResult(dual.step) : null;
  check('dual dns.set applied + verified (v4+v6 in one row)', dual.planStatus === 'succeeded' && !!dualRes?.success && dualRes.applied === true, { planStatus: dual.planStatus, result: dualRes });

  await refresh();
  check(`GET /dns shows ${TEST_NAME} with BOTH ${V4_A} and ${V6}`, await waitForDns([V4_A, V6]));

  // --- 2. Idempotent re-set (same v4, no ipv6 → sibling preserved ⇒ skip) ------
  const again = await runAction('dns.set', { name: TEST_NAME, ip: V4_A });
  const againRes = again.step ? actionResult(again.step) : null;
  check('re-set of same v4 is an idempotent skip (v6 preserved)', again.planStatus === 'succeeded' && !!againRes?.success && typeof againRes.details?.['skipped'] === 'string', { planStatus: again.planStatus, result: againRes });

  // --- 3. New v4 only — the row's v6 must SURVIVE (merge-aware replace) --------
  const swap = await runAction('dns.set', { name: TEST_NAME, ip: V4_B });
  const swapRes = swap.step ? actionResult(swap.step) : null;
  check(`v4-only re-set applied with v6 preserved (replacedFrom=${V4_A} + ${V6})`, swap.planStatus === 'succeeded' && !!swapRes?.success && swapRes.applied === true, { planStatus: swap.planStatus, result: swapRes });

  await refresh();
  check(`GET /dns shows ${TEST_NAME} with NEW v4 ${V4_B} AND surviving ${V6}`, await waitForDns([V4_B, V6]));

  // --- 4. Family-scoped delete (remove the v4 — the v6 must survive) -----------
  const del = await runAction('dns.delete', { name: TEST_NAME, ip: V4_B });
  const delRes = del.step ? actionResult(del.step) : null;
  check(`family-scoped dns.delete of ${V4_B} applied (kept=${V6})`, del.planStatus === 'succeeded' && !!delRes?.success && delRes.applied === true, { planStatus: del.planStatus, result: delRes });

  await refresh();
  check(`GET /dns shows only the surviving ${V6}`, await waitForDns([V6]));

  // --- 5. Cleanup — whole row gone ----------------------------------------------
  const cleanup = await runAction('dns.delete', { name: TEST_NAME });
  const cleanupRes = cleanup.step ? actionResult(cleanup.step) : null;
  check('cleanup dns.delete (whole row) applied', cleanup.planStatus === 'succeeded' && !!cleanupRes?.success, { planStatus: cleanup.planStatus, result: cleanupRes });

  await refresh();
  check(`${TEST_NAME} gone from GET /dns`, await waitForDns([]));

  pool.end();
  console.log(failures === 0 ? '\nLCOS dual v4+v6 verification OK.' : `\n${failures} check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
