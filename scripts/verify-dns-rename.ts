/**
 * verify-dns-rename.ts — LIVE verification of the canonical dns.rename intent
 * on WLC01 (the safe test vRouter, 10.25.0.20):
 *   1. dns.set creates a fresh entry (v4).
 *   2. dns.rename moves it to a new name — GET /dns must show the address under
 *     the NEW name and NOTHING under the old one.
 *   3. Idempotency: renaming an already-absent old name is a clean skip.
 *   4. Cleanup: dns.delete removes the renamed entry; gone from GET /dns.
 *
 * Addresses are RFC 5737 documentation ranges — they never collide with real
 * fleet entries, and WLC01 is a test device (writes OK). Every write has its
 * cleanup counterpart; on success the device ends in its pre-test state.
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/verify-dns-rename.ts
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';

// WLC01 — LCOS vRouter test device (writes OK).
const DEVICE_ID = process.env.LCOS_DEVICE_ID ?? '38cf30d7-e53e-47ae-9545-c79af2270751';
const PLUGIN_ID = process.env.LCOS_PLUGIN_ID ?? '00000000-0000-4000-8000-000000000006';

// Distinct test names — never collide with real fleet entries.
const OLD_NAME = 'unm-dns-rn';
const NEW_NAME = 'unm-dns-rn2';
const TEST_IP = '192.0.2.88'; // RFC 5737 documentation range

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

  /** Polls GET /dns until the expected name→ip state holds (re-refreshes while waiting). */
  async function waitForDns(present: Array<{ name: string; ip?: string }>, absentNames: string[], timeoutMs = 90_000): Promise<boolean> {
    const end = Date.now() + timeoutMs;
    let lastRefresh = Date.now();
    for (;;) {
      const r = await authed('GET', `/dns?deviceId=${DEVICE_ID}`);
      if (r.status === 200) {
        const rows = (await r.json()) as Array<{ name: string; ips: string[] }>;
        let ok = true;
        for (const p of present) {
          const row = rows.find((x) => x.name === p.name);
          if (!row || (p.ip && !row.ips.includes(p.ip))) { ok = false; break; }
        }
        if (ok) for (const n of absentNames) {
          if (rows.some((x) => x.name === n)) { ok = false; break; }
        }
        if (ok) return true;
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

  console.log(`\n== dns.rename @ WLC01 (${OLD_NAME} → ${NEW_NAME}) ==`);

  // --- 0. Precondition: clean slate ---------------------------------------------
  await refresh();
  const pre = (await (await authed('GET', `/dns?deviceId=${DEVICE_ID}`)).json()) as Array<{ name: string; ips: string[] }>;
  for (const n of [OLD_NAME, NEW_NAME]) {
    if (pre.some((x) => x.name === n)) {
      console.error(`  !! ${n} already exists on WLC01 — cleaning up first`);
      await runAction('dns.delete', { name: n });
      await refresh();
    }
  }

  // --- 1. Create the entry -------------------------------------------------------
  const set = await runAction('dns.set', { name: OLD_NAME, ip: TEST_IP });
  const setResult = set.step ? actionResult(set.step) : null;
  check('dns.set applied + verified (setup)', set.planStatus === 'succeeded' && !!setResult?.success, { planStatus: set.planStatus, result: setResult });

  await refresh();
  check(`GET /dns shows ${OLD_NAME} → ${TEST_IP}`, await waitForDns([{ name: OLD_NAME, ip: TEST_IP }], []));

  // --- 2. RENAME ------------------------------------------------------------------
  const ren = await runAction('dns.rename', { name: OLD_NAME, newName: NEW_NAME });
  const renResult = ren.step ? actionResult(ren.step) : null;
  check(`dns.rename applied + verified (${OLD_NAME} → ${NEW_NAME})`, ren.planStatus === 'succeeded' && !!renResult?.success && renResult.applied === true, { planStatus: ren.planStatus, result: renResult });

  await refresh();
  check(`GET /dns shows ${NEW_NAME} → ${TEST_IP} and NOTHING under ${OLD_NAME}`, await waitForDns([{ name: NEW_NAME, ip: TEST_IP }], [OLD_NAME]));

  // --- 3. Idempotency — the old name is gone now; renaming it again must skip ----
  const again = await runAction('dns.rename', { name: OLD_NAME, newName: NEW_NAME });
  const againResult = again.step ? actionResult(again.step) : null;
  check('re-rename of absent old name is an idempotent skip', again.planStatus === 'succeeded' && !!againResult?.success && typeof againResult.details?.['skipped'] === 'string', { planStatus: again.planStatus, result: againResult });

  // --- 4. Cleanup ------------------------------------------------------------------
  const del = await runAction('dns.delete', { name: NEW_NAME });
  const delResult = del.step ? actionResult(del.step) : null;
  check(`cleanup dns.delete of ${NEW_NAME} applied`, del.planStatus === 'succeeded' && !!delResult?.success, { planStatus: del.planStatus, result: delResult });

  await refresh();
  check(`${NEW_NAME} gone from GET /dns`, await waitForDns([], [NEW_NAME]));

  pool.end();
  console.log(failures === 0 ? '\ndns.rename verification OK.' : `\n${failures} check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
