/**
 * e2e-containers-image-set.ts — live write test of the canonical
 * containers.image.set intent on the DEV DOCKER HOST (socket transport = this
 * machine's own daemon, so a throwaway container is safe):
 *   1. create a throwaway `unm-imgset-e2e` container (alpine:3.19) via docker CLI;
 *   2. plan + execute containers.image.set { name, from: alpine:3.19 → to: alpine:3.20 };
 *      assert the plan SUCCEEDS (verified), details.changed === 1, and the daemon
 *      really shows the container running on the new ref;
 *   3. idempotent re-run with from === to — expect success + applied:false (skipped);
 *   4. cleanup: remove the throwaway container via docker CLI.
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-containers-image-set.ts
 */
import path from 'node:path';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';

// Dev Docker Host — socket transport, left in the DB for testing (writes OK).
const DEVICE_ID = process.env.DEVICE_ID ?? 'e29d1edb-d153-4208-94db-6d359df2e29f';
const PLUGIN_ID = process.env.PLUGIN_ID ?? '00000000-0000-4000-8000-00000000000b';

const NAME = 'unm-imgset-e2e';
const FROM_REF = 'alpine:3.19';
const TO_REF = 'alpine:3.20';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const { Pool } = apiRequire('pg');
// otplib@13 — functional API (no `authenticator` instance).
const { generate: otpGenerate } = apiRequire('otplib') as { generate: (opts: { strategy: string; secret: string }) => Promise<string> };
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

/** Mints a session JWT with amr ['totp'] — plan writes are require2FA-gated and
 * long-lived API tokens (amr ['token']) can never pass. */
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
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 500) : '');
  }
}

interface StepRow { id: string; stepIndex: number; deviceId: string; actionId: string; status: string; result?: Record<string, unknown> | null; }
interface PlanDto { id?: string; status?: string; steps?: StepRow[]; error?: string | null; }

function actionResult(step: StepRow): { success?: boolean; applied?: boolean; verified?: boolean; details?: Record<string, unknown>; error?: string } | null {
  const outer = step.result ?? null;
  if (!outer || typeof outer !== 'object') return null;
  const inner = (outer as Record<string, unknown>)['result'];
  const src: Record<string, unknown> = (inner && typeof inner === 'object' ? inner : outer) as Record<string, unknown>;
  return { success: src['success'] as boolean | undefined, applied: src['applied'] as boolean | undefined, verified: src['verified'] as boolean | undefined, details: src['details'] as Record<string, unknown> | undefined, error: src['error'] as string | undefined };
}

/** docker CLI against the local daemon (the Dev Docker Host's socket). */
function docker(...args: string[]): string {
  return execFileSync('docker', args, { encoding: 'utf8' }).trim();
}

async function main(): Promise<void> {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const token = await mintTotpSessionToken(pool);
  if (!token) throw new Error('could not mint a TOTP session token');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  const TERMINAL = ['succeeded', 'failed', 'cancelled', 'unverified'];
  async function runAction(actionId: string, inputs: Record<string, unknown>, timeoutMs = 600_000): Promise<{ planStatus?: string; step?: StepRow }> {
    const createRes = await authed('POST', '/plans', { pluginId: PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId: DEVICE_ID }] });
    if (createRes.status !== 201) {
      console.error(`  !! plan creation for ${actionId} → ${createRes.status}:`, JSON.stringify(await createRes.json()).slice(0, 400));
      return {};
    }
    const created = (await createRes.json()) as PlanDto;
    const execRes = await authed('POST', `/plans/${created.id}/execute`);
    if (execRes.status !== 202) {
      console.error(`  !! execute for ${actionId} → ${execRes.status}:`, JSON.stringify(await execRes.json()).slice(0, 300));
      return {};
    }
    const deadline = Date.now() + timeoutMs;
    let final: PlanDto = {};
    while (Date.now() < deadline) {
      const r = await authed('GET', `/plans/${created.id}`);
      final = (await r.json()) as PlanDto;
      if (TERMINAL.includes(final.status ?? '')) break;
      await new Promise((res2) => setTimeout(res2, 1000));
    }
    return { planStatus: final.status, step: final.steps?.find((s) => s.actionId === actionId) ?? final.steps?.[final.steps.length - 1] };
  }

  // --- Setup: throwaway container on the local daemon -------------------------
  try { docker('rm', '-f', NAME); } catch { /* not there yet */ }
  console.log(`creating ${NAME} (${FROM_REF})…`);
  docker('run', '-d', '--name', NAME, FROM_REF, 'sleep', '3600');

  // --- 1) tag bump -------------------------------------------------------------
  const r1 = await runAction('containers.image.set', { mappings: [{ name: NAME, from: FROM_REF, to: TO_REF }] });
  check('plan 1 (tag bump) succeeded + verified', r1.planStatus === 'succeeded', r1);
  const a1 = r1.step ? actionResult(r1.step) : null;
  check('step success=true, applied=true, changed=1', a1?.success === true && a1?.applied === true && (a1.details?.['changed'] as number | undefined) === 1, a1);

  // Daemon ground truth: the container must run on the NEW ref under its ORIGINAL name.
  const img = docker('inspect', '--format', '{{.Config.Image}}', NAME).trim();
  const state = docker('inspect', '--format', '{{.State.Status}}', NAME).trim();
  check(`daemon shows ${NAME} running on ${TO_REF}`, state === 'running' && (img === TO_REF || img.startsWith(TO_REF)), { img, state });

  // --- 2) idempotent re-run (from === to) --------------------------------------
  const r2 = await runAction('containers.image.set', { mappings: [{ name: NAME, from: TO_REF, to: TO_REF }] });
  check('plan 2 (idempotent) succeeded', r2.planStatus === 'succeeded', r2);
  const a2 = r2.step ? actionResult(r2.step) : null;
  check('step 2 applied=false + skipped entry', a2?.success === true && a2?.applied !== true && Object.keys((a2.details?.['skipped'] as Record<string, string>) ?? {}).length > 0, a2);

  // --- Cleanup ------------------------------------------------------------------
  try { docker('rm', '-f', NAME); console.log(`cleanup: removed ${NAME}`); } catch (e) { console.error('cleanup failed:', e instanceof Error ? e.message : String(e)); failures++; }

  await pool.end();
  if (failures > 0) throw new Error(`${failures} check(s) failed`);
  console.log('ALL CHECKS PASSED');
}

main().catch((e) => { console.error(e instanceof Error ? e.stack ?? e.message : String(e)); process.exit(1); });
