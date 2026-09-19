/**
 * E2E check for the OPNsense firmware actions: proves the plan workflow can
 * dispatch a single-device action from the persisted catalog by running the
 * READ-ONLY `firmware.status.read` against a real device and asserting the
 * step result carries live firmware status details.
 *
 * Usage (from repo root):
 *   ./node_modules/.bin/tsx scripts/e2e-firmware-status.ts [deviceName]
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 500) : '');
  }
}

interface StepRow {
  id: string; stepIndex: number; actionId: string; status: string;
  result?: Record<string, unknown> | null;
}

async function main(): Promise<void> {
  const deviceName = process.argv[2] ?? 'OPNSENSE01';

  // --- Login (admin/admin; TOTP from seeded secret when enabled) -------------
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const devRow = (await pool.query(`SELECT id FROM devices WHERE name = $1`, [deviceName])).rows[0] as { id: string } | undefined;
  if (!devRow) throw new Error(`no device named ${deviceName}`);

  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
  await pool.end();

  let token: string | null = null;
  if (!adminRow?.totpSecret) {
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
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // --- Find the OPNsense plugin ------------------------------------------------
  const plugins = ((await authed('GET', '/plugins').then((r) => r.json())) as Array<{ id: string; name: string }>) ?? [];
  const op = plugins.find((p) => /opnsense/i.test(p.name));
  check('OPNsense plugin found', Boolean(op), plugins.map((p) => p.name));
  if (!op) throw new Error('no OPNsense plugin');

  // --- Create plan: single-device fan-out of firmware.status.read -------------
  const createRes = await authed('POST', '/plans', {
    pluginId: op.id,
    intentActionId: 'firmware.status.read',
    inputs: {},
    devices: [{ deviceId: devRow.id }],
  });
  const plan = (await createRes.json()) as { id?: string; status?: string; steps?: StepRow[] };
  check('POST /plans (firmware.status.read) → 201', createRes.status === 201, plan);
  const planId = plan.id ?? '';
  check('plan ready with exactly one step', plan.status === 'ready' && (plan.steps?.length ?? 0) === 1, plan);

  // --- Execute + poll to completion --------------------------------------------
  const execRes = await authed('POST', `/plans/${planId}/execute`);
  check('POST /plans/:id/execute → 2xx', execRes.status >= 200 && execRes.status < 300, await execRes.json());

  let final: { status?: string; error?: string | null; steps?: StepRow[] } = {};
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const r = await authed('GET', `/plans/${planId}`);
    final = (await r.json()) as typeof final;
    if (['succeeded', 'failed', 'cancelled'].includes(final.status ?? '')) break;
    await new Promise((res2) => setTimeout(res2, 500));
  }
  check('plan succeeded', final.status === 'succeeded', { status: final.status, error: final.error });

  const step = (final.steps ?? [])[0];
  check('step firmware.status.read succeeded', step?.actionId === 'firmware.status.read' && step?.status === 'succeeded', step);

  // plan_steps.result stores { success, result: ActionResult } — details one level deeper.
  const inner = (step?.result?.['result'] ?? {}) as { success?: boolean; details?: Record<string, unknown> };
  check('action reported success', inner.success === true, inner);
  const d = inner.details ?? {};
  // The action normalizes the appliance payload to camelCase (see firmware.ts).
  check('details carry productVersion', typeof d.productVersion === 'string' && String(d.productVersion).length > 0, { productVersion: d.productVersion });
  check('details carry packages array', Array.isArray(d.packages), { count: (d.packages as unknown[])?.length });

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((err) => { console.error('ERROR', err.message ?? err); process.exit(1); });
