/**
 * Runs a packages.update plan step against one device — the exact dispatch path
 * of the Updates page "Update all" button (POST /plans with intentActionId
 * `packages.update`, then execute + poll to completion).
 *
 * Usage (from repo root):
 *   ./node_modules/.bin/tsx scripts/run-package-update.ts <deviceName> [package]
 *   (omit package = upgrade ALL upgradable packages)
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

interface StepRow { id: string; stepIndex: number; actionId: string; status: string; result?: Record<string, unknown> | null; }

async function main(): Promise<void> {
  const deviceName = process.argv[2];
  const pkg = (process.argv[3] ?? '').trim();
  if (!deviceName) throw new Error('usage: run-package-update.ts <deviceName> [package]');

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

  // --- Find the generic-ssh plugin -------------------------------------------
  const plugins = ((await authed('GET', '/plugins').then((r) => r.json())) as Array<{ id: string; name: string }>) ?? [];
  const op = plugins.find((p) => /generic.*ssh/i.test(p.name));
  if (!op) throw new Error(`no generic-ssh plugin found (have: ${plugins.map((p) => p.name).join(', ')})`);

  // --- Create + execute the plan ----------------------------------------------
  const createRes = await authed('POST', '/plans', {
    pluginId: op.id,
    intentActionId: 'packages.update',
    inputs: pkg ? { package: pkg } : {},
    devices: [{ deviceId: devRow.id }],
  });
  const plan = (await createRes.json()) as { id?: string; status?: string };
  if (createRes.status !== 201 || !plan.id) throw new Error(`POST /plans → ${createRes.status}: ${JSON.stringify(plan).slice(0, 400)}`);
  console.log(`plan ${plan.id} created (${pkg ? `package=${pkg}` : 'ALL packages'}) — executing…`);

  const execRes = await authed('POST', `/plans/${plan.id}/execute`);
  if (execRes.status < 200 || execRes.status >= 300) throw new Error(`execute → ${execRes.status}: ${JSON.stringify(await execRes.json()).slice(0, 400)}`);

  // --- Poll to completion (full OS upgrades can take many minutes) ------------
  const deadline = Date.now() + 15 * 60_000;
  let lastLog = '';
  for (;;) {
    if (Date.now() > deadline) throw new Error('still running after 15 min — giving up on polling');
    const r = await authed('GET', `/plans/${plan.id}`);
    const final = (await r.json()) as { status?: string; error?: string | null; steps?: StepRow[] };
    // 'unverified' is a legitimate terminal state: the action applied, but the
    // post-upgrade re-query still listed upgradable packages (common on live
    // hosts whose own apt activity refreshes lists mid-run). Treat it as done.
    if (['succeeded', 'failed', 'cancelled', 'unverified'].includes(final.status ?? '')) {
      const step = (final.steps ?? [])[0];
      const inner = (step?.result?.['result'] ?? {}) as Record<string, unknown>;
      console.log(`\nplan ${final.status}${final.error ? ` — ${final.error}` : ''}`);
      if (inner) console.log('step result:', JSON.stringify(inner).slice(0, 600));
      process.exitCode = ['succeeded', 'unverified'].includes(final.status ?? '') ? 0 : 1;
      return;
    }
    const now = new Date().toISOString().slice(11, 19);
    if (now !== lastLog) { console.log(`… ${final.status} (${Math.round((Date.now() - deadline) / -60_000)} min left)`); lastLog = now; }
    await new Promise((res2) => setTimeout(res2, 5_000));
  }
}

main().catch((err) => { console.error('ERROR', err.message ?? err); process.exit(1); });
