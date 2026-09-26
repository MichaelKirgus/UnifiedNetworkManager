/**
 * Live end-to-end verification that config backups land in UNM's central file
 * repository (the plugin → API broker → file-repo-plugin path):
 *   1. logs in via the real auth flow (TOTP minted from the seeded admin secret)
 *   2. creates a plan with intent `config.backup.download` for KIRGUSBANDE
 *      (read-only on the appliance — config.save just produces a backup file)
 *   3. executes it and waits for completion
 *   4. asserts the step result carries details.repoFileId + a convention name
 *      (<device>__config-backup-<UTC-ts>.db)
 *   5. asserts the repo_files row exists with providerId = file-repo plugin
 *   6. downloads it through GET /files/:id and checks size/sha match
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/verify-backup-to-repo.ts [deviceId]
 */

import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const TRUENAS_PLUGIN_UUID = '00000000-0000-4000-8000-000000000009';
const FILE_REPO_PLUGIN_UUID = '00000000-0000-4000-8000-000000000011';
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

/** Verifies one repo file end-to-end (row, provider, download round-trip, listing). */
async function verifyRepoFile(
  pool: import('pg').Pool,
  authed: (method: string, p: string, body?: unknown) => Promise<Response>,
  devName: string,
  repoFileId: string
): Promise<void> {
  // --- Repo row: provider + metadata ------------------------------------------
  const row = (await pool.query(`SELECT name, "providerId", "uploadedBy", category, "sizeBytes", sha256 FROM repo_files WHERE id = $1`, [repoFileId])).rows[0] as Record<string, unknown> | undefined;
  check('repo_files row exists', Boolean(row), { repoFileId });
  if (!row) return;
  const expectedName = new RegExp(`^${devName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}__config-backup-\\d{8}-\\d{6}\\.[a-z0-9]+$`);
  check('stored file name follows the shared convention', expectedName.test(String(row.name ?? '')), row.name);
  check('bytes stored in the file-repo PLUGIN (not api-local)', row.providerId === FILE_REPO_PLUGIN_UUID, row.providerId);
  check('category is config-backup', row.category === 'config-backup', row.category);
  check('uploadedBy is null (plugin upload)', row.uploadedBy === null, row.uploadedBy);

  // --- Download through the public API and compare ---------------------------
  const dl = await authed('GET', `/files/${encodeURIComponent(repoFileId)}`);
  check('download via GET /files/:id → 200', dl.status === 200, dl.status);
  if (dl.status === 200) {
    const buf = Buffer.from(await dl.arrayBuffer());
    check('downloaded bytes match repo sizeBytes', buf.length === Number(row.sizeBytes), { got: buf.length, want: row.sizeBytes });
    const sha = createHash('sha256').update(buf).digest('hex');
    check('downloaded sha256 matches the stored one', sha === String(row.sha256), { sha });
  }

  // --- It shows up on the Files page listing ---------------------------------
  const list = (await (await authed('GET', '/files')).json()) as { files: Array<{ id: string; name: string; category: string }> };
  check('appears in GET /files listing', list.files.some((f) => f.id === repoFileId), list.files.slice(0, 3));
}

async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  // --- Login (admin/admin; TOTP when enabled) ---------------------------------
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
  let token: string | null = null;
  if (!adminRow.totpSecret) {
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
  check('authenticated', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<Response> =>
    fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });

  // --- Pick the target device ---------------------------------------------------
  const deviceId = process.argv[2] ?? (await pool.query(`SELECT id FROM devices WHERE name = 'KIRGUSBANDE' LIMIT 1`)).rows[0]?.id as string | undefined;
  if (!deviceId) throw new Error('No KIRGUSBANDE device found — pass a deviceId as the first argument');
  const devName = (await pool.query(`SELECT name FROM devices WHERE id = $1`, [deviceId])).rows[0]?.name as string;
  console.log(`\nTarget device: ${devName} (${deviceId})`);

  // --- Verify an EXISTING repo file directly (REPO_FILE_ID env) ------------------
  if (process.env.REPO_FILE_ID) {
    await verifyRepoFile(pool, authed, devName, process.env.REPO_FILE_ID);
    await pool.end();
    console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
    process.exit(failures === 0 ? 0 : 1);
  }

  // --- Create + execute a read-only backup plan ---------------------------------
  const createRes = await authed('POST', '/plans', { pluginId: TRUENAS_PLUGIN_UUID, intentActionId: 'config.backup.download', inputs: {}, devices: [{ deviceId }] });
  const plan = (await createRes.json().catch(() => null)) as { id?: string; status?: string } | null;
  check('plan created (201)', createRes.status === 201, plan);
  if (!plan?.id) throw new Error('no plan id');

  const execRes = await authed('POST', `/plans/${plan.id}/execute`);
  const execBody = (await execRes.json().catch(() => null)) as unknown;
  check('plan execution enqueued (202)', execRes.status === 202, execBody);

  // Poll until the plan settles.
  let final: { status?: string; steps?: Array<{ actionId: string; status: string; result?: Record<string, unknown> | null }> } = {};
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 2_000));
    const r = await authed('GET', `/plans/${plan.id}`);
    final = (await r.json()) as typeof final;
    if (final.status && !['executing', 'running'].includes(final.status)) break;
  }
  check('plan finished successfully', final.status === 'succeeded' || final.status === 'completed', { status: final.status });

  const step = (final.steps ?? []).find((s) => s.actionId === 'config.backup.download');
  check('backup step present + succeeded', Boolean(step) && step!.status === 'succeeded', step?.status);
  // The stored result is {success, result:{success, verified, details}} — unwrap both nestings.
  const raw = step?.result as Record<string, unknown> | null;
  const inner = (raw?.result ?? raw) as Record<string, unknown> | undefined;
  const details = ((inner?.details ?? {}) as Record<string, unknown>);
  console.log('\nStep details:', JSON.stringify(details).slice(0, 400));

  check('details carry repoFileId', typeof details.repoFileId === 'string' && (details.repoFileId as string).length > 0, details);
  const expectedName = new RegExp(`^${devName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}__config-backup-\\d{8}-\\d{6}\\.db$`);
  check('file name follows the shared convention', expectedName.test(String(details.fileName ?? '')), details.fileName);

  const repoFileId = String(details.repoFileId ?? '');
  if (repoFileId) {
    await verifyRepoFile(pool, authed, devName, repoFileId);
  }

  await pool.end();
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
