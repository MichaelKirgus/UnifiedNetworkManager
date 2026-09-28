/**
 * E2E check for the lancom-lcos plugin v0.3.0 (SSH/SFTP + CLI transports).
 *
 * Drives REAL actions end-to-end through the live stack against WLC01:
 *   login (2FA) → discover catalog (v0.3.0, new action ids present)
 *   → plan config.backup.download  (SFTP /config read — READ-ONLY on device)
 *   → plan cli.param.read          (`set Time/Timezone ?` — READ-ONLY)
 *   → plan wlan.ssid.state.set     (negative: WLC01 has no WLAN radio, must fail cleanly)
 *
 * NO writes that could make the device unreachable are executed.
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-lcos-v03.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const LCOS_PLUGIN_ID = '00000000-0000-4000-8000-000000000006';
// WLC01.management.kirgus.intra — 10.25.0.20, LANCOM vRouter (no WLAN radio).
const DEVICE_ID = '38cf30d7-e53e-47ae-9545-c79af2270751';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 600) : '');
  }
}

async function main(): Promise<void> {
  // --- auth (login + TOTP from seeded secret) ---------------------------------
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
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
  check('authenticated (2FA flow)', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // --- 1. discovery: v0.3.0 + new catalog ------------------------------------
  let actions: Array<{ id: string; label?: string }> = [];
  let version = '';
  for (let i = 0; i < 45 && !version; i++) {
    const plugins = ((await authed('GET', '/plugins').then((r) => r.json())) as Array<{ id: string; version?: string }>) ?? [];
    const lc = plugins.find((p) => p.id === LCOS_PLUGIN_ID);
    if (lc?.version) {
      version = lc.version;
      actions = (((await authed('GET', `/plugins/${LCOS_PLUGIN_ID}/actions`).then((r) => r.json())) as { actions?: typeof actions })?.actions) ?? [];
    } else await new Promise((r) => setTimeout(r, 1_000));
  }
  check('plugin discovered at v0.3.0', version === '0.3.0', version);
  const expected = ['config.backup.download', 'config.restore', 'cli.param.read', 'system.name.set', 'system.timezone.cli.set', 'wlan.ssid.state.set'];
  for (const id of expected) {
    check(`catalog contains ${id}`, actions.some((a) => a.id === id), actions.map((a) => a.id));
  }

  // --- helper: run one single-device plan step and wait ------------------------
  const runStep = async (actionId: string, inputs: Record<string, unknown>): Promise<{ status: string; details?: Record<string, unknown>; error?: string }> => {
    const created = await authed('POST', '/plans', { pluginId: LCOS_PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId: DEVICE_ID }] });
    const plan = (await created.json()) as { id?: string };
    if (!plan.id) throw new Error(`plan creation failed for ${actionId}: status=${created.status}`);
    await authed('POST', `/plans/${plan.id}/execute`);
    let detail: Record<string, unknown> | null = null;
    for (let i = 0; i < 45; i++) {
      await new Promise((r) => setTimeout(r, 2_000));
      const d = ((await authed('GET', `/plans/${plan.id}`).then((r) => r.json())) as Record<string, unknown>) ?? null;
      if (d && ['succeeded', 'failed', 'cancelled'].includes(String(d.status))) { detail = d; break; }
    }
    // Step result shape: { success, result: <ActionResult {success, details|error}> }.
    // NOTE: write intents get a best-effort config.backup.download step PREPENDED —
    // pick the step whose actionId matches the requested intent.
    const steps = (detail?.steps ?? []) as Array<{ actionId?: string; status?: string; result?: { success?: boolean; result?: { success?: boolean; details?: Record<string, unknown>; error?: string } | null } | null }>;
    const step = steps.find((s) => s.actionId === actionId) ?? steps[steps.length - 1] ?? {};
    return { status: String(detail?.status), details: step.result?.result?.details, error: step.result?.result?.error };
  };

  // --- 2. config.backup.download (SFTP /config — read-only) --------------------
  console.log('\n[1] config.backup.download on WLC01');
  const backup = await runStep('config.backup.download', {});
  check('backup plan succeeded', backup.status === 'succeeded', { status: backup.status, error: backup.error });
  const repoFileId = String(backup.details?.repoFileId ?? '');
  check('backup returned a repo file id', Boolean(repoFileId), backup.details);
  const sizeBytes = Number(backup.details?.sizeBytes ?? 0);
  check('backup is a plausible LCF size (>50 KB)', sizeBytes > 50_000, { sizeBytes });

  if (repoFileId) {
    // GET /files/:id streams the raw bytes — sanity-check it is an LCF document.
    const contentRes = await fetch(`${API}/files/${encodeURIComponent(repoFileId)}`, { headers: { Authorization: `Bearer ${token}` } });
    if (contentRes.status === 200) {
      const text = Buffer.from(await contentRes.arrayBuffer()).toString('utf8');
      check('stored file is an LCF document', /\[TYPE:\s*LCF/i.test(text) && /\[END:\s*LCF\s*;?\]/i.test(text), `bytes=${text.length}`);
    } else {
      check('stored file content fetchable', false, { status: contentRes.status });
    }
  }

  // --- 3. cli.param.read (set Time/Timezone ? — read-only) ----------------------
  console.log('\n[2] cli.param.read on WLC01');
  const param = await runStep('cli.param.read', { dir: 'Setup/Time', name: 'Timezone' });
  check('param-read plan succeeded', param.status === 'succeeded', { status: param.status, error: param.error });
  const out = String(param.details?.output ?? '');
  check('param output mentions Timezone input set', /Timezone/i.test(out) && /(e0|eplus|eminus|\(0\)|Yes)/i.test(out), out.slice(0, 300));

  // --- 4. wlan.ssid.state.set (negative — WLC01 has no radio) -------------------
  console.log('\n[3] wlan.ssid.state.set negative test on WLC01 (no WLAN radio)');
  const wlan = await runStep('wlan.ssid.state.set', { ifc: 'WLAN-1', enabled: true });
  check('wlan step failed cleanly (expected — no radio)', wlan.status === 'failed' || Boolean(wlan.error), { status: wlan.status, error: wlan.error });
  check('failure mentions path/radio', /Path name wrong|no WLAN radio/i.test(String(wlan.error ?? '')), wlan.error);

  // --- summary ------------------------------------------------------------------
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('E2E crashed:', e);
  process.exit(1);
});
