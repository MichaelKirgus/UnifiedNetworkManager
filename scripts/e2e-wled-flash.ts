/**
 * e2e-wled-flash.ts — LIVE firmware flash of a real WLED device through UNM.
 *
 * The headline end-to-end test: creates a plan (POST /plans, 2FA-gated) for
 * `wled.firmware.update` on the "WLED-Test" device and executes it. The plugin
 * downloads the .bin through UNM's web-fetch broker, uploads it to the device's
 * own /update endpoint, waits for the reboot and verifies the new version.
 *
 * Prereqs: dev stack up, WLED-Test device exists (scripts/e2e-wled.ts creates it),
 * admin TOTP secret in the DB (minted codes via otplib — no browser login).
 *
 *   UNM_TOKEN=unm_...  (optional — when absent the script does the full
 *                       admin+TOTP login flow, which POST /plans requires) \
 *   WLED_ADDRESS=10.40.1.62 \
 *   tsx scripts/e2e-wled-flash.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.UNM_API_URL ?? 'http://localhost:3000/v1';
const TOKEN = process.env.UNM_TOKEN ?? '';
const ADDRESS = process.env.WLED_ADDRESS ?? '10.40.1.62';
const DEVICE_NAME = 'WLED-Test';
const WLED_PLUGIN_UUID = '00000000-0000-4000-8000-000000000016';

// pg + otplib live in api/node_modules — resolve through the API package.
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let passed = 0;
let failed = 0;
function check(label: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    passed++;
    console.log(`  ✅ ${label}`);
  } else {
    failed++;
    console.log(`  ❌ ${label}${detail !== undefined ? ` — ${JSON.stringify(detail).slice(0, 400)}` : ''}`);
  }
}

async function login(): Promise<string> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  try {
    const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
    if (!adminRow.totpSecret) {
      const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
      return ((await r.json()) as { accessToken?: string }).accessToken ?? '';
    }
    // otplib@13 functional API (same style the API itself uses for verifySync).
    const { generateSync } = apiRequire('otplib') as { generateSync: (opts: { strategy: string; secret: string }) => string };
    const code = generateSync({ strategy: 'totp', secret: adminRow.totpSecret });
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    return ((await r2.json()) as { accessToken?: string }).accessToken ?? '';
  } finally {
    await pool.end();
  }
}

async function main(): Promise<void> {
  // POST /plans + execute are 2FA-gated — a plain API token is not enough.
  const token = TOKEN || (await login());
  check('authenticated', Boolean(token));
  if (!token) process.exit(2);

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<any> }> => {
    const res = await fetch(`${API}${p}`, {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // --- Locate the device + its current version -----------------------------------------
  const devices = await authed('GET', '/devices').then((r) => r.json());
  const device = (devices as Array<{ id: string; name: string }>).find((d) => d.name === DEVICE_NAME);
  check(`device ${DEVICE_NAME} exists`, Boolean(device), devices?.length);
  if (!device) process.exit(2);

  let currentVersion = '';
  {
    const mon = await authed('GET', `/devices/${device.id}/monitoring`).then((r) => r.json());
    const snap = (mon.snapshots ?? []).find((s: any) => s.pluginId === WLED_PLUGIN_UUID);
    currentVersion = String(snap?.metrics?.['wled.version'] ?? '');
  }
  check('current version known from telemetry', /^16\.0\.\d+$/.test(currentVersion), currentVersion);

  // --- Read the updates row (the apply path) ---------------------------------------------
  const upd = await authed('GET', `/updates?deviceId=${device.id}&kind=firmware`).then((r) => r.json());
  const rows: Array<Record<string, any>> = upd.rows ?? [];
  check('one firmware update row available', rows.length === 1 && String(rows[0].latestVersion) !== currentVersion, rows.map((r) => ({ c: r.currentVersion, l: r.latestVersion })));
  if (rows.length !== 1 || String(rows[0].latestVersion) === currentVersion) {
    console.log('\nNothing to flash — device already up to date.');
    process.exit(failed === 0 ? 0 : 1);
  }
  const row = rows[0];
  const targetVersion = String(row.latestVersion);
  const applyInput = (row.applyInput ?? {}) as Record<string, string>;
  console.log(`\n  → flashing ${currentVersion} → ${targetVersion} (${applyInput.fileName})`);

  // --- Create the plan -------------------------------------------------------------------
  console.log('\n— POST /plans —');
  const createRes = await authed('POST', '/plans', {
    pluginId: WLED_PLUGIN_UUID,
    intentActionId: 'wled.firmware.update',
    inputs: applyInput,
    devices: [{ deviceId: device.id }],
  });
  const plan = (await createRes.json()) as Record<string, any>;
  check('plan created (201)', createRes.status === 201, { status: createRes.status, body: plan });
  if (!plan.id) process.exit(2);

  // --- Execute ---------------------------------------------------------------------------
  console.log('\n— POST /plans/:id/execute —');
  const execRes = await authed('POST', `/plans/${plan.id}/execute`);
  check('execution enqueued (202)', execRes.status === 202, { status: execRes.status, body: await execRes.json() });

  // --- Wait for the plan to finish ---------------------------------------------------------
  console.log('\n— Waiting for flash + reboot (~1–3 min) —');
  let finalPlan: Record<string, any> | null = null;
  const deadline = Date.now() + 420_000; // download + flash + reboot wait (action budget is 600s)
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 15_000));
    const p = await authed('GET', `/plans/${plan.id}?steps=true`).then((r) => r.json());
    finalPlan = p;
    if (['succeeded', 'failed', 'cancelled'].includes(p.status)) break;
    const steps: Array<{ actionId: string; status: string }> = p.steps ?? [];
    console.log(`  … ${p.status}: ` + steps.map((s) => `${s.actionId.replace('wled.firmware.', '')}=${s.status}`).join(', '));
  }

  check('plan finished', finalPlan !== null && ['succeeded', 'failed'].includes(finalPlan?.status), finalPlan?.status);
  const steps: Array<Record<string, any>> = (finalPlan?.steps ?? []) as Array<Record<string, any>>;
  for (const s of steps) {
    console.log(`  step ${s.stepIndex} ${s.actionId}: ${s.status}${s.result ? ` — ${JSON.stringify(s.result).slice(0, 200)}` : ''}`);
  }
  const flashStep = steps.find((s) => s.actionId === 'wled.firmware.update');
  check('flash step succeeded', flashStep?.status === 'succeeded', flashStep?.result);
  const details = (flashStep?.result?.details ?? {}) as Record<string, any>;
  check(
    `verified ${currentVersion} → ${targetVersion}`,
    String(details.from) === currentVersion && String(details.to) === targetVersion,
    { from: details.from, to: details.to },
  );

  // --- Post-flash telemetry + updates row ---------------------------------------------------
  console.log('\n— Post-flash verification —');
  let postVersion = '';
  const vDeadline = Date.now() + 120_000;
  while (Date.now() < vDeadline) {
    await new Promise((r) => setTimeout(r, 5_000));
    const mon = await authed('GET', `/devices/${device.id}/monitoring`).then((r) => r.json());
    const snap = (mon.snapshots ?? []).find((s: any) => s.pluginId === WLED_PLUGIN_UUID);
    postVersion = String(snap?.metrics?.['wled.version'] ?? '');
    if (postVersion === targetVersion && snap?.health === 'ok') break;
  }
  check(`telemetry now reports ${targetVersion}`, postVersion === targetVersion, postVersion);

  const upd2 = await authed('GET', `/updates?deviceId=${device.id}&kind=firmware`).then((r) => r.json());
  const rows2: Array<Record<string, any>> = upd2.rows ?? [];
  check(
    'updates row cleared (current == latest)',
    rows2.length === 0 || String(rows2[0].latestVersion) === targetVersion,
    rows2.map((r) => ({ c: r.currentVersion, l: r.latestVersion })),
  );

  console.log(`\n${failed === 0 ? '✅' : '❌'} ${passed} passed, ${failed} failed`);
  console.log(`\nDevice ${DEVICE_NAME} (${ADDRESS}): ${currentVersion} → ${postVersion || 'unknown'}`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
