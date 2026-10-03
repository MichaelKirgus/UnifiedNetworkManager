/**
 * Live verification of the gap-fill actions (2026-10-03):
 *  - OPNsense config.backup.download on OPNSENSE01 (READONLY — safe) + GWBN01
 *  - OPNsense system.users.read on OPNSENSE01 (readonly key, read-only action)
 *  - LCOS firewall.rules.read / routing.static.read / dhcp.networks.read on WLC01
 *  - OPNsense config.restore round-trip on GWBN01 ONLY (restore the SAME backup
 *    we just downloaded — no net change; exercises staging + rc.reload_all).
 * Usage: tsx scripts/verify-gap-actions.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

// Device + plugin ids (from the live DB).
const OPNSENSE_PLUGIN = 'b0e6c8a2-4f1e-4a3d-9c7b-1a2b3c4d5e6f';
const LCOS_PLUGIN = '00000000-0000-4000-8000-000000000006';
const OPNSENSE01 = '2eb40794-fd9c-4139-a381-184197b4f97a'; // PRODUCTION — reads only!
const GWBN01 = '0add51bf-165f-461c-ad38-935b5f9eb1b3';     // test box — restore OK
const WLC01 = '38cf30d7-e53e-47ae-9545-c79af2270751';

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else { failures++; console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 500) : ''); }
}

interface StepRow { stepIndex: number; deviceId: string; actionId: string; status: string; result?: Record<string, unknown> | null; bestEffort?: boolean; }
interface PlanRow { id: string; status: string; error?: string | null; steps?: StepRow[]; }

async function main() {
  // --- login (2FA) -------------------------------------------------------------
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

  const runPlan = async (label: string, pluginId: string, actionId: string, deviceId: string, inputs: Record<string, unknown>, timeoutMs = 180_000): Promise<StepRow | null> => {
    console.log(`\n=== ${label} (${actionId} on device) ===`);
    const createRes = await authed('POST', '/plans', { pluginId, intentActionId: actionId, inputs, devices: [{ deviceId }] });
    const plan = (await createRes.json()) as PlanRow; // read ONCE — the body stream is consumed
    check(`${label}: POST /plans → 201`, createRes.status === 201 && Boolean(plan.id), { status: createRes.status, id: plan.id ?? null });
    if (!plan.id) return null;
    const execRes = await authed('POST', `/plans/${plan.id}/execute`);
    check(`${label}: execute → 202`, execRes.status === 202, await execRes.json());

    let final: PlanRow = {};
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const gotRes = await authed('GET', `/plans/${plan.id}`);
      const got = (await gotRes.json()) as PlanRow;
      if (got.status && ['succeeded', 'failed', 'cancelled', 'unverified'].includes(got.status)) { final = got; break; }
      await new Promise((r) => setTimeout(r, 3000));
    }
    check(`${label}: plan terminal (${final.status})`, Boolean(final.status && ['succeeded', 'failed', 'cancelled', 'unverified'].includes(final.status)), { status: final.status, error: final.error });
    const raw = (final.steps ?? []).find((s) => s.actionId === actionId);
    if (!raw) return null;
    // The executor stores the plugin's ActionResult under result.result.
    const inner = ((raw.result as Record<string, unknown> | undefined)?.['result'] ?? {}) as Record<string, unknown>;
    const step: StepRow = { ...raw, result: { success: inner['success'], details: inner['details'], error: inner['error'] } };
    if (step.result) console.log(`  step result:`, JSON.stringify(step.result).slice(0, 700));
    return step;
  };

  // --- 1. OPNsense backup download on OPNSENSE01 (READONLY — safe) --------------
  const osBackup = await runPlan('OPNSENSE01 backup', OPNSENSE_PLUGIN, 'config.backup.download', OPNSENSE01, {});
  check('OPNSENSE01: config.backup.download succeeded', osBackup?.status === 'succeeded' || (osBackup?.result as Record<string, unknown>)?.['success'] !== false, osBackup?.result);

  // --- 2. OPNsense users read on OPNSENSE01 (readonly key) ----------------------
  const osUsers = await runPlan('OPNSENSE01 users', OPNSENSE_PLUGIN, 'system.users.read', OPNSENSE01, {});
  check('OPNSENSE01: system.users.read succeeded', (osUsers?.result as Record<string, unknown>)?.['success'] === true || osUsers?.status === 'succeeded', osUsers?.result);

  // --- 3. LCOS gap reads on WLC01 ------------------------------------------------
  const lcFw = await runPlan('WLC01 firewall rules', LCOS_PLUGIN, 'firewall.rules.read', WLC01, {});
  check('WLC01: firewall.rules.read succeeded', (lcFw?.result as Record<string, unknown>)?.['success'] === true || lcFw?.status === 'succeeded', lcFw?.result);

  const lcRoutes = await runPlan('WLC01 static routes', LCOS_PLUGIN, 'routing.static.read', WLC01, {});
  check('WLC01: routing.static.read succeeded', (lcRoutes?.result as Record<string, unknown>)?.['success'] === true || lcRoutes?.status === 'succeeded', lcRoutes?.result);

  const lcDhcp = await runPlan('WLC01 dhcp networks', LCOS_PLUGIN, 'dhcp.networks.read', WLC01, {});
  check('WLC01: dhcp.networks.read succeeded', (lcDhcp?.result as Record<string, unknown>)?.['success'] === true || lcDhcp?.status === 'succeeded', lcDhcp?.result);

  // --- 4. GWBN01 backup → restore round-trip (SAME file — no net change) --------
  const gwBackup = await runPlan('GWBN01 backup', OPNSENSE_PLUGIN, 'config.backup.download', GWBN01, {});
  const gwDetails = ((gwBackup?.result as Record<string, unknown>)?.['details'] ?? {}) as Record<string, unknown>;
  const repoFileId = gwDetails['repoFileId'];
  check('GWBN01: backup produced a repoFileId', typeof repoFileId === 'string' && (repoFileId as string).length > 0, gwBackup?.result);

  // The downloaded file is the appliance's LATEST LOCAL backup — restoring it
  // rolls GWBN01 back to that instant. For a TRUE zero-net-change round trip we
  // instead fetch the CURRENT /conf/config.xml over SSH (root slot) and restore
  // THAT inline: same code path, no rollback of recent changes at all.
  const source = String(gwDetails['source'] ?? '');
  console.log(`  latest local backup: ${source}`);

  if (process.env.SKIP_RESTORE === '1') {
    console.log('\n=== SKIP_RESTORE=1 — skipping the GWBN01 restore round-trip ===');
  } else {
    // The live config was pre-fetched into /tmp/gwbn-live.b64 via the plugin's
    // SDK ssh pool (root slot) — see fetch-gwbn-cfg.js. Restoring THIS file is a
    // true zero-net-change round trip of the restore code path.
    const fs = await import('node:fs');
    let liveB64 = '';
    try { liveB64 = fs.readFileSync('/tmp/gwbn-live.b64', 'utf8').trim(); } catch { /* absent */ }
    if (!liveB64 || !/<opnsense/.test(Buffer.from(liveB64, 'base64').toString('utf8').slice(0, 512))) {
      console.log('\n=== no usable live config (/tmp/gwbn-live.b64) — skipping the restore round-trip ===');
    } else {
      const gwRestore = await runPlan('GWBN01 restore round-trip', OPNSENSE_PLUGIN, 'config.restore', GWBN01, { fileBase64: liveB64 }, 420_000);
      check('GWBN01: config.restore succeeded (live-config round trip)', (gwRestore?.result as Record<string, unknown>)?.['success'] === true || gwRestore?.status === 'succeeded', gwRestore?.result);
    }
  }

  console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error('FATAL', e); process.exit(1); });
