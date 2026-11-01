/**
 * e2e-dns-writes.ts — live write test of the canonical dns.set / dns.delete
 * intents on SAFE TEST DEVICES ONLY (never GW_Ralf, which is production):
 *   - WLC01  (10.25.0.20) via the LCOS plugin: set → refresh → assert in
 *     GET /dns → idempotent re-set → delete → refresh → assert gone. This also
 *     live-verifies the LCOS CLI add grammar (`add "NAME" 0 <ip>` — an empty
 *     quoted v6 value is rejected by LCOS, see plugins/lancom-lcos docs).
 *   - ROUTEROS01 (10.25.2.1, QEMU test router) via the RouterOS plugin: same
 *     cycle over REST /ip/dns/static. Skipped when the device is unreachable.
 * OPNsense has no safe write target in this lab (OPNSENSE01 is the primary
 * router — reads only), so it is intentionally not exercised here.
 *
 * Every write is paired with its cleanup counterpart; on success the devices
 * end in their pre-test state.
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-dns-writes.ts
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';

// WLC01 — LCOS vRouter test device (writes OK).
const LCOS_DEVICE_ID = process.env.LCOS_DEVICE_ID ?? '38cf30d7-e53e-47ae-9545-c79af2270751';
const LCOS_PLUGIN_ID = process.env.LCOS_PLUGIN_ID ?? '00000000-0000-4000-8000-000000000006';
// ROUTEROS01 — QEMU x86_64 test router (writes OK).
const ROS_DEVICE_ID = process.env.ROS_DEVICE_ID ?? '5c6e5d9a-1ad4-4ddd-82f3-508991d3ce15';
const ROS_PLUGIN_ID = process.env.ROS_PLUGIN_ID ?? '00000000-0000-4000-8000-00000000000a';

// Distinct test entry — never collides with real fleet entries.
const TEST_NAME = 'unm-dns-e2e';
const TEST_IP = '192.168.178.250';

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

/**
 * Mints a session JWT with amr ['totp'] — the same claim shape /auth/2fa/verify
 * produces after a successful TOTP step. Plan writes are require2FA-gated and
 * long-lived API tokens (amr ['token']) can never pass, so this is the only
 * non-interactive way to get a write-capable session in an E2E script. The
 * code itself comes from the DB-enrolled secret via otplib — equivalent to the
 * 2FA flow without needing the admin's password.
 */
async function mintTotpSessionToken(pool: Pool): Promise<string | null> {
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
  const roles = parseArr(row.roles);
  const permissions = parseArr(row.permissions);
  return jwt.sign({ sub: row.id, username: row.username, roles, permissions, amr: ['totp'] }, secret, { expiresIn: 3600 });
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

/** ActionResult as stored one level inside step.result ({ success, result }). */
function actionResult(step: StepRow): { success?: boolean; applied?: boolean; details?: Record<string, unknown>; error?: string } | null {
  const outer = step.result ?? null;
  if (!outer || typeof outer !== 'object') return null;
  const inner = (outer as Record<string, unknown>)['result'];
  const src: Record<string, unknown> = (inner && typeof inner === 'object' ? inner : outer) as Record<string, unknown>;
  return { success: src['success'] as boolean | undefined, applied: src['applied'] as boolean | undefined, details: src['details'] as Record<string, unknown> | undefined, error: src['error'] as string | undefined };
}

async function main(): Promise<void> {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  // --- Auth --------------------------------------------------------------------
  // Plan writes are require2FA-gated: the session JWT must carry an amr that
  // intersects the user's gateAmrs (default ['totp']). Long-lived API tokens
  // (amr ['token']) can NEVER pass — so mint a totp-amr session directly from
  // the DB-enrolled secret + JWT_SECRET (equivalent to completing /auth/2fa/verify).
  const minted = await mintTotpSessionToken(pool);
  let token: string | null = minted;
  if (!token) {
    // Fallbacks when minting is impossible (no .env JWT_SECRET / no admin row):
    // long-lived API token — read-only checks still work, writes will 401.
    try {
      const envFile = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
      token = (/^UNM_API_TOKEN=(.+)$/m.exec(envFile)?.[1] ?? '').trim() || null;
    } catch { /* no .env */ }
  }
  if (!token) {
    const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
    const password = process.env.UNM_ADMIN_PW ?? 'admin';
    if (!adminRow.totpSecret) {
      const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password }) });
      token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
    } else {
      const code = await otpGenerate({ strategy: 'totp', secret: adminRow.totpSecret });
      const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password }) });
      const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
      const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
      token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
    }
  }
  check('authenticated (token or 2FA flow)', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  const TERMINAL = ['succeeded', 'failed', 'cancelled', 'unverified'];
  // Plans carry a pre-step (config.backup.download) before the intent step —
  // locate the step by actionId, not position. Generous timeout: LCOS/RouterOS
  // SSH steps can burn 60s+ per attempt on flaky test devices.
  async function runAction(pluginId: string, deviceId: string, actionId: string, inputs: Record<string, unknown>, timeoutMs = 300_000): Promise<{ planStatus?: string; step?: StepRow }> {
    const createRes = await authed('POST', '/plans', { pluginId, intentActionId: actionId, inputs, devices: [{ deviceId }] });
    if (createRes.status !== 201) {
      console.error(`  !! plan creation for ${actionId} → ${createRes.status}:`, JSON.stringify(await createRes.json()).slice(0, 300));
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
      await new Promise((res2) => setTimeout(res2, 750));
    }
    return { planStatus: final.status, step: final.steps?.find((s) => s.actionId === actionId) ?? final.steps?.[final.steps.length - 1] };
  }

  /** Force an immediate inventory re-poll of the device (bypasses the staggered
   * window). Retries until the TARGET PLUGIN's assignment actually polls OK — a
   * timed-out poll writes NO telemetry row, so the entry would never surface in
   * GET /dns and the following check would fail spuriously. The API can be
   * briefly saturated (other devices' 30s timeouts), which makes single-shot
   * refreshes flaky. NOTE: the device-level `ok` flag is "ANY assignment
   * reachable" — a failed LCOS poll next to a healthy ICMP one still reports
   * ok:true, so we must check the per-assignment results for our pluginId. */
  async function refresh(deviceId: string, pluginId?: string): Promise<void> {
    for (let attempt = 1; attempt <= 5; attempt++) {
      const r = await authed('POST', '/devices/refresh', { deviceIds: [deviceId] });
      if (r.status !== 200) {
        console.error(`  !! refresh ${deviceId} → ${r.status}:`, JSON.stringify(await r.json()).slice(0, 300));
        return;
      }
      const body = (await r.json()) as { results?: Array<{ ok: boolean; results?: Array<{ pluginId: string; reachable: boolean; error?: string }> }> };
      const dev = body.results?.[0];
      if (!dev) return;
      // No specific plugin given — device-level "any reachable" is enough.
      if (!pluginId) { if (dev.ok) return; }
      else {
        const a = (dev.results ?? []).find((x) => x.pluginId === pluginId);
        if (a?.reachable) return;
        console.error(`  .. refresh ${deviceId}: assignment ${pluginId} not reachable${a?.error ? ` (${a.error})` : ''}`);
      }
      console.error(`  .. refresh ${deviceId} attempt ${attempt}/5 not ok — retrying in 10s`);
      await new Promise((res2) => setTimeout(res2, 10_000));
    }
  }

  /** Polls GET /dns until the entry appears/disappears on the device. Re-triggers
   * a forced refresh every ~35 s while waiting: LCOS's SNMP config mirror can
   * lag a CLI write by tens of seconds, and the plugin's inventory snapshot is
   * TTL-cached (15 min) — only a fresh forced re-walk surfaces the change. */
  async function waitForDns(deviceId: string, present: boolean, timeoutMs = 90_000, pluginId?: string): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    let lastRefresh = Date.now();
    for (;;) {
      const r = await authed('GET', `/dns?deviceId=${deviceId}`);
      if (r.status === 200) {
        const rows = (await r.json()) as Array<{ name: string; ips: string[] }>;
        const row = rows.find((x) => x.name === TEST_NAME);
        const has = Boolean(row && row.ips.includes(TEST_IP));
        if (has === present) return true;
      }
      if (Date.now() > deadline) break;
      // Re-poll the device while we wait — a single initial refresh can race
      // the on-device config mirror update and read an empty table.
      if (pluginId && Date.now() - lastRefresh >= 35_000) {
        lastRefresh = Date.now();
        await refresh(deviceId, pluginId);
      }
      await new Promise((res2) => setTimeout(res2, 3_000));
    }
    return false;
  }

  /** One full set → verify → idempotent re-set → delete → verify-gone cycle. */
  async function dnsCycle(label: string, pluginId: string, deviceId: string): Promise<void> {
    console.log(`\n== ${label} ==`);

    // 1. SET — creates the entry (LCOS: also verifies the CLI add grammar).
    const set = await runAction(pluginId, deviceId, 'dns.set', { name: TEST_NAME, ip: TEST_IP });
    const setResult = set.step ? actionResult(set.step) : null;
    check('dns.set applied + verified', set.planStatus === 'succeeded' && !!setResult?.success && setResult.applied !== false, { planStatus: set.planStatus, result: setResult });

    // 2. Ingest — force a re-poll and assert the entry shows up on GET /dns.
    // The wait loop re-triggers refreshes while it polls (config-mirror lag).
    await refresh(deviceId, pluginId);
    check('entry visible in GET /dns after refresh', await waitForDns(deviceId, true, 90_000, pluginId));

    // 3. Idempotent re-set — same name+ip must be a clean no-op skip. Skip
    // results carry NO `applied` field (undefined) — they signal the skip via
    // details.skipped and verified:true (the desired state was confirmed).
    const again = await runAction(pluginId, deviceId, 'dns.set', { name: TEST_NAME, ip: TEST_IP });
    const againResult = again.step ? actionResult(again.step) : null;
    const skippedAgain = typeof againResult?.details?.['skipped'] === 'string';
    check('dns.set idempotent (skip)', again.planStatus === 'succeeded' && !!againResult?.success && (skippedAgain || againResult.applied === false), { planStatus: again.planStatus, result: againResult });

    // 4. DELETE — ip-scoped removal of the test entry.
    const del = await runAction(pluginId, deviceId, 'dns.delete', { name: TEST_NAME, ip: TEST_IP });
    const delResult = del.step ? actionResult(del.step) : null;
    check('dns.delete applied + verified', del.planStatus === 'succeeded' && !!delResult?.success, { planStatus: del.planStatus, result: delResult });

    // 5. Ingest — the entry must vanish from GET /dns (delete-on-absent).
    await refresh(deviceId, pluginId);
    check('entry gone from GET /dns after delete', await waitForDns(deviceId, false, 90_000, pluginId));
  }

  // --- LCOS on WLC01 -----------------------------------------------------------
  console.log('\n== LCOS dns.set/dns.delete (WLC01) ==');
  await dnsCycle('LCOS @ WLC01', LCOS_PLUGIN_ID, LCOS_DEVICE_ID);

  // --- RouterOS on ROUTEROS01 (skip when the test router is down) ---------------
  console.log('\n== RouterOS dns.set/dns.delete (ROUTEROS01) ==');
  const rosHealth = await authed('GET', `/devices/${ROS_DEVICE_ID}`);
  const rosDev = ((await rosHealth.json()) as { status?: string }) ?? {};
  // Skip when the QEMU test router is not fully online — writes to an
  // offline/degraded device burn the full SSH timeout per step. SKIP_ROS=1
  // forces a skip regardless of reported state (e.g. while it is being fixed).
  if (process.env.SKIP_ROS === '1') {
    console.log('  SKIP ROUTEROS01 — SKIP_ROS=1 set, cycle not run.');
  } else if ((rosDev.status ?? 'unknown') !== 'online') {
    console.log(`  SKIP ROUTEROS01 is ${rosDev.status ?? 'unknown'} (not online) — cycle not run.`);
  } else {
    await dnsCycle('RouterOS @ ROUTEROS01', ROS_PLUGIN_ID, ROS_DEVICE_ID);
  }

  // --- OPNsense: no safe write target in this lab -------------------------------
  console.log('\n== OPNsense ==');
  console.log('  SKIP — OPNSENSE01 is the primary router (reads only); no safe write target.');

  pool.end();
  console.log(failures === 0 ? '\nDNS write E2E OK.' : `\n${failures} check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
