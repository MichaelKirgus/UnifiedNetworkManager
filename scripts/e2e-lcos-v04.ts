/**
 * E2E check for the lancom-lcos plugin v0.4.0 (WiFi parity round 1).
 *
 * Drives REAL actions end-to-end through the live stack:
 *   discovery (v0.4.0, new action ids present, wlan.ssid.state.set removed)
 *   → GW_Ralf (production, dual radio): wlan.networks.read + wlan.radios.read  [SNMP reads — safe]
 *   → WLC01 (test, no radio): wlan.radio.channel.set negative test             [must fail cleanly]
 *   → GW_Ralf: config.backup.download soft check                               [documents the empty-/config finding]
 *
 * NO WiFi writes are executed on GW_Ralf. The only write-path exercise is the
 * expected-FAIL channel set on the radio-less test device.
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/e2e-lcos-v04.ts
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const LCOS_PLUGIN_ID = '00000000-0000-4000-8000-000000000006';
// GW_Ralf — 10.28.0.1, LANCOM 1803VAW-5G (dual-radio WiFi, PRODUCTION).
const DEVICE_GW = 'fb2f6114-f169-4ca0-b145-f741fec55f11';
// WLC01 — 10.25.0.20, LANCOM vRouter (no WLAN radio, TEST device).
const DEVICE_WLC = '38cf30d7-e53e-47ae-9545-c79af2270751';

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

  // --- helper: run one single-device plan step and wait ------------------------
  const runStep = async (deviceId: string, actionId: string, inputs: Record<string, unknown>): Promise<{ status: string; details?: Record<string, unknown>; error?: string }> => {
    const created = await authed('POST', '/plans', { pluginId: LCOS_PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId }] });
    const plan = (await created.json()) as { id?: string };
    if (!plan.id) throw new Error(`plan creation failed for ${actionId}: status=${created.status}`);
    await authed('POST', `/plans/${plan.id}/execute`);
    let detail: Record<string, unknown> | null = null;
    for (let i = 0; i < 60; i++) {
      await new Promise((r) => setTimeout(r, 2_000));
      const d = ((await authed('GET', `/plans/${plan.id}`).then((r) => r.json())) as Record<string, unknown>) ?? null;
      if (d && ['succeeded', 'failed', 'cancelled'].includes(String(d.status))) { detail = d; break; }
    }
    // Step result shape: { success, result: <ActionResult {success, details|error}> }.
    const steps = (detail?.steps ?? []) as Array<{ actionId?: string; status?: string; result?: { success?: boolean; result?: { success?: boolean; details?: Record<string, unknown>; error?: string } | null } | null }>;
    const step = steps.find((s) => s.actionId === actionId) ?? steps[steps.length - 1] ?? {};
    return { status: String(detail?.status), details: step.result?.result?.details, error: step.result?.result?.error };
  };

  // --- 1. discovery: v0.4.0 + new catalog ------------------------------------
  console.log('\n[1] plugin discovery');
  let actions: Array<{ id: string }> = [];
  let version = '';
  for (let i = 0; i < 60 && !version; i++) {
    const plugins = ((await authed('GET', '/plugins').then((r) => r.json())) as Array<{ id: string; version?: string }>) ?? [];
    const lc = plugins.find((p) => p.id === LCOS_PLUGIN_ID);
    if (lc?.version) {
      version = lc.version;
      actions = (((await authed('GET', `/plugins/${LCOS_PLUGIN_ID}/actions`).then((r) => r.json())) as { actions?: typeof actions })?.actions) ?? [];
    } else await new Promise((r) => setTimeout(r, 1_000));
  }
  check('plugin discovered at v0.4.0', version === '0.4.0', version);
  for (const id of ['wlan.networks.read', 'wlan.radios.read', 'wlan.radio.channel.set', 'wlan.radio.power.set']) {
    check(`catalog contains ${id}`, actions.some((a) => a.id === id), actions.map((a) => a.id));
  }
  check('catalog no longer has wlan.ssid.state.set (runtime-only state)', !actions.some((a) => a.id === 'wlan.ssid.state.set'));

  // --- 2. GW_Ralf: WLAN reads --------------------------------------------------
  console.log('\n[2] wlan.networks.read on GW_Ralf');
  const nets = await runStep(DEVICE_GW, 'wlan.networks.read', {});
  check('networks-read plan succeeded', nets.status === 'succeeded', { status: nets.status, error: nets.error });
  const networkList = (nets.details?.networks ?? []) as Array<{ ifc?: string; name?: string; operating?: number | null; stations?: number | null }>;
  check('at least one SSID reported', networkList.length >= 1, { count: networkList.length });
  check('SSID names are non-empty (status MIB carries them)', networkList.some((n) => typeof n.name === 'string' && n.name.length > 0), networkList);

  console.log('\n[3] wlan.radios.read on GW_Ralf');
  const radios = await runStep(DEVICE_GW, 'wlan.radios.read', {});
  check('radios-read plan succeeded', radios.status === 'succeeded', { status: radios.status, error: radios.error });
  const radioList = (radios.details?.radios ?? []) as Array<{ ifc?: string; band?: number | null; channel?: number | null }>;
  check('at least one radio reported (dual-radio model)', radioList.length >= 1, { count: radioList.length });
  check('radio rows carry a channel value', radioList.some((r) => typeof r.channel === 'number'), radioList);

  // --- 4. WLC01 negative: channel set on a radio-less device --------------------
  console.log('\n[4] wlan.radio.channel.set negative test on WLC01 (no WLAN radio)');
  const ch = await runStep(DEVICE_WLC, 'wlan.radio.channel.set', { ifc: 'WLAN-1', channel: 6 });
  check('channel-set failed cleanly (expected — no radio)', ch.status === 'failed' || Boolean(ch.error), { status: ch.status, error: ch.error });

  // --- 5. GW_Ralf soft check: config.backup.download ----------------------------
  // KNOWN FINDING: physical LCOS devices expose an EMPTY SFTP /config file (opens,
  // never delivers data) — only the vRouter WLC01 serves the real LCF document.
  // This documents the behavior; it does not fail the E2E.
  console.log('\n[5] config.backup.download on GW_Ralf (soft check — empty-/config finding)');
  const backup = await runStep(DEVICE_GW, 'config.backup.download', {});
  const sizeBytes = Number(backup.details?.sizeBytes ?? -1);
  if (backup.status === 'succeeded' && sizeBytes > 50_000) {
    console.log(`  INFO backup unexpectedly worked (${sizeBytes} bytes) — empty-/config finding may be device-specific`);
  } else {
    console.log(`  INFO confirmed: backup on physical device → status=${backup.status}, sizeBytes=${sizeBytes}, error=${JSON.stringify(backup.error ?? '').slice(0, 200)}`);
  }

  // --- summary ------------------------------------------------------------------
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('E2E crashed:', e);
  process.exit(1);
});
