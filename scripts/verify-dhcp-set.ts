/**
 * Live verification for dhcp.staticMapping.set (Kea backend) on OPNSENSE01.
 *
 * Runs an IDEMPOTENT no-op edit: picks one existing Kea reservation and re-saves
 * the SAME mac/ip/hostname through a plan (dhcp.staticMapping.set +
 * dhcp.reconfigure). If the plugin's set_reservation payload shape is wrong for
 * real firmware, the step fails with the appliance's validation error — which
 * is exactly what this script exists to catch. The reservation values are
 * unchanged either way, so the test is safe to re-run.
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/verify-dhcp-set.ts
 */

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const jwt = apiRequire('jsonwebtoken') as { sign: (payload: Record<string, unknown>, secret: string, opts?: { expiresIn?: number | string }) => string };

function envValue(key: string): string | null {
  try {
    const m = new RegExp(`^${key}=(.+)$`, 'm').exec(fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 500) : '');
  }
}

async function main(): Promise<void> {
  const pg = apiRequire('pg') as typeof import('pg');
  const pool = new pg.Pool({ connectionString: envValue('DATABASE_URL') ?? 'postgres://unm:unm@localhost:5432/unm' });
  const secret = envValue('JWT_SECRET') ?? 'dev-secret';
  const row = (await pool.query(`SELECT id, username, roles, permissions FROM users WHERE username = 'admin'`)).rows[0] as
    | { id: string; username: string; roles: unknown; permissions: unknown }
    | undefined;
  if (!row) throw new Error('no admin user');
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
  const token = jwt.sign({ sub: row.id, username: row.username, roles: parseArr(row.roles), permissions: parseArr(row.permissions), amr: ['totp'] }, secret, { expiresIn: 3600 });

  async function authed(method: string, urlPath: string, body?: unknown): Promise<{ status: number; json(): Promise<unknown> }> {
    const res = await fetch(`${API}${urlPath}`, {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, json: async () => (await res.json()) as unknown };
  }

  // --- Pick a real Kea reservation on OPNSENSE01 ---------------------------------
  async function getJson(urlPath: string): Promise<unknown> {
    const r = await authed('GET', urlPath);
    return r.json();
  }
  const dhcp = (await getJson('/dhcp')) as {
    networks: Array<{ deviceId: string; pluginId: string; name: string; cidr?: string | null; refId?: string | null }>;
    reservations: Array<{ deviceId: string; pluginId: string; mac: string; ip?: string | null; hostname?: string | null; refId?: string | null; deviceName?: string | null }>;
  };
  const devices = (await getJson('/devices')) as Array<{ id: string; name: string; plugins?: Array<{ pluginId: string }> }>;
  const opnsense01 = devices.find((d) => d.name === 'OPNSENSE01');
  check('OPNSENSE01 found', !!opnsense01, devices.map((d) => d.name));
  if (!opnsense01) { await pool.end(); return; }

  const target = dhcp.reservations.find((r) => r.deviceId === opnsense01.id && r.refId && r.ip);
  check('found a Kea reservation with uuid + ip', !!target, dhcp.reservations.filter((r) => r.deviceId === opnsense01.id).length);
  if (!target) { await pool.end(); return; }
  console.log(`\nTarget: ${target.mac} → ${target.ip}${target.hostname ? ` (${target.hostname})` : ''} refId=${target.refId}`);

  // --- Create the no-op edit plan -------------------------------------------------
  const createRes = await authed('POST', '/plans', {
    pluginId: target.pluginId,
    intentActionId: 'dhcp.staticMapping.set',
    inputs: { uuid: target.refId, mac: target.mac, ip: target.ip, hostname: target.hostname ?? undefined },
    devices: [{ deviceId: opnsense01.id }],
  });
  const createBody = await createRes.json();
  check('POST /plans (set) → 201', createRes.status === 201, createBody);
  const plan = createBody as { id: string };

  // Append the reconfigure step so the staged change is activated.
  const bulkRes = await authed('POST', `/plans/${plan.id}/steps/bulk`, { steps: [{ deviceId: opnsense01.id, actionId: 'dhcp.reconfigure', input: {} }] });
  const bulkBody = await bulkRes.json();
  check('append dhcp.reconfigure step → 2xx', bulkRes.status >= 200 && bulkRes.status < 300, bulkBody);

  // --- Execute + poll -------------------------------------------------------------
  const execRes = await authed('POST', `/plans/${plan.id}/execute`);
  const execBody = await execRes.json();
  check('POST /plans/:id/execute → 2xx', execRes.status >= 200 && execRes.status < 300, execBody);

  // The executor wraps the plugin's action result: step.result = { success, result: <plugin output> }.
  type StepResult = { success?: boolean; result?: { success?: boolean; details?: Record<string, unknown> }; details?: Record<string, unknown> };
  let final: { status: string; steps?: Array<{ actionId: string; status: string; result?: StepResult }> } | null = null;
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 3000));
    const p = (await getJson(`/plans/${plan.id}`)) as typeof final;
    if (p && ['succeeded', 'failed', 'cancelled'].includes(p.status)) { final = p; break; }
  }
  check('plan reached a terminal status', !!final, 'timed out after 180s');
  if (!final) { await pool.end(); return; }

  const setStep = (final.steps ?? []).find((s) => s.actionId === 'dhcp.staticMapping.set');
  const reconfStep = (final.steps ?? []).find((s) => s.actionId === 'dhcp.reconfigure');
  check('set step succeeded', final.status === 'succeeded' && setStep?.status === 'succeeded', { status: final.status, steps: final.steps });
  if (setStep && !setStep.result?.success) {
    // Plugin output is nested one level down; print whatever error details exist.
    const inner = setStep.result?.result ?? {};
    console.error('  appliance error payload:', JSON.stringify(inner.details ?? inner).slice(0, 800));
  }
  check('reconfigure step succeeded', reconfStep?.status === 'succeeded', reconfStep);

  // --- Verify the reservation is unchanged after the no-op edit --------------------
  try { await authed('POST', '/devices/refresh', { deviceIds: [opnsense01.id] }); } catch { /* best-effort */ }
  await new Promise((r) => setTimeout(r, 5000));
  const dhcp2 = (await getJson(`/dhcp?deviceId=${opnsense01.id}`)) as typeof dhcp;
  const after = dhcp2.reservations.find((r) => r.refId === target.refId);
  check('reservation still present with same mac/ip', !!after && after.mac === target.mac && after.ip === target.ip, after);

  // --- Cleanup ----------------------------------------------------------------------
  const delRes = await authed('DELETE', `/plans/${plan.id}`);
  check('cleanup: plan deleted → 204', delRes.status === 204, delRes.status);

  console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) FAILED.`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
