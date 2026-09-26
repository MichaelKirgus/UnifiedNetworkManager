/**
 * End-to-end verification for the VMs page CPU columns (live dev stack):
 *   1. logs in via the real auth flow (TOTP minted from the seeded admin secret)
 *   2. GET /vms — asserts cores/threads are present in extra and vcpus is the
 *      EFFECTIVE allocation (cores × threads), not the appliance's legacy field
 *   3. GET /devices/:id/probe?keys=vmStates,vmStats TWICE (~4 s apart) — first
 *      call establishes the cpu.time baseline (cpuPct may be absent), second
 *      must carry live cpuPct for running VMs + vcpus per domain
 *   4. asserts stopped VMs are present in vmStats without a bogus cpuPct
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/verify-vm-cpu.ts [deviceId]
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

async function main(): Promise<void> {
  // --- Login (admin/admin; TOTP when enabled) ---------------------------------
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret", id FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null; id: string };

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

  const authed = async (method: string, p: string): Promise<Response> =>
    fetch(`${API}${p}`, { method, headers: { Authorization: `Bearer ${token}` } });

  // --- Target device -----------------------------------------------------------
  let deviceId = process.argv[2];
  if (!deviceId) {
    const dRes = await authed('GET', '/devices');
    const devices = (await dRes.json()) as Array<{ id: string; name: string }>;
    const truenas = devices.find((d) => /KIRGUS/i.test(d.name)) ?? devices[0];
    if (!truenas) throw new Error('no device found');
    deviceId = truenas.id;
    console.log(`  INFO using device ${truenas.name} (${deviceId})`);
  }

  // Force a fresh inventory poll so the vms rows carry the NEW cores/threads
  // extra fields (rows from before this plugin version lack them).
  const refRes = await fetch(`${API}/devices/refresh`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ deviceIds: [deviceId] }) });
  check('POST /devices/refresh → 200', refRes.status === 200, { status: refRes.status });
  await new Promise((r) => setTimeout(r, 6_000)); // let the poll land

  // --- 1. GET /vms — cores/threads + effective vcpus ---------------------------
  const vRes = await authed('GET', '/vms');
  check('GET /vms → 200', vRes.status === 200);
  const body = (await vRes.json()) as { vms?: Array<{ name: string; state: string; vcpus?: number | null; extra?: Record<string, unknown> }> };
  const rows = (body.vms ?? []).filter((v) => true);
  check('VMs returned', rows.length > 0, rows.length);

  let withCores = 0;
  let withThreads = 0;
  let effectiveOk = 0;
  for (const v of rows) {
    const e = v.extra ?? {};
    const cores = typeof e['cores'] === 'number' ? (e['cores'] as number) : null;
    const threads = typeof e['threads'] === 'number' ? (e['threads'] as number) : null;
    if (cores !== null) withCores++;
    if (threads !== null) withThreads++;
    // Effective vcpus must equal cores × threads when both are reported.
    if (cores !== null && threads !== null && v.vcpus === cores * threads) effectiveOk++;
  }
  check('cores present on all VM rows', withCores === rows.length, { withCores, total: rows.length });
  check('threads present on all VM rows', withThreads === rows.length, { withThreads, total: rows.length });
  check('vcpus = cores × threads (effective allocation)', effectiveOk === rows.length, { effectiveOk, total: rows.length });

  const runningNames = new Set(rows.filter((v) => v.state === 'RUNNING').map((v) => v.name));
  console.log(`  INFO ${rows.length} VMs, ${runningNames.size} running: ${[...runningNames].join(', ')}`);

  // --- 2. Probe round 1 — establishes the cpu.time baseline --------------------
  const KEYS = encodeURIComponent('vmStates,vmStats');
  const p1 = await authed('GET', `/devices/${deviceId}/probe?keys=${KEYS}`);
  const p1Clone = p1.clone();
  check('probe #1 → 200', p1.status === 200, { status: p1.status, body: (await p1.text().catch(() => '')).slice(0, 300) });
  const b1 = (await p1Clone.json().catch(() => null)) as { probe?: { metrics: Record<string, unknown> } } | null;
  if (!b1) throw new Error('probe #1 response not JSON');
  const stats1 = (b1.probe?.metrics['vmStats'] ?? {}) as Record<string, { cpuPct?: number; vcpus?: number }>;
  check('probe #1 vmStats present', Object.keys(stats1).length > 0, Object.keys(stats1));

  // --- 3. Probe round 2 (~4 s later) — live CPU percent ------------------------
  await new Promise((r) => setTimeout(r, 4_000));
  const p2 = await authed('GET', `/devices/${deviceId}/probe?keys=${KEYS}`);
  check('probe #2 → 200', p2.status === 200, { status: p2.status });
  const b2 = (await p2.json()) as { probe?: { metrics: Record<string, unknown> } };
  const stats2 = (b2.probe?.metrics['vmStats'] ?? {}) as Record<string, { cpuPct?: number; vcpus?: number }>;
  check('probe #2 vmStats present', Object.keys(stats2).length > 0, Object.keys(stats2));

  let withCpu = 0;
  for (const [name, s] of Object.entries(stats2)) {
    if (runningNames.has(name) && typeof s.cpuPct === 'number') withCpu++;
  }
  check('live cpuPct on running VMs', withCpu > 0, { withCpu, running: runningNames.size });

  let vcpusOk = 0;
  for (const [name, s] of Object.entries(stats2)) {
    const row = rows.find((v) => v.name === name);
    if (row && typeof s.vcpus === 'number' && s.vcpus === row.vcpus) vcpusOk++;
  }
  check('probe vcpus matches inventory effective vcpus', vcpusOk > 0, { vcpusOk, total: Object.keys(stats2).length });

  // Stopped VMs must NOT carry a cpuPct (no CPU time accrues while shut off —
  // the counter is flat, so rate ≤ 0 → absent).
  let stoppedClean = true;
  for (const [name, s] of Object.entries(stats2)) {
    if (!runningNames.has(name) && typeof s.cpuPct === 'number') stoppedClean = false;
  }
  check('stopped VMs carry no cpuPct', stoppedClean);

  // --- Summary ------------------------------------------------------------------
  const sample = Object.entries(stats2).slice(0, 5).map(([n, s]) => `${n}: ${typeof s.cpuPct === 'number' ? s.cpuPct.toFixed(1) + '%' : '—'} (vcpus=${s.vcpus ?? '?'})`);
  console.log(`\n  sample: ${sample.join(' | ')}`);

  if (failures > 0) {
    console.error(`\n❌ ${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('\n✅ ALL CHECKS PASSED');
}

main().catch((e) => { console.error('FATAL:', e instanceof Error ? (e.stack ?? e.message) : e); process.exit(1); });
