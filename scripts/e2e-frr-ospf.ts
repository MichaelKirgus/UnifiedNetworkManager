/**
 * End-to-end verification for FRR/OSPF routing-protocol monitoring (opnsense plugin ≥ 0.7.0).
 *
 * Validates against the deployed stack (API on :3000):
 *   1. Finds a real OPNsense device with an SSH slot bound (one of four lab
 *      boxes by default), override with DEVICE_NAME (substring) or DEVICE_ADDRESS.
 *   2. Forces an immediate re-poll (POST /devices/refresh) and reads the latest
 *      telemetry row + the rolled-up device healthReasons.
 *   3. Asserts the routing-protocol metrics are present: FRR reachable, router ID,
 *      neighbor counts + per-neighbor rows, learned-route counts — and that a
 *      healthy box produces NO FRR/OSPF health reasons (no false positives).
 *
 * If no SSH slot is bound to the device, `routing.frr.reachable` is absent from
 * the telemetry — the script reports SKIP for those checks instead of failing
 * (the feature is intentionally silent without an ssh slot).
 *
 * The script never writes to the appliance — it only triggers a normal poll.
 *
 * Usage (from the repo root, with the stack up):
 *   ./node_modules/.bin/tsx scripts/e2e-frr-ospf.ts
 */

import fs from 'node:fs';
import path from 'node:path';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';

/** Long-lived UNM_API_TOKEN (bypasses 2FA; the seeded admin password was changed at onboarding). */
function readToken(): string {
  if (process.env.UNM_API_TOKEN) return process.env.UNM_API_TOKEN.trim();
  const env = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
  const m = env.match(/^\s*UNM_API_TOKEN\s*=\s*(.*)$/m);
  if (!m) throw new Error('UNM_API_TOKEN not found in .env or the environment');
  return m[1].trim().replace(/^["']|["']$/g, '');
}

const TOKEN = readToken();
let failures = 0;
function check(label: string, cond: boolean, extra?: unknown) {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

interface DeviceRow {
  id: string;
  name: string;
  managementAddress: string | null;
  status?: string;
  healthReasons?: Array<{ pluginId: string; severity: string; message: string }>;
}
interface TelemetryRow {
  collectedAt: string;
  health: string;
  metrics: Record<string, unknown>;
}

async function main(): Promise<void> {
  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}` },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  const health = await fetch('http://localhost:3000/healthz').then((r) => r.json()).catch(() => null);
  check('API healthy', (health as { status?: string })?.status === 'ok', health);

  // --- Find the target device -------------------------------------------------
  const devRes = await authed('GET', '/devices');
  check('GET /devices returns 200', devRes.status === 200, { status: devRes.status });
  const devices = (await devRes.json()) as DeviceRow[];

  const nameHint = process.env.DEVICE_NAME ?? 'GWST03';
  const addrHint = process.env.DEVICE_ADDRESS ?? null;
  // Exact name match first (there are several such boxes), then substring.
  const device =
    (addrHint ? devices.find((d) => d.managementAddress === addrHint) : undefined) ??
    devices.find((d) => d.name === nameHint) ??
    devices.find((d) => new RegExp(nameHint, 'i').test(d.name));
  check(`device matching ${JSON.stringify(addrHint ?? nameHint)} found`, Boolean(device), {
    candidates: devices.filter((d) => /opnsense|GWST/i.test(`${d.name} ${d.managementAddress ?? ''}`)).map((d) => d.name).slice(0, 10),
  });
  if (!device) throw new Error('target device not found');

  // --- Force an immediate re-poll (synchronous — telemetry is written on return) --
  const refresh = await authed('POST', '/devices/refresh', { deviceIds: [device.id] });
  check('forced refresh accepted', refresh.status === 200, { status: refresh.status });

  // --- Read the latest telemetry row -------------------------------------------
  const telRes = await authed('GET', `/devices/${device.id}/telemetry?limit=5`);
  check('GET /devices/:id/telemetry returns 200', telRes.status === 200, { status: telRes.status });
  const { history } = (await telRes.json()) as { deviceId: string; history: TelemetryRow[] };
  const latest = history[history.length - 1];
  check('telemetry row exists', Boolean(latest));
  if (!latest) throw new Error('no telemetry rows');

  const freshMin = Date.now() - 5 * 60_000;
  check(
    'row is from this refresh (≤ 5 min old)',
    new Date(latest.collectedAt).getTime() >= freshMin,
    { collectedAt: latest.collectedAt }
  );

  const m = latest.metrics ?? {};
  const hasFrr = typeof m['routing.frr.reachable'] === 'number';
  if (!hasFrr) {
    console.log('\n  SKIP no SSH slot bound to this device — FRR/OSPF metrics absent (feature correctly silent).');
    const devRes2 = await authed('GET', '/devices');
    const devices2 = (await devRes2.json()) as DeviceRow[];
    const freshDevice = devices2.find((d) => d.id === device.id);
    check(
      'no FRR health reasons without an ssh slot',
      !((freshDevice?.healthReasons ?? []).some((r) => /ospf|frr/i.test(r.message)))
    );
    return;
  }

  // --- Healthy-box assertions ---------------------------------------------------
  console.log('\n— Routing-protocol metrics (SSH slot bound) —');
  check('FRR reachable via vtysh', m['routing.frr.reachable'] === 1, { value: m['routing.frr.reachable'] });
  check(
    'router ID parsed',
    typeof m['routing.ospf.routerId'] === 'string' && /\d/.test(String(m['routing.ospf.routerId'])),
    { value: m['routing.ospf.routerId'] }
  );

  const total = Number(m['routing.ospf.neighborsTotal']);
  const full = Number(m['routing.ospf.neighborsFull']);
  check('at least one OSPF neighbor', total >= 1, { total });
  check('all neighbors Full (healthy box)', full === total && total > 0, { total, full });

  const routesV4 = m['routing.ospf.routesV4'];
  check(
    'v4 learned-route count present and > 0',
    typeof routesV4 === 'number' && (routesV4 as number) > 0,
    { value: routesV4 }
  );

  const rows = Array.isArray(m['ospfNeighbors']) ? (m['ospfNeighbors'] as Record<string, unknown>[]) : [];
  check('per-neighbor rows present', rows.length === total, { rows: rows.length, total });
  check(
    'every neighbor row is up/Full',
    rows.length > 0 && rows.every((r) => r['status'] === 'up' && /^full/i.test(String(r['state'] ?? ''))),
    rows.slice(0, 6)
  );

  // --- No false-positive health reasons on a healthy box -------------------------
  // Re-fetch the device row — the healthReasons rollup is written by THIS poll.
  const devRes2 = await authed('GET', '/devices');
  const devices2 = (await devRes2.json()) as DeviceRow[];
  const freshDevice = devices2.find((d) => d.id === device.id);
  const frrReasons = (freshDevice?.healthReasons ?? []).filter((r) => /ospf|frr/i.test(r.message));
  check('no FRR/OSPF health reasons on a healthy box', frrReasons.length === 0, frrReasons);

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  if (failures > 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error('E2E aborted:', err);
  process.exit(1);
});
