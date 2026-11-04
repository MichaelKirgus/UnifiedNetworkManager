/**
 * e2e-wled.ts — Live end-to-end test of the WLED plugin against a real device.
 *
 * Prereqs: dev stack up (docker compose -f docker-compose.dev.yml), wled-plugin
 * + web-fetch-plugin online, and a reachable WLED device on the LAN.
 *
 *   UNM_API_URL=http://localhost:3000/v1 \
 *   UNM_TOKEN=unm_... \
 *   WLED_ADDRESS=10.40.1.62 \
 *   tsx scripts/e2e-wled.ts [create|verify|cleanup]
 *
 * Phases (default = create + verify):
 *  - create:  POST /devices "WLED-Test" with the wled-plugin assignment (no secret)
 *  - verify:  force refresh → assert telemetry metrics + updates row (v16.0.0 → v16.0.1,
 *             applyActionId wled.firmware.update, download.wled.me URL)
 *  - cleanup: DELETE the device again (idempotent; safe to re-run)
 */

const API = process.env.UNM_API_URL ?? 'http://localhost:3000/v1';
const TOKEN = process.env.UNM_TOKEN ?? '';
const ADDRESS = process.env.WLED_ADDRESS ?? '10.40.1.62';
const DEVICE_NAME = 'WLED-Test';
const WLED_PLUGIN_UUID = '00000000-0000-4000-8000-000000000016';

if (!TOKEN) {
  console.error('UNM_TOKEN is required');
  process.exit(2);
}

let passed = 0;
let failed = 0;
function check(label: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    passed++;
    console.log(`  ✅ ${label}`);
  } else {
    failed++;
    console.log(`  ❌ ${label}${detail !== undefined ? ` — ${JSON.stringify(detail)}` : ''}`);
  }
}

async function authed(method: string, path: string, body?: unknown): Promise<Response> {
  return fetch(`${API}${path}`, {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function findDeviceByName(name: string): Promise<{ id: string } | null> {
  const r = await authed('GET', '/devices');
  if (!r.ok) return null;
  const list = (await r.json()) as Array<{ id: string; name: string }>;
  return list.find((d) => d.name === name) ?? null;
}

async function findWledPluginId(): Promise<string | null> {
  const r = await authed('GET', '/plugins');
  if (!r.ok) return null;
  const list = (await r.json()) as Array<{ id: string; uuid?: string }>;
  const hit = list.find((p) => p.id === WLED_PLUGIN_UUID || p.uuid === WLED_PLUGIN_UUID);
  return hit?.id ?? null;
}

async function createDevice(): Promise<string | null> {
  console.log('\n— Create device —');
  const pluginId = await findWledPluginId();
  check('wled-plugin registered in API', pluginId !== null, { expected: WLED_PLUGIN_UUID });
  if (!pluginId) return null;

  // Idempotent: reuse an existing "WLED-Test" device.
  const existing = await findDeviceByName(DEVICE_NAME);
  if (existing) {
    console.log(`  (info) reusing existing device ${existing.id}`);
    return existing.id;
  }

  const r = await authed('POST', '/devices', {
    name: DEVICE_NAME,
    vendor: 'wled',
    managementAddress: ADDRESS,
    deviceTypes: ['lighting'],
    plugins: [{ pluginId, isPrimary: true, secretId: null }],
  });
  const body = await r.json();
  check('POST /devices accepted', r.status === 200 || r.status === 201, { status: r.status, body });
  return (body as { id?: string }).id ?? null;
}

async function verify(deviceId: string): Promise<void> {
  console.log('\n— Force refresh + telemetry —');
  const refresh = await authed('POST', '/devices/refresh', { deviceIds: [deviceId] });
  check('forced refresh accepted', refresh.status === 200, { status: refresh.status, body: await refresh.json() });

  // The poll is async — wait for a fresh telemetry snapshot.
  let metrics: Record<string, unknown> = {};
  let health = '';
  let sawSnapshot = false;
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 5_000));
    const r = await authed('GET', `/devices/${deviceId}/monitoring`);
    if (!r.ok) continue;
    const body = (await r.json()) as { health: string; snapshots: Array<{ pluginId: string; collectedAt: string | null; metrics: Record<string, unknown>; health: string }> };
    const snap = body.snapshots.find((s) => s.pluginId === WLED_PLUGIN_UUID);
    if (snap?.collectedAt && Object.keys(snap.metrics).length > 0) {
      sawSnapshot = true;
      metrics = snap.metrics;
      health = snap.health;
      break;
    }
  }
  check('telemetry snapshot ingested', sawSnapshot, { health });

  const expectedKeys = ['wled.freeHeapBytes', 'wled.fps', 'wled.ledCount', 'wled.wifiRssiDbm', 'wled.version'];
  for (const key of expectedKeys) {
    check(`metric present: ${key}`, metrics[key] !== undefined, metrics[key]);
  }
  if (metrics['wled.freeHeapBytes'] !== undefined) {
    const heap = Number(metrics['wled.freeHeapBytes']);
    check('freeHeapBytes is a sane number', Number.isFinite(heap) && heap > 0 && heap < 512_000, heap);
  }
  if (metrics['wled.wifiRssiDbm'] !== undefined) {
    const rssi = Number(metrics['wled.wifiRssiDbm']);
    check('wifiRssiDbm in [-100, 0]', Number.isFinite(rssi) && rssi <= 0 && rssi >= -100, rssi);
  }
  if (metrics['wled.version'] !== undefined) {
    check('version is 16.0.x', /^16\.0\.\d+$/.test(String(metrics['wled.version'])), metrics['wled.version']);
  }

  console.log('\n— Updates row —');
  let rows: Array<Record<string, unknown>> = [];
  const uDeadline = Date.now() + 90_000;
  while (Date.now() < uDeadline) {
    await new Promise((r) => setTimeout(r, 5_000));
    const r = await authed('GET', `/updates?deviceId=${deviceId}&kind=firmware`);
    if (!r.ok) continue;
    rows = ((await r.json()) as { rows: Array<Record<string, unknown>> }).rows ?? [];
    if (rows.length > 0) break;
  }
  check('exactly one firmware update row', rows.length === 1, rows);
  if (rows.length === 1) {
    const row = rows[0];
    check('row name is "os" / kind firmware', row['name'] === 'os' && row['kind'] === 'firmware', { name: row['name'], kind: row['kind'] });
    check('current version 16.0.x', /^16\.0\.\d+$/.test(String(row['currentVersion'])), row['currentVersion']);
    check('latest > current (update available)', String(row['latestVersion']) !== String(row['currentVersion']), { cur: row['currentVersion'], latest: row['latestVersion'] });
    const applyInput = row['applyInput'] as Record<string, unknown> | null;
    check(
      'applyActionId is wled.firmware.update',
      (row['applyActionId'] as string) === 'wled.firmware.update',
      row['applyActionId'],
    );
    const url = String(applyInput?.url ?? '');
    check('applyInput.url points at download.wled.me with full GitHub path', url.startsWith('https://download.wled.me/wled/WLED/releases/download/'), url);
    check('applyInput.fileName matches WLED_{ver}_{release}.bin pattern', /^WLED_\d+\.\d+\.\d+_ESP32\.bin$/.test(String(applyInput?.fileName ?? '')), applyInput?.fileName);
  }

  console.log('\n— Quick action (web UI) —');
  const qa = await authed('POST', `/devices/${deviceId}/quick-action`, { actionId: 'webui' });
  check('quick-action resolves web-UI URL', qa.status === 200, { status: qa.status, body: await qa.json() });
}

async function cleanup(): Promise<void> {
  console.log('\n— Cleanup —');
  const existing = await findDeviceByName(DEVICE_NAME);
  if (!existing) {
    console.log('  (info) no WLED-Test device to delete');
    return;
  }
  const r = await authed('DELETE', `/devices/${existing.id}`);
  check(`deleted ${DEVICE_NAME}`, r.status === 200 || r.status === 204, { status: r.status });
}

async function main(): Promise<void> {
  const mode = process.argv[2] ?? 'all';
  if (mode === 'cleanup') {
    await cleanup();
  } else {
    const deviceId = await createDevice();
    if (!deviceId) {
      failed++;
    } else {
      await verify(deviceId);
    }
  }

  console.log(`\n${failed === 0 ? '✅' : '❌'} ${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
