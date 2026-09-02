/**
 * End-to-end smoke test for the TrueNAS plugin (first config-capable release).
 *
 * Boots a MOCK TrueNAS appliance — a WebSocket JSON-RPC server at /api/current
 * answering the documented methods the plugin calls — then boots the REAL plugin
 * (importing src/index.ts, which listens on PORT) and exercises:
 *   - GET  /discover    → capabilities include configuration+planning+deviceState; catalog present
 *   - POST /monitoring  → system/pools/networks/ports metrics collected from the mock
 *   - POST /state       → Pools + Interfaces + System sections with power actions
 *   - POST /config      → read action executes; system.reboot returns a job id; unknown → success:false
 *   - POST /plan        → single-device fan-out yields one step per device
 */
import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';

const MOCK_PORT = 48761;
const PLUGIN_PORT = 48762;
const BASE = `http://localhost:${PLUGIN_PORT}`;

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra) : '');
  }
}

// --- Mock TrueNAS appliance (WebSocket JSON-RPC at /api/current) ----------------------

const httpServer = http.createServer((_req, res) => {
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ noServer: true });

httpServer.on('upgrade', (req, socket, head) => {
  if ((req.url ?? '').split('?')[0] !== '/api/current') {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws));
});

wss.on('connection', (ws: WebSocket) => {
  let authenticated = false;
  ws.on('message', (raw) => {
    const msg = JSON.parse(String(raw)) as { id?: number; method?: string; params?: unknown[] };
    const reply = (result: unknown, error?: { code: number; message: string }) => {
      if (!ws.readyState || ws.readyState !== WebSocket.OPEN) return;
      ws.send(JSON.stringify(error ? { jsonrpc: '2.0', id: msg.id, error } : { jsonrpc: '2.0', id: msg.id, result }));
    };

    switch (msg.method) {
      case 'auth.login_ex':
        authenticated = true;
        return reply({ response_type: 'SUCCESS' });
      case 'system.info':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply({
          hostname: 'mock-truenas',
          version: 'SCALE 25.04.2',
          model: 'Intel Core i7-8700',
          cores: 6,
          loadavg: [1.2, 0.9, 0.7],
          physmem: 32_212_254_720,
          uptime_seconds: 123_456,
        });
      case 'pool.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply([
          { name: 'tank', status: 'ONLINE', size: 8_796_093_022_208, allocated: 4_398_046_511_104, free: 4_398_046_511_104, scan: { function: 'SCRUB', state: 'SCANNING', percentage: 42 } },
          { name: 'cache', status: 'DEGRADED', size: 1_099_511_627_776, allocated: 549_755_813_888, free: 549_755_813_888 },
        ]);
      case 'interface.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply([
          { name: 'vnet0', description: 'NET_MANAGEMENT', state: { link_state: 'LINK_STATE_UP', link_address: 'aa:bb:cc:dd:ee:01' }, aliases: [JSON.stringify({ type: 'INET', address: '10.25.0.10', netmask: 16 })] },
          { name: 'vnet1', description: 'LAN', state: { link_state: 'LINK_STATE_DOWN', link_address: 'aa:bb:cc:dd:ee:02' }, aliases: [JSON.stringify({ type: 'INET', address: '192.168.50.1', netmask: 24 })], vlan_tag: 50 },
        ]);
      case 'alert.list':
        return reply([]);
      case 'staticroute.query':
        return reply([{ id: 1, destination: '0.0.0.0/0', gateway: '10.25.0.1', description: 'default' }]);
      case 'system.dmidecode_info':
        return reply({ 'baseboard-product-name': 'To Be Filled By O.E.M.', 'system-serial-number': 'TN-SERIAL-001' });
      case 'system.reboot':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply(42); // job id — the appliance will go down shortly
      case 'system.shutdown':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply(43);
      default:
        return reply(null, { code: -32601, message: `Method ${msg.method} does not exist` });
    }
  });
});

// --- Test driver -----------------------------------------------------------------------

async function main(): Promise<void> {
  await new Promise<void>((r) => httpServer.listen(MOCK_PORT, () => r()));
  console.log(`[smoke] mock TrueNAS (ws JSON-RPC) on :${MOCK_PORT}`);

  process.env.PORT = String(PLUGIN_PORT);
  await import('./src/index');
  await new Promise((r) => setTimeout(r, 300));
  console.log(`[smoke] plugin on :${PLUGIN_PORT}`);

  const creds = { username: 'root', password: 'truenas' };
  // The mock is plain HTTP — the client picks ws/wss from the `transport` setting
  // (auto → wss), so inject transport=http on every call via x-unm-settings.
  const ADDR = `localhost:${MOCK_PORT}`;
  const SETTINGS = JSON.stringify({ transport: 'http' });
  const post = (path: string, body: unknown) =>
    fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-unm-settings': SETTINGS }, body: JSON.stringify(body) });

  // --- /discover -----------------------------------------------------------------------
  const disc = (await (await fetch(`${BASE}/discover`)).json()) as Record<string, unknown>;
  console.log('\n== /discover ==');
  check('uuid is the TrueNAS plugin uuid', disc.uuid === '00000000-0000-4000-8000-000000000009', disc.uuid);
  const caps = (disc.capabilities ?? []) as string[];
  check('capabilities include configuration+planning+deviceState', ['configuration', 'planning', 'deviceState'].every((c) => caps.includes(c)), caps);
  const actions = (disc.actions ?? []) as { id: string; riskLevel: string }[];
  check('action catalog has 5 actions', actions.length === 5, `count=${actions.length}`);
  check('dangerous power actions marked', actions.filter((a) => a.riskLevel === 'dangerous').map((a) => a.id).sort().join(',') === 'system.reboot,system.shutdown');

  // --- /monitoring ---------------------------------------------------------------------
  const mon = (await post('/monitoring', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds })) as Response;
  const monJson = (await mon.json()) as { health?: string; metrics?: Record<string, unknown> };
  console.log('\n== /monitoring ==');
  // The mock includes a DEGRADED pool ('cache') → health must be warning, not ok.
  check('health warning (degraded pool present)', monJson.health === 'warning', { health: monJson.health, err: monJson.metrics?.['system.error'] });
  const m = monJson.metrics ?? {};
  check('hostname + version collected', m['system.hostname'] === 'mock-truenas' && m['system.version'] === 'SCALE 25.04.2');
  check('CPU load computed from loadavg/cores', typeof m['system.cpuLoad'] === 'number', m['system.cpuLoad']);
  const pools = (m['pools'] ?? []) as Record<string, unknown>[];
  check('pools table has 2 rows', pools.length === 2, `count=${pools.length}`);
  check('pool usage gauge computed', typeof m['storage.poolUsedPct'] === 'number' && (m['storage.poolUsedPct'] as number) > 0, m['storage.poolUsedPct']);
  const networks = (m['networks'] ?? []) as Record<string, unknown>[];
  check('networks inventory emitted (one row per IP alias)', networks.length === 2 && networks.some((r) => r.name === 'NET_MANAGEMENT' && r.ip === '10.25.0.10'), networks);
  const ports = (m['ports'] ?? []) as Record<string, unknown>[];
  check('ports[] inventory emitted with live state + MAC', ports.length === 2 && ports.some((p) => p.name === 'NET_MANAGEMENT' && p.status === 'up' && (p.extra as Record<string, unknown>)?.mac === 'aa:bb:cc:dd:ee:01'), ports);
  check('ports[] carries vlanId for VLAN interfaces', ports.some((p) => p.name === 'LAN' && p.vlanId === 50), ports);

  // --- /state --------------------------------------------------------------------------
  const stateRes = await post('/state', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds });
  const stateJson = (await stateRes.json()) as { collectedAt?: string; sections?: { id: string; label: string; kind?: string; layout?: { groups: { id: string; portKeys: string[] }[] }; items?: { key: string; title: string; status?: string; fields?: Record<string, unknown>; actions?: { actionId: string }[] }[] }[] };
  console.log('\n== /state ==');
  check('HTTP 200', stateRes.status === 200);
  const sectionIds = (stateJson.sections ?? []).map((s) => s.id);
  check('has pools + interfaces + system sections', ['pools', 'interfaces', 'system'].every((id) => sectionIds.includes(id)), sectionIds);
  const poolSection = (stateJson.sections ?? []).find((s) => s.id === 'pools');
  check('2 pool items with size/used fields', poolSection?.items?.length === 2 && /TB/.test(String(poolSection.items![0].fields?.Size)), poolSection?.items);
  const degradedPool = poolSection?.items?.find((i) => i.key === 'cache');
  check('DEGRADED pool flagged critical-ish status', !!degradedPool, degradedPool);
  const ifSection = (stateJson.sections ?? []).find((s) => s.id === 'interfaces');
  const mgmtIface = ifSection?.items?.find((i) => i.key === 'NET_MANAGEMENT');
  check('management interface up with MAC + IP', mgmtIface?.status === 'up' && mgmtIface.fields?.MAC === 'aa:bb:cc:dd:ee:01' && Array.isArray(mgmtIface.fields?.IPs), mgmtIface);
  // Virtual switch face: kind + layout must cover every interface exactly once.
  const ifLayoutKeys = (ifSection?.layout?.groups ?? []).flatMap((g) => g.portKeys);
  check('interfaces section is a virtual switch', ifSection?.kind === 'switch', ifSection?.kind);
  check(
    'interface layout covers all items exactly once',
    ifLayoutKeys.length === (ifSection?.items?.length ?? 0) && new Set(ifLayoutKeys).size === ifLayoutKeys.length,
    ifLayoutKeys
  );
  const sysSection = (stateJson.sections ?? []).find((s) => s.id === 'system');
  check('system item advertises reboot + shutdown', !!sysSection?.items?.[0]?.actions && ['system.reboot', 'system.shutdown'].every((id) => sysSection.items![0].actions!.some((a) => a.actionId === id)), sysSection?.items?.[0]?.actions);

  // --- /config (read action) -----------------------------------------------------------
  const cfgRead = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'pools.read', input: {} });
  const cfgReadJson = (await cfgRead.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config pools.read ==');
  check('success true with poolCount', cfgRead.status === 200 && cfgReadJson.success === true && (cfgReadJson.result?.details as Record<string, unknown>)?.poolCount === 2, cfgReadJson);

  // --- /config (system.reboot → job id) -------------------------------------------------
  const cfgReboot = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'system.reboot', input: { reason: 'smoke test reboot' } });
  const cfgRebootJson = (await cfgReboot.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config system.reboot ==');
  check('success true with job id', cfgReboot.status === 200 && cfgRebootJson.success === true && ((cfgRebootJson.result?.details as Record<string, unknown>)?.jobId === 42), cfgRebootJson);

  // --- /config (validation + unknown action) -------------------------------------------
  const badInput = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'system.reboot', input: {} });
  const badInputJson = (await badInput.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config validation ==');
  check('missing required reason rejected', badInput.status === 200 && badInputJson.success === false && /reason/.test(String(badInputJson.result?.error)), badInputJson);

  const unknown = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'nope.nope', input: {} });
  const unknownJson = (await unknown.json()) as { success?: boolean };
  check('unknown action → 400 + success:false', unknown.status === 400 && unknownJson.success === false);

  // --- /plan (single-device fan-out) ----------------------------------------------------
  const planRes = await post('/plan', {
    intent: { actionId: 'system.reboot', inputs: { reason: 'smoke test reboot' } },
    devices: [
      { deviceId: 'devA', managementAddress: ADDR, credentials: creds },
      { deviceId: 'devB', managementAddress: ADDR, credentials: creds },
    ],
  });
  const planJson = (await planRes.json()) as { plan?: { provisionRequests: unknown[]; steps: { stepIndex: number; deviceId: string; actionId: string; input: Record<string, unknown> }[] } };
  console.log('\n== /plan system.reboot ==');
  check('HTTP 200', planRes.status === 200);
  const plan = planJson.plan!;
  check('no provision requests (TrueNAS needs no secrets)', Array.isArray(plan.provisionRequests) && plan.provisionRequests.length === 0);
  check('fan-out yields one step per device', plan.steps.length === 2 && plan.steps.every((s) => s.actionId === 'system.reboot' && s.input.reason === 'smoke test reboot'), plan.steps);

  console.log(failures === 0 ? '\nALL SMOKE TESTS PASSED' : `\n${failures} SMOKE TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('[smoke] fatal:', err);
  process.exit(1);
});
