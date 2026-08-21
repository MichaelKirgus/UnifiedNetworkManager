/**
 * End-to-end smoke test for the OPNsense plugin (Phase D).
 *
 * Boots a MOCK OPNsense appliance (plain HTTP, port 4901) that answers the
 * endpoints the plugin probes, then boots the REAL plugin (importing src/index.ts,
 * which listens on PORT=4002) and exercises:
 *   - GET  /discover  → actions catalog non-empty + new options present
 *   - POST /plan      → wireguard.tunnel.create yields correct steps/deps/provision
 *   - POST /config    → read action executes; unknown action → success:false
 *   - POST /monitoring→ metrics collected from the mock appliance
 */
import http from 'http';

const MOCK_PORT = 48731;
const PLUGIN_PORT = 48732;
const BASE = `http://localhost:${PLUGIN_PORT}`;

// --- Mock OPNsense appliance ---------------------------------------------------------

function json(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

const mock = http.createServer((req, res) => {
  const url = req.url ?? '/';
  console.log(`[mock] ${req.method} ${url}`);

  // Edition probe: CE → 403 (no opncentral/sync).
  if (url.startsWith('/api/opncentral/')) return json(res, 403, { error: 'forbidden' });
  // DNS backend probe: unbound not enabled → dnsmasq.
  if (url === '/api/unbound/overview/is_enabled') return json(res, 200, { enabled: false });
  // DHCP backend probe: kea not running → dnsmasq.
  if (url === '/api/kea/service/status') return json(res, 200, { running: false });

  switch (url) {
    case '/api/core/system/status':
      return json(res, 200, { metadata: { system: { status: 2 } } });
    case '/api/diagnostics/cpu_usage/stream': {
      // SSE: one sample then close.
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write('event: message\ndata: {"total":11,"user":3,"nice":0,"sys":7,"intr":1,"idle":89}\n\n');
      return setTimeout(() => res.end(), 200);
    }
    case '/api/diagnostics/system/system_resources':
      return json(res, 200, { memory: { total: '8589934592', used: '4294967296' } });
    case '/api/diagnostics/system/system_information':
      return json(res, 200, { name: 'mock-fw', versions: ['OPNsense 24.1'] });
    case '/api/diagnostics/interface/get_interface_names':
      return json(res, 200, { wan: {}, lan: {} });
    case '/api/diagnostics/interface/get_interface_statistics':
      return json(
        res,
        200,
        { statistics: { 'igc0 / aa:bb:cc:dd:ee:ff': { name: 'wan', 'received-bytes': 123456789, 'sent-bytes': 98765432, address: 'aa:bb:cc:dd:ee:ff' } } }
      );
    case '/api/diagnostics/interface/search_arp/':
      return json(res, 200, { rows: [{ mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.10', intf: 'lan' }] });
    case '/api/diagnostics/interface/search_ndp/':
      return json(res, 200, { rows: [] });
    // Snapshots (rollback point).
    case '/api/core/snapshots/is_supported':
      return json(res, 200, true);
    case '/api/core/snapshots/add':
      return json(res, 200, { uuid: 'snap-uuid-1' });
    // WireGuard.
    case '/api/wireguard/server/list_servers':
      return json(res, 200, { rows: [] });
    case '/api/wireguard/client/get':
      return json(res, 200, { rows: [] });
    case '/api/wireguard/server/add_server':
      return json(res, 200, { uuid: 'server-uuid-A' });
    case '/api/wireguard/client/add_client_builder':
      return json(res, 200, { uuid: 'peer-uuid-1' });
    case '/api/wireguard/service/reconfigure':
      return json(res, 200, {});
    default:
      // Unknown endpoint → 404 (plugin treats as ok:false).
      return json(res, 404, { error: 'not found' });
  }
});

// --- Test helpers ----------------------------------------------------------------------

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra) : '');
  }
}

async function main(): Promise<void> {
  await new Promise<void>((r) => mock.listen(MOCK_PORT, () => r()));
  console.log(`[smoke] mock appliance on :${MOCK_PORT}`);

  // Boot the real plugin (index.ts calls app.listen on PORT).
  process.env.PORT = String(PLUGIN_PORT);
  await import('./src/index');
  await new Promise((r) => setTimeout(r, 300));
  console.log(`[smoke] plugin on :${PLUGIN_PORT}`);

  // --- /discover -----------------------------------------------------------------------
  const disc = (await (await fetch(`${BASE}/discover`)).json()) as Record<string, unknown>;
  const actions = (disc.actions ?? []) as { id: string; deviceCount: number | 'N' }[];
  console.log('\n== /discover ==');
  check('actions catalog non-empty', Array.isArray(actions) && actions.length > 20, `count=${actions.length}`);
  check('multi-device intent present', actions.some((a) => a.id === 'wireguard.tunnel.create' && a.deviceCount === 'N'));
  const opts = (disc.options ?? []) as { key: string }[];
  check('new options advertised', ['editionOverride', 'dnsBackend', 'dhcpBackend'].every((k) => opts.some((o) => o.key === k)));

  // --- /plan (wireguard tunnel, CE devices) ---------------------------------------------
  const planBody = {
    intent: { actionId: 'wireguard.tunnel.create', inputs: { name: 't1', subnet: '10.255.0.0/24' } },
    devices: [
      { deviceId: 'devA', managementAddress: `http://localhost:${MOCK_PORT}`, credentials: { apiKey: 'kA', apiSecret: 'sA' } },
      { deviceId: 'devB', managementAddress: `http://localhost:${MOCK_PORT}`, credentials: { apiKey: 'kB', apiSecret: 'sB' } },
    ],
  };
  const planRes = await fetch(`${BASE}/plan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(planBody) });
  const planJson = (await planRes.json()) as { plan?: { provisionRequests: { ref: string; type: string }[]; steps: { stepIndex: number; deviceId: string; actionId: string; dependsOn?: number[]; bestEffort?: boolean; input: Record<string, unknown> }[] } };
  console.log('\n== /plan wireguard.tunnel.create ==');
  check('HTTP 200', planRes.status === 200);
  const plan = planJson.plan!;
  check('two provisionRequests (keyA/keyB)', plan.provisionRequests.length === 2 && plan.provisionRequests.every((p) => p.type === 'wireguardKeyPair'), plan.provisionRequests);
  // Expect: [snapA(bestEffort), snapB(bestEffort), A.server, B.server, A.peer(dep serverA), B.peer(dep serverB), A.reconf, B.reconf]
  check('8 steps total', plan.steps.length === 8, `got ${plan.steps.length}`);
  const byId = (id: string) => plan.steps.filter((s) => s.actionId === id);
  check('2 best-effort snapshot.create prepended', byId('snapshot.create').length === 2 && byId('snapshot.create').every((s) => s.bestEffort));
  const serverA = plan.steps.find((s) => s.deviceId === 'devA' && s.actionId === 'wireguard.server.set')!;
  const peerA = plan.steps.find((s) => s.deviceId === 'devA' && s.actionId === 'wireguard.peer.add')!;
  check('peer A depends on server A', peerA.dependsOn?.includes(serverA.stepIndex), { peer: peerA.dependsOn, server: serverA.stepIndex });
  check('no key material in plan output', JSON.stringify(plan).length > 0 && !/privateKey|publicKey/.test(JSON.stringify(plan)));

  // --- /config (read action) -------------------------------------------------------------
  const cfgRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `http://localhost:${MOCK_PORT}`, apiKey: 'kA', apiSecret: 'sA', actionId: 'wireguard.servers.read', input: {} }),
  });
  const cfgJson = (await cfgRes.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config wireguard.servers.read ==');
  check('HTTP 200 + success true', cfgRes.status === 200 && cfgJson.success === true, cfgJson);

  // --- /config (unknown action) -----------------------------------------------------------
  const badRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ managementAddress: `http://localhost:${MOCK_PORT}`, apiKey: 'k', apiSecret: 's', actionId: 'nope.nope', input: {} }),
  });
  const badJson = (await badRes.json()) as { success?: boolean };
  check('unknown action → success:false', badRes.status === 400 && badJson.success === false, badJson);

  // --- /monitoring --------------------------------------------------------------------------
  const monRes = await fetch(`${BASE}/monitoring`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `http://localhost:${MOCK_PORT}`, apiKey: 'kA', apiSecret: 'sA' }),
  });
  const monJson = (await monRes.json()) as { health?: string; metrics?: Record<string, unknown> };
  console.log('\n== /monitoring ==');
  check('health ok', monJson.health === 'ok', monJson.health);
  check('cpu.percent collected', typeof monJson.metrics?.['cpu.percent'] === 'number', monJson.metrics?.['cpu.percent']);
  check('memory.percent computed', typeof monJson.metrics?.['memory.percent'] === 'number');

  console.log(failures === 0 ? '\nALL SMOKE TESTS PASSED' : `\n${failures} SMOKE TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('[smoke] fatal:', err);
  process.exit(1);
});
