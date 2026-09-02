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
  // Strip query strings — some endpoints are called with params (e.g. interfaces_info?details=true).
  const url = (req.url ?? '/').split('?')[0];
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
    // Inventory collection (Networks page): the REAL recordset shape from
    // searchRecordsetBase — assigned interfaces carry `config` + `identifier`,
    // addresses are CIDR strings, VLAN tags ride on the row. Unassigned
    // interfaces (no config) must NOT produce network rows.
    case '/api/interfaces/overview/interfaces_info':
      return json(res, 200, {
        total: 5,
        rows: [
          { identifier: 'lan', description: 'LAN', device: 'igb0', macaddr: 'aa:bb:cc:dd:ee:ff', status: 'up', ipv4: [{ ipaddr: '192.168.1.1/24' }], vlan_tag: null, config: { if: 'igb0', descr: 'LAN', enable: '1' } },
          { identifier: 'wan', description: 'WAN', device: 'igc0', macaddr: 'aa:bb:cc:dd:ee:0f', status: 'up', ipv4: [{ ipaddr: '10.0.0.2/24' }], vlan_tag: null, config: { if: 'igc0', descr: 'WAN', enable: '1' } },
          { identifier: 'opt1', description: 'Guests', device: 'vlan0.100', macaddr: 'aa:bb:cc:dd:ee:10', status: 'up', ipv4: [{ ipaddr: '192.168.100.1/24' }], vlan_tag: 100, config: { if: 'vlan0.100', descr: 'Guests', enable: '1' } },
          // Legacy entry shape (older firmware): separate address + dotted netmask.
          { name: 'legacy0', mac: 'aa:bb:cc:dd:ee:30', status: 'up', ipv4: { address: '172.16.5.1', netmask: '255.255.0.0' } },
          // Unassigned physical interface — must be skipped by the parser.
          { identifier: '', description: 'Unassigned Interface', device: 'igb1', macaddr: 'aa:bb:cc:dd:ee:20', status: 'down' },
        ],
      });
    case '/api/interfaces/vlan_settings/get':
      return json(res, 200, [{ interface: 'igb0', vlanid: 100, description: 'guests' }]);
    // Inventory collection (Hosts page): dnsmasq leases (mock runs dnsmasq backend).
    case '/api/dnsmasq/leases/search':
      return json(res, 200, {
        rows: [
          { mac: 'aa:bb:cc:dd:ee:01', ipaddress: '192.168.1.10', hostname: 'laptop-1', interface: 'lan', expires: Math.floor(Date.now() / 1000) + 3600 },
        ],
      });
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
  // Intents report their TRUE device count (2 for tunnels), not 'N'.
  check('multi-device intent present with exact count', actions.some((a) => a.id === 'wireguard.tunnel.create' && a.deviceCount === 2));
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

  // --- /monitoring inventory (networks + dhcpLeases) ------------------------------------
  const networks = (monJson.metrics?.['networks'] ?? []) as Record<string, unknown>[];
  // lan + wan + opt1 (assigned recordset rows) + legacy0 (legacy shape).
  // The unassigned interface must NOT produce a row.
  check('networks collected (assigned interfaces only)', Array.isArray(networks) && networks.length === 4, `count=${networks.length}`);
  const lanRow = networks.find((r) => r.name === 'lan');
  check('lan row parsed from CIDR string', lanRow?.ip === '192.168.1.1' && lanRow.prefix === 24 && lanRow.version === 'v4', lanRow);
  const wanRow = networks.find((r) => r.name === 'wan');
  check('wan row parsed from CIDR string', wanRow?.ip === '10.0.0.2' && wanRow.prefix === 24, wanRow);
  const vlanRow = networks.find((r) => r.name === 'opt1');
  check('vlan_tag carried as vlanId', vlanRow?.vlanId === 100, vlanRow);
  const legacyRow = networks.find((r) => r.name === 'legacy0');
  check('legacy shape (address+netmask) still parsed', legacyRow?.ip === '172.16.5.1' && legacyRow.prefix === 16, legacyRow);
  check('unassigned interface produces no row', !networks.some((r) => r.mac === 'aa:bb:cc:dd:ee:20'), networks.map((r) => r.name));

  const leases = (monJson.metrics?.['dhcpLeases'] ?? []) as Record<string, unknown>[];
  check('dhcpLeases collected', Array.isArray(leases) && leases.length >= 1, `count=${leases.length}`);
  const lease = leases[0];
  check('lease normalized (mac/ip/hostname/expiry ISO)', lease?.mac === 'aa:bb:cc:dd:ee:01' && lease.ip === '192.168.1.10' && lease.hostname === 'laptop-1' && typeof lease.expiry === 'string' && !Number.isNaN(Date.parse(lease.expiry as string)), lease);

  const descriptors = (monJson.metricDescriptors ?? []) as { key: string }[];
  check('networks descriptor present', descriptors.some((d) => d.key === 'networks'));
  check('dhcpLeases descriptor present', descriptors.some((d) => d.key === 'dhcpLeases'));

  // --- /state (device-state document for the Config page) ---------------------------
  const stateRes = await fetch(`${BASE}/state`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `http://localhost:${MOCK_PORT}`, credentials: { apiKey: 'kA', apiSecret: 'sA' } }),
  });
  const stateJson = (await stateRes.json()) as { collectedAt?: string; sections?: { id: string; label: string; items?: { key: string; title: string; status?: string; fields?: Record<string, unknown>; actions?: { actionId: string }[] }[]; actions?: { actionId: string }[] }[] };
  console.log('\n== /state ==');
  check('HTTP 200', stateRes.status === 200);
  check('collectedAt is ISO timestamp', typeof stateJson.collectedAt === 'string' && !Number.isNaN(Date.parse(stateJson.collectedAt!)), stateJson.collectedAt);
  const sectionIds = (stateJson.sections ?? []).map((s) => s.id);
  check('has interfaces + system sections', sectionIds.includes('interfaces') && sectionIds.includes('system'), sectionIds);
  const ifSection = (stateJson.sections ?? []).find((s) => s.id === 'interfaces');
  const lanItem = ifSection?.items?.find((i) => i.key === 'lan');
  check('lan interface item present with MAC + IPs', !!lanItem && lanItem.fields?.MAC === 'aa:bb:cc:dd:ee:ff' && Array.isArray(lanItem.fields?.IPs), lanItem);
  const sysSection = (stateJson.sections ?? []).find((s) => s.id === 'system');
  check('system item advertises reboot/halt/service actions', !!sysSection?.items?.[0]?.actions && ['system.reboot', 'system.halt', 'system.service.restart'].every((id) => sysSection.items![0].actions!.some((a) => a.actionId === id)), sysSection?.items?.[0]?.actions);

  console.log(failures === 0 ? '\nALL SMOKE TESTS PASSED' : `\n${failures} SMOKE TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('[smoke] fatal:', err);
  process.exit(1);
});
