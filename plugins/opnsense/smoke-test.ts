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

/** Flips the mock between dnsmasq and Kea DHCP backends (the smoke test drives
 * both read paths against the same appliance). */
let mockDhcpBackend: 'dnsmasq' | 'kea' = 'dnsmasq';

/** Captured write payloads — assertions verify the plugin sends model-correct bodies. */
const capturedWrites: Record<string, unknown> = {};

function readBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve({}); } });
  });
}

const mock = http.createServer((req, res) => {
  // Strip query strings — some endpoints are called with params (e.g. interfaces_info?details=true).
  const url = (req.url ?? '/').split('?')[0];
  console.log(`[mock] ${req.method} ${url}`);

  // --- DHCP write surface (staged mutations) -----------------------------------
  if (url === '/api/kea/dhcpv4/add_reservation') {
    return void readBody(req).then((body) => { capturedWrites['keaAdd'] = body; json(res, 200, {}); });
  }
  const keaSetMatch = url.match(/^\/api\/kea\/dhcpv4\/set_reservation\/([^/]+)$/);
  if (keaSetMatch) {
    return void readBody(req).then((body) => { capturedWrites['keaSet'] = { uuid: decodeURIComponent(keaSetMatch[1]), body }; json(res, 200, {}); });
  }
  if (url === '/api/kea/dhcpv4/get_reservation/res-uuid-1') {
    // REAL firmware shape: the subnet relation comes back as a map
    // { <subnetUuid>: { value, selected } } — not a plain string.
    return json(res, 200, { reservation: {
      uuid: 'res-uuid-1',
      subnet: {
        'subnet-uuid-lan': { value: '192.168.1.0/24', selected: 1 },
        'subnet-uuid-other': { value: '10.0.0.0/24', selected: 0 },
      },
      hw_address: 'aa:bb:cc:dd:ee:99', ip_address: '192.168.1.10', hostname: 'printer',
    } });
  }
  if (url === '/api/services/dhcp/staticmap/add') {
    return void readBody(req).then((body) => { capturedWrites['dnsmasqAdd'] = body; json(res, 200, {}); });
  }
  const smDelMatch = url.match(/^\/api\/services\/dhcp\/staticmap\/del\/([^/]+)$/);
  if (smDelMatch) {
    return void readBody(req).then((body) => { capturedWrites['dnsmasqDel'] = { uuid: decodeURIComponent(smDelMatch[1]), body }; json(res, 200, {}); });
  }

  // Edition probe: CE → 403 (no opncentral/sync).
  if (url.startsWith('/api/opncentral/')) return json(res, 403, { error: 'forbidden' });
  // DNS backend probe: unbound not enabled → dnsmasq.
  if (url === '/api/unbound/overview/is_enabled') return json(res, 200, { enabled: false });
  // DHCP backend probe — driven by mockDhcpBackend so the smoke test can flip it.
  if (url === '/api/kea/service/status') return json(res, 200, { running: mockDhcpBackend === 'kea' });

  // --- Configured DHCP surface (DHCP page) — dnsmasq backend -------------------
  if (mockDhcpBackend === 'dnsmasq') {
    // Ranges: the real search_range recordset shape ({ interface, start_addr, end_addr, uuid }).
    if (url === '/api/dnsmasq/settings/search_range') return json(res, 200, { rows: [
      { uuid: 'range-uuid-lan', interface: 'lan', start_addr: '192.168.1.50', end_addr: '192.168.1.200' },
    ] });
    // Static maps (services/dhcp controller) — per-interface, uuid-keyed.
    if (url === '/api/services/dhcp/staticmap/search') return json(res, 200, { rows: [
      { uuid: 'sm-uuid-1', interface: 'lan', mac: 'AA:BB:CC:DD:EE:99', ipaddr: '192.168.1.10', hostname: 'printer' },
    ] });
  }

  // --- Configured DHCP surface (DHCP page) — Kea backend -----------------------
  if (mockDhcpBackend === 'kea') {
    // Current firmware: the full config carries NO subnets (only general/lexpire/ha).
    if (url === '/api/kea/dhcpv4/get') return json(res, 200, { dhcpv4: { general: { enabled: '1' }, lexpire: {}, ha: {} } });
    // Subnets live in the search_subnet recordset — pools is ONE "start-end" STRING.
    if (url === '/api/kea/dhcpv4/search_subnet') return json(res, 200, { rows: [
      { uuid: 'subnet-uuid-lan', subnet_id: '1', subnet: '192.168.1.0/24', pools: '192.168.1.50-192.168.1.200', description: 'LAN' },
    ] });
    // Kea reservations (search_reservation recordset) — hw_address/ip_address fields.
    if (url === '/api/kea/dhcpv4/search_reservation') return json(res, 200, { rows: [
      { uuid: 'res-uuid-1', subnet: 'subnet-uuid-lan', ip_address: '192.168.1.10', hw_address: 'AA:BB:CC:DD:EE:99', hostname: 'printer' },
    ] });
  }

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
    // --- Storage (mounted filesystems) — the ONLY storage endpoint OPNsense has.
    // Size fields are BASE-10 human strings exactly as systemDiskAction returns them.
    case '/api/diagnostics/system/system_disk/':
      return json(res, 200, { devices: [
        // ZFS root (the appliance's main pool) — surfaced as the top-level zfs-pool row.
        { device: 'zroot', type: 'zfs', blocks: '107G', used: '5.4G', available: '102G', used_pct: 5, mountpoint: '/' },
        // A UFS data partition mounted from a USB stick.
        { device: '/dev/da1p1', type: 'ufs', blocks: '32G', used: '8G', available: '24G', used_pct: 25, mountpoint: '/mnt/data' },
      ] });
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

  // Boot the real plugin (index.ts calls app.listen on PORT). Disable the
  // inventory cache: the test flips the mock's DHCP backend between two
  // /monitoring calls and each must re-collect.
  process.env.PORT = String(PLUGIN_PORT);
  process.env.UNM_NO_INVENTORY_CACHE = '1';
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
  check('peer A depends on server A', (peerA.dependsOn ?? []).includes(serverA.stepIndex), { peer: peerA.dependsOn, server: serverA.stepIndex });
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
  const monJson = (await monRes.json()) as { health?: string; metrics?: Record<string, unknown>; metricDescriptors?: unknown[] };
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

  // --- /monitoring DHCP config (dnsmasq backend — auto-detected) -----------------
  const dhcpNets = (monJson.metrics?.['dhcpNetworks'] ?? []) as Record<string, unknown>[];
  console.log('\n== /monitoring dhcpNetworks/dhcpReservations (dnsmasq) ==');
  check('dnsmasq range row parsed', Array.isArray(dhcpNets) && dhcpNets.length === 1, dhcpNets);
  const dn = dhcpNets[0];
  check('range carries interface + start/end + uuid refId', dn?.interface === 'lan' && dn.rangeStart === '192.168.1.50' && dn.rangeEnd === '192.168.1.200' && dn.refId === 'range-uuid-lan', dn);
  const dhcpRes = (monJson.metrics?.['dhcpReservations'] ?? []) as Record<string, unknown>[];
  check('dnsmasq staticmap row parsed', Array.isArray(dhcpRes) && dhcpRes.length === 1, dhcpRes);
  const dr = dhcpRes[0];
  check('staticmap normalized (mac lowercased + ip + interface + uuid)', dr?.mac === 'aa:bb:cc:dd:ee:99' && dr.ip === '192.168.1.10' && dr.interface === 'lan' && dr.refId === 'sm-uuid-1', dr);
  check('dhcpNetworks descriptor present', descriptors.some((d) => d.key === 'dhcpNetworks'));

  // --- /monitoring DHCP config (Kea backend — forced via the dhcpBackend option) --
  mockDhcpBackend = 'kea';
  const monKeaRes = await fetch(`${BASE}/monitoring`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-unm-settings': JSON.stringify({ dhcpBackend: 'kea' }) },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `http://localhost:${MOCK_PORT}`, apiKey: 'kA', apiSecret: 'sA' }),
  });
  const monKeaJson = (await monKeaRes.json()) as { health?: string; metrics?: Record<string, unknown> };
  console.log('\n== /monitoring dhcpNetworks/dhcpReservations (kea) ==');
  check('HTTP 200', monKeaRes.status === 200);
  const keaNets = (monKeaJson.metrics?.['dhcpNetworks'] ?? []) as Record<string, unknown>[];
  check('Kea subnet pool split into start/end', Array.isArray(keaNets) && keaNets.length === 1, keaNets);
  const kn = keaNets[0];
  // Real firmware shape: search_subnet recordset row (uuid + description + pools string).
  check('Kea row carries name/cidr/refId from the recordset', kn?.name === 'LAN' && kn.rangeStart === '192.168.1.50' && kn.rangeEnd === '192.168.1.200' && kn.cidr === '192.168.1.0/24' && kn.refId === 'subnet-uuid-lan', kn);
  const keaRes = (monKeaJson.metrics?.['dhcpReservations'] ?? []) as Record<string, unknown>[];
  check('Kea reservation row parsed', Array.isArray(keaRes) && keaRes.length === 1, keaRes);
  const kr = keaRes[0];
  // Real firmware shape: hw_address/ip_address fields (no interface on Kea rows).
  check('Kea reservation normalized (mac + ip + refId)', kr?.mac === 'aa:bb:cc:dd:ee:99' && kr.ip === '192.168.1.10' && kr.refId === 'res-uuid-1', kr);

  // --- /config DHCP writes (Kea backend — forced via the dhcpBackend option) ----
  console.log('\n== /config dhcp.staticMapping.add/set (kea) ==');
  const keaAddRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-unm-settings': JSON.stringify({ dhcpBackend: 'kea' }) },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `http://localhost:${MOCK_PORT}`, apiKey: 'kA', apiSecret: 'sA', actionId: 'dhcp.staticMapping.add', input: { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.50', hostname: 'laptop-1' } }),
  });
  const keaAddJson = (await keaAddRes.json()) as { success?: boolean };
  check('Kea add succeeds without interface', keaAddRes.status === 200 && keaAddJson.success === true, keaAddJson);
  // Model-correct payload under the `reservation` key (the controller reads
  // POST['reservation']) with hw_address/ip_address + the REQUIRED subnet
  // relation resolved from IP containment (192.168.1.50 ∈ 192.168.1.0/24 → subnet-uuid-lan).
  const keaAddItem = ((capturedWrites['keaAdd'] as { reservation?: Record<string, unknown> })?.reservation ?? {}) as Record<string, unknown>;
  check('Kea add payload uses model fields + resolved subnet', keaAddItem['hw_address'] === 'aa:bb:cc:dd:ee:01' && keaAddItem['ip_address'] === '192.168.1.50' && keaAddItem['hostname'] === 'laptop-1' && keaAddItem['subnet'] === 'subnet-uuid-lan', capturedWrites['keaAdd']);

  const keaSetRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-unm-settings': JSON.stringify({ dhcpBackend: 'kea' }) },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `http://localhost:${MOCK_PORT}`, apiKey: 'kA', apiSecret: 'sA', actionId: 'dhcp.staticMapping.set', input: { uuid: 'res-uuid-1', mac: 'aa:bb:cc:dd:ee:99', ip: '192.168.1.77' } }),
  });
  const keaSetJson = (await keaSetRes.json()) as { success?: boolean };
  check('Kea set succeeds', keaSetRes.status === 200 && keaSetJson.success === true, keaSetJson);
  // Same-subnet edit keeps the original subnet relation (no re-resolve needed).
  // The mock get_reservation returns the real-firmware relation-map shape — this
  // also proves the parser extracts the selected uuid from it.
  const keaSetCapture = capturedWrites['keaSet'] as { uuid?: string; body?: { reservation?: Record<string, unknown> } };
  check('Kea set targets the right uuid', keaSetCapture.uuid === 'res-uuid-1', capturedWrites['keaSet']);
  const keaSetItem = (keaSetCapture.body?.reservation ?? {}) as Record<string, unknown>;
  check('Kea set payload keeps subnet + new ip_address', keaSetItem['subnet'] === 'subnet-uuid-lan' && keaSetItem['ip_address'] === '192.168.1.77' && keaSetItem['hw_address'] === 'aa:bb:cc:dd:ee:99', capturedWrites['keaSet']);

  // --- /config DHCP writes (dnsmasq backend) ------------------------------------
  mockDhcpBackend = 'dnsmasq';
  console.log('\n== /config dhcp.staticMapping.add/set (dnsmasq) ==');
  const dmAddRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `http://localhost:${MOCK_PORT}`, apiKey: 'kA', apiSecret: 'sA', actionId: 'dhcp.staticMapping.add', input: { interface: 'lan', mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.1.51' } }),
  });
  const dmAddJson = (await dmAddRes.json()) as { success?: boolean };
  check('dnsmasq add succeeds with interface', dmAddRes.status === 200 && dmAddJson.success === true, dmAddJson);
  const dmAddBody = capturedWrites['dnsmasqAdd'] as Record<string, unknown>;
  check('dnsmasq add payload (interface/mac/ipaddr)', dmAddBody['interface'] === 'lan' && dmAddBody['mac'] === 'aa:bb:cc:dd:ee:02' && dmAddBody['ipaddr'] === '192.168.1.51', capturedWrites['dnsmasqAdd']);

  const dmNoIfaceRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `http://localhost:${MOCK_PORT}`, apiKey: 'kA', apiSecret: 'sA', actionId: 'dhcp.staticMapping.add', input: { mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.1.51' } }),
  });
  const dmNoIfaceJson = (await dmNoIfaceRes.json()) as { success?: boolean };
  check('dnsmasq add without interface fails cleanly', dmNoIfaceRes.status === 200 && dmNoIfaceJson.success === false, dmNoIfaceJson);

  const dmSetRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `http://localhost:${MOCK_PORT}`, apiKey: 'kA', apiSecret: 'sA', actionId: 'dhcp.staticMapping.set', input: { uuid: 'sm-uuid-1', mac: 'aa:bb:cc:dd:ee:99', ip: '192.168.1.77' } }),
  });
  const dmSetJson = (await dmSetRes.json()) as { success?: boolean };
  check('dnsmasq set succeeds (del+add emulation)', dmSetRes.status === 200 && dmSetJson.success === true, dmSetJson);
  // Emulation: del by uuid THEN re-add with the ORIGINAL interface preserved.
  const dmDelCapture = capturedWrites['dnsmasqDel'] as { uuid?: string };
  check('dnsmasq set deleted the original row', dmDelCapture.uuid === 'sm-uuid-1', capturedWrites['dnsmasqDel']);
  const dmSetAddBody = capturedWrites['dnsmasqAdd'] as Record<string, unknown>;
  check('dnsmasq re-add kept interface + new ipaddr', dmSetAddBody['interface'] === 'lan' && dmSetAddBody['mac'] === 'aa:bb:cc:dd:ee:99' && dmSetAddBody['ipaddr'] === '192.168.1.77', capturedWrites['dnsmasqAdd']);

  // --- /monitoring storage (mounted filesystems via system_disk) --------------
  const fsRows = (monJson.metrics?.['filesystems'] ?? []) as Record<string, unknown>[];
  console.log('\n== /monitoring storage ==');
  check('two mounted filesystems parsed', fsRows.length === 2, fsRows.map((r) => `${r.type}:${r.name}`));
  const zroot = fsRows.find((r) => r.name === 'zroot');
  // base-10: "107G" → 107e9 bytes; type zfs → surfaced as the top-level zfs-pool.
  check('zfs root → zfs-pool row with size/used/free', zroot?.type === 'zfs-pool' && (zroot.sizeBytes as number) === 107 * 1e9 && (zroot.usedBytes as number) === 5.4 * 1e9 && (zroot.freeBytes as number) === 102 * 1e9, zroot);
  check('zfs root mountpoint is /', zroot?.mountpoint === '/', zroot?.mountpoint);
  const data = fsRows.find((r) => r.name === '/dev/da1p1');
  check('ufs mount parsed (other type + base-10 sizes)', data?.type === 'other' && (data.sizeBytes as number) === 32 * 1e9 && (data.usedBytes as number) === 8 * 1e9, data);

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
