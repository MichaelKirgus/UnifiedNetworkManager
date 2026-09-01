/**
 * End-to-end smoke test for the MikroTik RouterOS plugin.
 *
 * Boots ONE MOCK RouterOS box (plain HTTP, real Basic-auth check) on :48761
 * with stateful interface counters (they increment per poll so throughput
 * rates become non-null), then boots the REAL plugin (src/index.ts on
 * PORT=48762) and exercises:
 *   - GET  /discover    → identity, capabilities, options (incl. schemeMode), models
 *   - POST /monitoring  → metrics + inventory keys; bad creds → critical;
 *                         unreachable → critical; auto-scheme fallback over an
 *                         HTTP-only box; pinned https against it → critical
 *   - in-process getMonitoring() → rate computation across two collections,
 *     stale-snapshot warning when the box goes away mid-flight
 */

import http from 'http';

const MOCK_PORT = 48761; // box A — happy path + in-process rate/stale tests
const MOCK2_PORT = 48763; // box B — scheme/auth/unreachable tests (fresh cache keys)
const PLUGIN_PORT = 48762;
const BASE = `http://localhost:${PLUGIN_PORT}`;
const DEAD_PORT = 49999; // nothing listens here → unreachable path

let passed = 0;
const failures: string[] = [];
function check(name: string, cond: boolean, detail?: unknown): void {
  if (cond) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failures.push(name);
    console.error(`  FAIL ${name}${detail !== undefined ? ` — ${JSON.stringify(detail)}` : ''}`);
  }
}
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// --- Mock RouterOS REST server -----------------------------------------------------------

interface MockState {
  trafficRx: number; // cumulative bytes added per /rest/interface poll
  trafficTx: number;
}

function makeRouterOsMock(port: number): http.Server & { state: MockState } {
  const state: MockState = { trafficRx: 0, trafficTx: 0 };
  const BASE_RX = 1_000_000_000; // starting cumulative counters (as if up for a while)
  const BASE_TX = 500_000_000;

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost:${port}`);
    const path = url.pathname.replace(/\/+$/, '');

    // Basic auth gate — same as a real RouterOS box.
    const expected = 'Basic ' + Buffer.from('admin:secret', 'utf8').toString('base64');
    if ((req.headers['authorization'] ?? '') !== expected) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 401, message: 'Unauthorized' }));
      return;
    }

    const json = (code: number, body: unknown): void => {
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    };

    switch (path) {
      case '/rest/system/resource':
        // Single-row table → one-element array (REST contract).
        json(200, [
          {
            '.id': '*1',
            version: '7.14',
            'build-time': 'May/20/2025 12:00:00',
            'architecture-name': 'x86_64',
            'board-name': 'CCR2004-1G-12S+2XS+',
            'cpu-load': '35', // string, percent
            'free-memory': '1500000000',
            'total-memory': '2000000000',
            uptime: '2d20h12m20s',
          },
        ]);
        return;

      case '/rest/system/identity':
        json(200, [{ '.id': '*1', name: 'router-mock' }]);
        return;

      case '/rest/interface':
        // Counters increment per poll → rates are non-null from the 2nd sample.
        state.trafficRx += 2_500_000;
        state.trafficTx += 1_250_000;
        json(200, [
          {
            '.id': '*1',
            name: 'ether1',
            type: 'ether',
            running: 'true',
            disabled: 'false',
            mtu: '1500',
            'mac-address': 'AA:BB:CC:DD:EE:01',
            speed: '1G',
            'rx-byytes': String(BASE_RX + state.trafficRx), // RouterOS spells it "byytes"
            'tx-byytes': String(BASE_TX + state.trafficTx),
          },
          { '.id': '*2', name: 'bridge1', type: 'bridge', running: 'true', disabled: 'false', mtu: '1476' },
          { '.id': '*3', name: 'vlan10', type: 'vlan', running: 'true', disabled: 'false', mtu: '1500' },
        ]);
        return;

      case '/rest/ip/address':
        json(200, [
          { '.id': '*1', address: '192.168.1.1/24', interface: 'ether1', network: '192.168.1.0' },
          { '.id': '*2', address: '10.0.0.1/30', interface: 'sfpplus1', network: '10.0.0.0' },
        ]);
        return;

      case '/rest/arp':
        json(200, [
          { '.id': '*1', 'mac-address': 'AA:BB:CC:DD:EE:99', address: '192.168.1.50', interface: 'ether1' },
        ]);
        return;

      case '/rest/ip/dhcp-server/lease':
        json(200, [
          {
            '.id': '*1',
            'mac-address': 'AA:BB:CC:DD:EE:77',
            address: '192.168.1.100',
            'host-name': 'laptop',
            'expires-after': '1d2h3m4s',
            interface: 'ether1',
          },
        ]);
        return;

      case '/rest/ip/route':
        json(200, [
          { '.id': '*1', 'dst-address': '0.0.0.0/0', gateway: '10.0.0.254', kind: 'static', distance: '1' },
          { '.id': '*2', 'dst-address': '192.168.1.0/24', kind: 'connected' },
        ]);
        return;

      case '/rest/interface/wifi/registration-table':
        // No WiFi on this box — 404 like a real non-WiFi RouterOS device.
        json(404, { error: 404, message: 'Not Found' });
        return;

      default:
        json(404, { error: 404, message: `no such command or directory (${path})` });
    }
  }) as http.Server & { state: MockState };
  (server as unknown as { state: MockState }).state = state;
  return server;
}

// --- Test run ------------------------------------------------------------------------------

async function main(): Promise<void> {
  const mock = makeRouterOsMock(MOCK_PORT);
  await new Promise<void>((r) => mock.listen(MOCK_PORT, () => r()));
  const mock2 = makeRouterOsMock(MOCK2_PORT);
  await new Promise<void>((r) => mock2.listen(MOCK2_PORT, () => r()));
  console.log(`mock RouterOS REST on :${MOCK_PORT} + :${MOCK2_PORT}`);

  // Boot the real plugin (src/index.ts listens on PORT).
  process.env.PORT = String(PLUGIN_PORT);
  await import('./src/index');
  await sleep(300); // let listen() settle

  // Same module instance the running server uses — lets us clear caches between
  // HTTP tests and drive getMonitoring() in-process for rate/stale checks.
  const { getMonitoring, clearMonitoringCache } = await import('./src/monitoring');

  const postMonitoring = async (body: Record<string, unknown>, settings?: Record<string, unknown>): Promise<Record<string, any>> => {
    const res = await fetch(`${BASE}/monitoring`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(settings ? { 'x-unm-settings': JSON.stringify(settings) } : {}) },
      body: JSON.stringify(body),
    });
    return (await res.json()) as Record<string, any>;
  };

  // --- /discover ---------------------------------------------------------------------------
  console.log('\n/discover');
  const disc = (await (await fetch(`${BASE}/discover`)).json()) as Record<string, any>;
  check('uuid is the RouterOS plugin uuid', disc.uuid === '00000000-0000-4000-8000-00000000000a', disc.uuid);
  check('name', disc.name === 'MikroTik RouterOS Plugin', disc.name);
  const caps: string[] = Array.isArray(disc.capabilities) ? disc.capabilities : [];
  check('capabilities include monitoring+inventory', caps.includes('monitoring') && caps.includes('inventory'), caps);
  check('configuration/planning NOT advertised yet (v0.1)', !caps.includes('configuration') && !caps.includes('planning'), caps);
  check('requiredSecretType usernamePassword', disc.requiredSecretType === 'usernamePassword', disc.requiredSecretType);
  const opts: Record<string, any>[] = Array.isArray(disc.options) ? disc.options : [];
  const schemeOpt = opts.find((o) => o.key === 'schemeMode');
  check('option schemeMode declared (default auto)', !!schemeOpt && schemeOpt.default === 'auto' && /auto/.test(schemeOpt.pattern ?? ''), schemeOpt);
  check('option insecureTls declared', opts.some((o) => o.key === 'insecureTls'));
  check('iconUrl advertised', disc.iconUrl === '/icons/routeros.svg', disc.iconUrl);
  const models: Record<string, any>[] = Array.isArray(disc.deviceModels) ? disc.deviceModels : [];
  check('deviceModels non-empty', models.length >= 8, models.length);
  check('all models suggest core layer', models.every((m) => m.defaultLayerId === 'core'));

  // Icon is served statically.
  const iconRes = await fetch(`${BASE}/icons/routeros.svg`);
  check('plugin icon served', iconRes.status === 200 && (await iconRes.text()).includes('<svg'), iconRes.status);

  // --- /monitoring happy path (pinned http — deterministic, no TLS noise) -------------------
  console.log('\n/monitoring (schemeMode=http)');
  const ok = await postMonitoring(
    { deviceId: 'dev-1', managementAddress: `localhost:${MOCK_PORT}`, credentials: { username: 'admin', password: 'secret' } },
    { schemeMode: 'http' }
  );
  check('health ok', ok.health === 'ok', ok);
  const m = (ok.metrics ?? {}) as Record<string, any>;
  check('system.version parsed', m['system.version'] === '7.14', m['system.version']);
  check('system.hostname from /system/identity', m['system.hostname'] === 'router-mock', m['system.hostname']);
  check('cpu load gauge value (string→number)', m['system.cpuLoad'] === 35, m['system.cpuLoad']);
  check('uptime parsed to seconds', m['system.uptime'] === 2 * 86_400 + 20 * 3_600 + 12 * 60 + 20, m['system.uptime']);
  check('memory used % computed', typeof m['system.memoryUsedPercent'] === 'number' && (m['system.memoryUsedPercent'] as number) > 0 && (m['system.memoryUsedPercent'] as number) < 100, m['system.memoryUsedPercent']);
  check('interfaces up count', m['router.interfacesUp'] === '3/3', m['router.interfacesUp']);

  const ifaces: Record<string, any>[] = Array.isArray(m['router.interfaces']) ? m['router.interfaces'] : [];
  check('interface table has 3 rows', ifaces.length === 3, ifaces);
  const ether1 = ifaces.find((i) => i.name === 'ether1');
  check('ether1 row: type/speed/mac/mtu', !!ether1 && ether1.type === 'ether' && ether1.speed === '1G' && ether1.macAddress === 'aa:bb:cc:dd:ee:01' && ether1.mtu === '1500', ether1);
  check('first poll → rates are "—" (no baseline yet)', ifaces.every((i) => i.rxRate === '—' && i.txRate === '—'), ifaces.map((i) => [i.name, i.rxRate]));
  check('aggregate throughput absent on first sample', m['router.rxThroughput'] === undefined);

  const addrs: Record<string, any>[] = Array.isArray(m['router.ipAddresses']) ? m['router.ipAddresses'] : [];
  check('ip address table (2 rows)', addrs.length === 2 && addrs.some((a) => a.address === '192.168.1.1/24'), addrs);

  // Inventory keys consumed by the API's ingestInventory().
  const networks: Record<string, any>[] = Array.isArray(m['networks']) ? m['networks'] : [];
  check('networks[] rows (ip+prefix)', networks.length === 2 && networks.some((n) => n.name === 'ether1' && n.ip === '192.168.1.1' && n.prefix === 24 && n.version === 'v4'), networks);
  const arp: Record<string, any>[] = Array.isArray(m['arp']) ? m['arp'] : [];
  check('arp[] row', arp.length === 1 && arp[0].mac === 'aa:bb:cc:dd:ee:99' && arp[0].ip === '192.168.1.50' && arp[0].intf === 'ether1', arp);
  const leases: Record<string, any>[] = Array.isArray(m['dhcpLeases']) ? m['dhcpLeases'] : [];
  check('dhcpLeases[] row (hostname + ISO expiry)', leases.length === 1 && leases[0].hostname === 'laptop' && typeof leases[0].expiry === 'string' && !Number.isNaN(Date.parse(leases[0].expiry)), leases);
  const routes: Record<string, any>[] = Array.isArray(m['routes']) ? m['routes'] : [];
  check('routes[] (static default + connected)', routes.length === 2 && routes.some((r) => r.destination === '0.0.0.0/0' && r.protocol === 'static' && r.gateway === '10.0.0.254') && routes.some((r) => r.destination === '192.168.1.0/24' && r.protocol === 'connected'), routes);
  check('wlanClients absent (no WiFi on box)', m['wlanClients'] === undefined, m['wlanClients']);

  // Descriptors cover every emitted metric key.
  const descKeys = new Set(((ok.metricDescriptors ?? []) as Record<string, any>[]).map((d) => d.key));
  check('descriptors cover system + summary metrics', ['system.version', 'system.hostname', 'system.cpuLoad', 'router.interfacesUp', 'router.interfaces'].every((k) => descKeys.has(k)), [...descKeys]);

  // Settings echo (API→plugin loop proof).
  const as = (ok.activeSettings ?? {}) as Record<string, any>;
  check('activeSettings echoes schemeMode + insecureTls', as.schemeMode === 'http' && as.insecureTls === false, as);

  // --- auth failure (box B — fresh key, real network call) ------------------------------------
  console.log('\n/monitoring (bad credentials)');
  const badAuth = await postMonitoring(
    { deviceId: 'dev-1', managementAddress: `localhost:${MOCK2_PORT}`, credentials: { username: 'admin', password: 'WRONG' } },
    { schemeMode: 'http' }
  );
  check('health critical on 401', badAuth.health === 'critical', badAuth);
  check('error mentions authentication', /authentication failed/i.test(String(badAuth.metrics?.['system.error'] ?? '')), badAuth.metrics?.['system.error']);

  // --- unreachable -----------------------------------------------------------------------------
  console.log('\n/monitoring (unreachable)');
  const dead = await postMonitoring(
    { deviceId: 'dev-2', managementAddress: `localhost:${DEAD_PORT}`, credentials: { username: 'admin', password: 'secret' } },
    { schemeMode: 'http' }
  );
  check('health critical when nothing listens', dead.health === 'critical', dead);

  // --- auto-scheme fallback (HTTPS first → HTTP) --------------------------------------------------
  console.log('\n/monitoring (schemeMode=auto over an HTTP-only box)');
  const auto = await postMonitoring(
    { deviceId: 'dev-1', managementAddress: `localhost:${MOCK2_PORT}`, credentials: { username: 'admin', password: 'secret' } },
    { schemeMode: 'auto' }
  );
  check('auto mode falls back to HTTP and succeeds', auto.health === 'ok', auto);

  // --- pinned https against an HTTP-only box must fail ---------------------------------------------
  console.log('\n/monitoring (schemeMode=https over an HTTP-only box)');
  clearMonitoringCache(); // the auto test above cached a good snapshot for this address — force a real HTTPS attempt
  const httpsOnly = await postMonitoring(
    { deviceId: 'dev-1', managementAddress: `localhost:${MOCK2_PORT}`, credentials: { username: 'admin', password: 'secret' } },
    { schemeMode: 'https' }
  );
  check('pinned https fails cleanly (critical)', httpsOnly.health === 'critical', httpsOnly);

  // --- in-process: rate computation + stale fallback -------------------------------------------------
  console.log('\nin-process getMonitoring (rates + stale)');
  clearMonitoringCache();
  const monOpts = { cacheTtlMs: 0, requestTimeoutMs: 4_000, insecureTls: false, schemeMode: 'http' as const }; // ttl 0 → always re-collect

  const first = await getMonitoring(`localhost:${MOCK_PORT}`, { username: 'admin', password: 'secret' }, monOpts);
  check('first collection: rates null (no baseline)', first.snapshot.totalRxBitsPerSec === null, first.snapshot.totalRxBitsPerSec);

  await sleep(1_200); // let the mock counters advance
  const second = await getMonitoring(`localhost:${MOCK_PORT}`, { username: 'admin', password: 'secret' }, monOpts);
  check('second collection: RX rate > 0 bits/s', (second.snapshot.totalRxBitsPerSec ?? -1) > 0, second.snapshot.totalRxBitsPerSec);
  check('second collection: TX rate > 0 bits/s', (second.snapshot.totalTxBitsPerSec ?? -1) > 0, second.snapshot.totalTxBitsPerSec);
  const etherRate = second.snapshot.interfaces.find((i) => i.name === 'ether1');
  check('per-interface RX rate present on ether1', (etherRate?.rxBitsPerSec ?? -1) > 0, etherRate?.rxBitsPerSec);

  // Kill box A → next collection must serve the stale snapshot with a warning.
  await new Promise<void>((r) => mock.close(() => r()));
  const stale = await getMonitoring(`localhost:${MOCK_PORT}`, { username: 'admin', password: 'secret' }, monOpts);
  check('stale flag set after box goes away', stale.stale === true, stale.error);
  check('stale snapshot still carries data', stale.snapshot.interfaces.length === 3, stale.snapshot.interfaces.length);

  // --- summary --------------------------------------------------------------------------------------
  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length > 0) {
    console.error('Failed checks:', failures.join('; '));
    process.exit(1);
  }
  process.exit(0);
}

main().catch((err) => {
  console.error('smoke test crashed:', err);
  process.exit(1);
});
