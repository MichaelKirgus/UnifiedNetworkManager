/**
 * @unm/plugin-test-kit — plain-HTTP mock appliances for the REST-based plugins.
 *
 * Each `start*Mock()` boots a plain-HTTP server on an ephemeral 127.0.0.1 port,
 * speaks just enough of that appliance's API to make its `/monitoring` poll
 * report health 'ok', and records every request so suites can assert what the
 * plugin actually asked for. All bind ephemeral ports and expose
 * `{port, url, requests, stop()}` — same contract as httpMock/ntpMock/dockerMock.
 *
 * The plugins under test resolve a bare host to HTTPS-first (candidate[0]), so
 * each config forces plain HTTP via `x-unm-settings` (`transport:'http'`) or an
 * explicit `http://…` management address — no in-process TLS/cert generation is
 * needed, and the SDK pinning guard skips non-TLS endpoints entirely.
 */

import http from 'node:http';

/** Shared server factory: records requests, delegates routing to `handler`. */
function makeServer(handler) {
  const requests = [];
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      let data = '';
      req.on('data', (c) => (data += c));
      req.on('end', () => {
        requests.push({ method: req.method, url: req.url, headers: req.headers, body: data });
        if (requests.length > 500) requests.shift();
        try {
          handler(req, res, data);
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: String(err.message ?? err) }));
        }
      });
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        port,
        url: `http://127.0.0.1:${port}`,
        requests,
        stop: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}

function json(res, status, obj, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json', ...extraHeaders });
  res.end(body);
}

/**
 * OPNsense — Basic auth (apiKey/apiSecret). Health source is
 * `GET /api/core/system/status` → `{metadata:{system:{status:2}}}`. Every other
 * endpoint is best-effort and answered with an empty JSON object so the poll's
 * parallel calls resolve without sinking health.
 */
export function startOpnsenseMock() {
  return makeServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/api/core/system/status') {
      json(res, 200, { metadata: { system: { status: 2 } }, status: 'ok' });
      return;
    }
    // Best-effort endpoints — empty but well-formed so parsing never throws.
    if (u.pathname.startsWith('/api/')) {
      json(res, 200, {});
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end('{}');
  });
}

/**
 * mailcow — `X-API-Key` header. Decisive endpoint is
 * `GET /api/v1/get/status/version` → `{version:'<string>'}` (a missing version
 * on a reachable host is treated as an auth failure → critical). The three
 * inventory list endpoints answer with empty arrays.
 */
export function startMailcowMock() {
  return makeServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/api/v1/get/status/version') {
      json(res, 200, { version: '2025-09' });
      return;
    }
    // /get/domain/all, /get/mailbox/all, /get/alias/all → empty lists.
    if (u.pathname.startsWith('/api/v1/get/') && u.pathname.endsWith('/all')) {
      json(res, 200, []);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end('{}');
  });
}

/**
 * zabbix — JSON-RPC over POST to `<base>/zabbix/api_jsonrpc.php` (default
 * basePath `/zabbix`). Answers by `method`: apiinfo.version → version string,
 * host.get → one row, problem.get → []. Auth is Bearer-token or user.login; the
 * mock ignores auth and answers purely on method so either credential shape works.
 */
export function startZabbixMock() {
  return makeServer((req, res, body) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname !== '/zabbix/api_jsonrpc.php' || req.method !== 'POST') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end('{}');
      return;
    }
    let msg = {};
    try { msg = JSON.parse(body); } catch { /* malformed → error envelope */ }
    const id = msg.id ?? 1;
    const method = msg.method;
    if (method === 'apiinfo.version') json(res, 200, { jsonrpc: '2.0', id, result: '7.0.5' });
    else if (method === 'host.get') json(res, 200, { jsonrpc: '2.0', id, result: [{ hostid: '1', host: 'mock-host', name: 'Mock Host', status: '0' }] });
    else if (method === 'problem.get') json(res, 200, { jsonrpc: '2.0', id, result: [] });
    else if (method === 'user.login') json(res, 200, { jsonrpc: '2.0', id, result: 'mock-session-id' });
    else json(res, 200, { jsonrpc: '2.0', id, error: { code: -32601, message: `unknown method ${method}` } });
  });
}

/**
 * fbox (webui mode) — classic-UI session flow. `GET /login_sid.lua?username&password`
 * returns a SID cookie + `<SessionInfo><SID>…</SID>` XML; the health-relevant
 * endpoint is then `GET /systeminfo64.json` → JSON object. Other data endpoints
 * 404 (treated as absent, not a warning).
 */
export function startFboxMock() {
  const SID = '1234567890abcdef';
  return makeServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/login_sid.lua') {
      res.writeHead(200, {
        'Content-Type': 'text/xml',
        'Set-Cookie': `SID=${SID}; Path=/`,
      });
      res.end(`<SessionInfo><SID>${SID}</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>`);
      return;
    }
    if (u.pathname === '/systeminfo64.json') {
      json(res, 200, { name: 'mock-fritz', model: 'FRITZ!Box 4040', version: '07.78', uptime: 12345, temperature: 42 });
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end('{}');
  });
}

/**
 * openwrt (LuCI mode) — session flow: `GET /` serves a login page carrying the
 * stok CSRF token; the login POST sets a SID cookie; `POST /ubus/` answers the
 * `system.board` probe with one row, which alone yields health 'ok'.
 */
export function startOpenwrtMock() {
  const STOK = 'deadbeefcafebabe1234567890abcdef';
  return makeServer((req, res, body) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<html><head><meta name="csrf-token" content="${STOK}"></head><body>login</body></html>`);
      return;
    }
    if (u.pathname.includes('/admin/login') && req.method === 'POST') {
      res.writeHead(302, { 'Content-Type': 'text/html', 'Set-Cookie': `SID=mocksid123; Path=/`, Location: '/' });
      res.end('');
      return;
    }
    if (u.pathname === '/ubus/' && req.method === 'POST') {
      let msg = {};
      try { msg = JSON.parse(body); } catch { /* ignore */ }
      const id = msg.id ?? 1;
      // LuCI-only mode gets its ONLY live metric from traffic counters, so the
      // mock must answer the network.interface dump + per-interface status calls.
      if (msg.method === 'call' && msg.service === 'system') {
        json(res, 200, { result: [{ hostname: 'mock-openwrt', model: 'MockBox', board: 'x86/64', release: 'OpenWrt 23.05.0', revision: '', uptime: 123 }] });
        return;
      }
      if (msg.method === 'call' && msg.service === 'network' && msg.member === 'interface') {
        // `dump` → object keyed by interface name (array-wrapped — callUbus only
        // accepts array results); `@<name>` status → ibytes/obytes.
        if (msg.path === 'dump') {
          json(res, 200, { result: [{ lo: { name: 'lo' }, eth0: { name: 'eth0', proto: 'dhcp' } }] });
          return;
        }
        const m = String(msg.path ?? '').match(/^@(.+)$/);
        if (m) {
          json(res, 200, { result: [{ name: m[1], ibytes: 1_000_000, obytes: 500_000, up: true }] });
          return;
        }
      }
      json(res, 200, { result: [] });
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end('{}');
  });
}

/**
 * mikrotik-routeros — RouterOS REST API over plain HTTP + Basic auth. The client
 * prefixes every path with `/rest` (e.g. `GET /rest/system/resource`). Health is
 * 'ok' when the probe gate (`/system/resource`) returns a non-empty row AND at
 * least one interface or an identity is reported; unreachable/bad creds → critical.
 * RouterOS returns everything as strings, so numeric fields are stringified here.
 */
export function startRouterOsMock() {
  return makeServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (!u.pathname.startsWith('/rest/')) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end('{}');
      return;
    }
    const table = u.pathname.slice('/rest/'.length);
    switch (table) {
      case 'system/resource':
        json(res, 200, [{
          cpu: 'ARMv7 Processor rev v5l',
          'architecture-name': 'armv7l',
          'board-name': 'Mock hEX S',
          version: '7.14',
          'build-time': '2024-09-01T00:00:00Z',
          'cpu-load': '12',
          'free-memory': '67108864',
          'total-memory': '134217728',
          'free-disk-space': '536870912',
          'total-disk-space': '1073741824',
          uptime: '1d4h30m15s',
        }]);
        return;
      case 'system/identity':
        json(res, 200, [{ name: 'mock-routeros', identity: 'AA:BB:CC:DD:EE:FF' }]);
        return;
      case 'interface':
        json(res, 200, [
          { '.id': '*1', name: 'ether1', type: 'ether', running: 'true', disabled: 'false', mtu: '1500', mac_address: 'AA:BB:CC:DD:EE:FF', speed: '1G', 'rx-byytes': '123456789', 'tx-byytes': '98765432' },
          { '.id': '*2', name: 'bridge1', type: 'bridge', running: 'true', disabled: 'false', mtu: '1500', 'rx-byytes': '1000000', 'tx-byytes': '900000' },
        ]);
        return;
      case 'system/clock':
        json(res, 200, [{ date: '2024-09-02', time: '12:34:56', 'time-zone-name': 'Europe/Berlin' }]);
        return;
      default:
        // Best-effort tables (ip/address, arp, dhcp leases, routes, firewall…) —
        // empty arrays so the parallel batch resolves without sinking health.
        json(res, 200, []);
        return;
    }
  });
}
