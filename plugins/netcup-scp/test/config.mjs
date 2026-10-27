/**
 * Test config for plugins/netcup-scp — see packages/plugin-test-kit README.
 * T4 target: a plain-HTTP mock of the netcup SCP REST API (ping, server list +
 * detail with live info/interfaces, tasks) PLUS the Keycloak token endpoint
 * (refresh-token exchange). The mock is self-contained here because the test
 * kit has no shared SCP appliance yet.
 */

import http from 'node:http';

/** Minimal in-process SCP API + OAuth2 mock — just enough for /monitoring to go green. */
export async function startScpMock() {
  const requests = [];
  let tokenIssuances = 0;
  const server = http.createServer((req, res) => {
    // The plugin normalizes a bare host to <host>/scp-core — accept both with and without the prefix.
    const url = (req.url ?? '').replace(/^\/scp-core/, '') || '/';
    requests.push({ method: req.method, url, auth: req.headers.authorization ?? '' });
    const send = (status, body) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };

    // Keycloak realm "scp" token endpoint — refresh-token exchange.
    if (req.method === 'POST' && url === '/realms/scp/protocol/openid-connect/token') {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        const params = new URLSearchParams(raw);
        if (params.get('grant_type') !== 'refresh_token' || !params.get('refresh_token')) {
          return send(400, { error: 'invalid_request', error_description: 'unsupported grant or missing refresh_token' });
        }
        tokenIssuances += 1;
        // Keycloak rotates the refresh token in the response — the plugin must keep using the original.
        return send(200, { access_token: `mock-access-${tokenIssuances}`, expires_in: 3600, refresh_token: 'rotated-should-be-ignored', token_type: 'Bearer' });
      });
      return;
    }

    if (req.method === 'GET' && url === '/api/ping') return send(200, '"OK"');

    if (req.method === 'GET' && url.startsWith('/api/v1/servers/')) {
      // Strip the query string (?loadServerLiveInfo=true) before parsing the id.
      const pathOnly = url.split('?')[0];
      const id = Number(pathOnly.split('/')[4]);
      if (id === 1) {
        return send(200, {
          id: 1,
          name: 'vm-test',
          hostname: 'vm-test.example.com',
          nickname: 'Test VM',
          disabled: false,
          serverLiveInfo: {
            state: 'RUNNING',
            autostart: true,
            cpuCount: 2,
            cpuMaxCount: 4,
            currentServerMemoryInMiB: 4096,
            maxServerMemoryInMiB: 8192,
            uptimeInSeconds: 3600,
            interfaces: [
              { mac: 'AA:BB:CC:DD:EE:01', driver: 'virtio', speedInMBits: 1000, ipv4Addresses: [{ id: 10, ip: '192.168.10.5', netmask: '255.255.255.0', gateway: '192.168.10.1' }], ipv6Addresses: [] },
            ],
          },
          ipv4Addresses: [{ id: 10, ip: '192.168.10.5', netmask: '255.255.255.0', gateway: '192.168.10.1' }],
          ipv6Addresses: [],
        });
      }
      return send(404, { code: 'error.not.found', message: `server ${id} not found` });
    }

    if (req.method === 'GET' && url.startsWith('/api/v1/servers')) {
      return send(200, [{ id: 1, name: 'vm-test', hostname: 'vm-test.example.com', nickname: 'Test VM', disabled: false }]);
    }

    if (req.method === 'GET' && url.startsWith('/api/v1/tasks')) {
      // No tasks → resolveUserId() returns null → firewall policy reads are skipped.
      return send(200, []);
    }

    if (req.method === 'GET' && url.includes('/interfaces')) {
      return send(200, [
        { mac: 'AA:BB:CC:DD:EE:01', driver: 'virtio', speedInMBits: 1000, ipv4Addresses: [{ id: 10, ip: '192.168.10.5', netmask: '255.255.255.0' }], ipv6Addresses: [] },
      ]);
    }

    return send(404, { code: 'error.not.found', message: `no mock route for ${req.method} ${url}` });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  return {
    name: 'scp-mock',
    port,
    requests,
    tokenIssuances: () => tokenIssuances,
    stop: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

export default {
  async setup({ getDeadTcpPort }) {
    const ap = await startScpMock();
    return {
      mocks: [ap],
      config: {
        monitoringAddress: `http://127.0.0.1:${ap.port}`,
        credentials: { apiKey: 'test-scp-token' }, // static Bearer token (apiKeyNoSecret) — T4 happy path
        expectHealth: 'ok',
        deadAddress: `http://127.0.0.1:${getDeadTcpPort()}`,
        expectDeadHealth: 'critical',
        extraChecks: async ({ url, rec }) => {
          const pings = ap.requests.filter((q) => q.url === '/api/ping');
          rec.check('X', 'mock received /api/ping probe(s)', pings.length > 0, `requests=${ap.requests.length}`);
          const serverList = ap.requests.filter((q) => q.method === 'GET' && q.url.startsWith('/api/v1/servers') && !q.url.includes('/interfaces'));
          rec.check('X', 'mock received server list + detail reads', serverList.length >= 2, `requests=${ap.requests.length}`);

          // --- Refresh-token mode: a second poll with an scpRefreshToken credential. ---
          const before = ap.requests.length;
          const monRes = await fetch(`${url}/monitoring`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              deviceId: 'refresh-test-device',
              managementAddress: `http://127.0.0.1:${ap.port}`,
              credentials: { refreshToken: 'mock-refresh-1' },
            }),
          });
          const mon = await monRes.json().catch(() => ({}));
          rec.check('X', 'refresh-token monitoring → health ok', mon.health === 'ok', `health=${mon.health} err=${JSON.stringify(mon.metrics?.['system.error'] ?? '')}`);

          const tokenCalls = ap.requests.filter((q) => q.url === '/realms/scp/protocol/openid-connect/token');
          rec.check('X', 'mock received refresh-token exchange(s)', tokenCalls.length >= 1, `tokenCalls=${tokenCalls.length}`);

          // The exchanged access token must be what the API calls carry (not the raw refresh token).
          const usedExchanged = ap.requests.slice(before).filter((q) => q.auth === 'Bearer mock-access-1');
          rec.check('X', 'API calls carried the EXCHANGED access token', usedExchanged.length > 0, `post-poll requests=${ap.requests.slice(before).map((r) => `${r.method} ${r.url} auth=${r.auth}`).join(', ')}`);

          // A second poll with the SAME refresh token must reuse the cached access token (no new exchange).
          const issuancesBefore = ap.tokenIssuances();
          await fetch(`${url}/monitoring`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              deviceId: 'refresh-test-device-2',
              managementAddress: `http://127.0.0.1:${ap.port}`,
              credentials: { refreshToken: 'mock-refresh-1' },
            }),
          });
          rec.check('X', 'cached access token reused (no re-exchange)', ap.tokenIssuances() === issuancesBefore, `issuances=${ap.tokenIssuances()} before=${issuancesBefore}`);

          // The refreshWindowSec option must flow through x-unm-settings into the client.
          const optRes = await fetch(`${url}/monitoring`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-unm-settings': JSON.stringify({ refreshWindowSec: 300 }) },
            body: JSON.stringify({
              deviceId: 'refresh-test-device-3',
              managementAddress: `http://127.0.0.1:${ap.port}`,
              credentials: { refreshToken: 'mock-refresh-1' },
            }),
          });
          const optMon = await optRes.json().catch(() => ({}));
          rec.check('X', 'refreshWindowSec option honored via x-unm-settings', optMon.activeSettings?.refreshWindowSec === 300, `activeSettings=${JSON.stringify(optMon.activeSettings ?? {})}`);
        },
      },
    };
  },
};
