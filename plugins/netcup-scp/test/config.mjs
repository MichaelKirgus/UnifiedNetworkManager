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

    // CPU metrics time series — { "<ISO minute>": { "CPU<n>": <ns of CPU-time per s wall> } }.
    // Latest point: CPU0 = 5e8 (50%), CPU1 = 1e9 (100%) → mean 7.5e8 → cpuPct 75, vcpus 2.
    if (req.method === 'GET' && url.includes('/metrics/cpu')) {
      const id = Number(url.split('?')[0].split('/')[4]);
      if (id !== 1) return send(404, { code: 'error.not.found', message: `server ${id} not found` });
      return send(200, {
        '2026-01-01T00:00:00Z': { CPU0: 1e8, CPU1: 1e8 },
        '2026-01-01T00:01:00Z': { CPU0: 5e8, CPU1: 1e9 },
      });
    }

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

          // --- Generic vms[]/vmHosts[] emission (feeds UNM's VMs + Hosts pages). ---
          const vmRes = await fetch(`${url}/monitoring`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ deviceId: 'vms-check-device', managementAddress: `http://127.0.0.1:${ap.port}`, credentials: { apiKey: 'test-scp-token' } }),
          });
          const vmMon = await vmRes.json().catch(() => ({}));
          const vms = Array.isArray(vmMon.metrics?.vms) ? vmMon.metrics.vms : null;
          rec.check('X', 'monitoring emits generic vms[] rows', vms !== null && vms.length === 1, `vms=${JSON.stringify(vms ?? [])}`);
          if (vms?.[0]) {
            const row = vms[0];
            rec.check(
              'X',
              'vm row carries state/vcpus/memory + NIC device child row',
              row.name === 'vm-test' && row.state === 'RUNNING' && row.vcpus === 2 && row.memoryMiB === 4096
                && Array.isArray(row.extra?.devices) && row.extra.devices[0]?.dtype === 'NIC' && row.extra.devices[0]?.label === 'aa:bb:cc:dd:ee:01',
              JSON.stringify(row),
            );
          }
          const vmHosts = Array.isArray(vmMon.metrics?.vmHosts) ? vmMon.metrics.vmHosts : null;
          rec.check(
            'X',
            'monitoring emits vmHosts[] with MAC + live IP (RUNNING only)',
            vmHosts !== null && vmHosts.length === 1 && vmHosts[0].mac === 'aa:bb:cc:dd:ee:01' && vmHosts[0].ip === '192.168.10.5' && vmHosts[0].hostname === 'vm-test',
            JSON.stringify(vmHosts ?? []),
          );

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

          // --- Live CPU probe (capability 'probe' → VMs page CPU column). ---
          const cpuCallsBefore = ap.requests.filter((q) => q.url.includes('/metrics/cpu')).length;
          const probeRes = await fetch(`${url}/probe`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              deviceId: 'probe-check-device',
              managementAddress: `http://127.0.0.1:${ap.port}`,
              credentials: { apiKey: 'test-scp-token' },
              keys: ['vmStats'],
            }),
          });
          const probe = await probeRes.json().catch(() => ({}));
          rec.check('X', 'POST /probe → 200 with collectedAt + metrics', probeRes.status === 200 && typeof probe.collectedAt === 'string' && probe.metrics !== undefined, `status=${probeRes.status} body=${JSON.stringify(probe).slice(0, 300)}`);
          rec.check('X', 'probe serves vmStates as an (empty) object so the webapp keeps vmStats', probe.metrics?.vmStates !== null && typeof probe.metrics.vmStates === 'object' && Object.keys(probe.metrics.vmStates).length === 0, `vmStates=${JSON.stringify(probe.metrics?.vmStates ?? null)}`);
          const vmStat = probe.metrics?.vmStats?.['vm-test'];
          // Latest mock point: (5e8 + 1e9)/2 = 7.5e8 ns/s → 75% of allocated cores, 2 vCPUs.
          rec.check('X', 'probe vmStats carries cpuPct (mean over vCPUs ÷ 1e9) + vcpus', vmStat?.cpuPct === 75 && vmStat?.vcpus === 2, `vm-test=${JSON.stringify(vmStat ?? null)} all=${JSON.stringify(probe.metrics?.vmStats ?? {})}`);
          rec.check('X', 'probe hit the mock metrics/cpu endpoint', ap.requests.filter((q) => q.url.includes('/metrics/cpu')).length > cpuCallsBefore, `cpuCalls before=${cpuCallsBefore} after=${ap.requests.length}`);

          // A second probe within the 15 s TTL must be served from cache — no new netcup calls.
          const totalBefore = ap.requests.length;
          await fetch(`${url}/probe`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              deviceId: 'probe-check-device',
              managementAddress: `http://127.0.0.1:${ap.port}`,
              credentials: { apiKey: 'test-scp-token' },
              keys: ['vmStats'],
            }),
          });
          rec.check('X', 'second probe within TTL served from cache (no new netcup calls)', ap.requests.length === totalBefore, `requests before=${totalBefore} after=${ap.requests.length}`);

          // Unknown-only key list → 502 with an error (nothing supported requested).
          const badProbe = await fetch(`${url}/probe`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              deviceId: 'probe-check-device',
              managementAddress: `http://127.0.0.1:${ap.port}`,
              credentials: { apiKey: 'test-scp-token' },
              keys: ['nope'],
            }),
          });
          const badBody = await badProbe.json().catch(() => ({}));
          rec.check('X', 'probe with only unknown keys → 502 + error', badProbe.status === 502 && typeof badBody.error === 'string' && badBody.error.includes('No supported probe keys'), `status=${badProbe.status} body=${JSON.stringify(badBody)}`);
        },
      },
    };
  },
};
