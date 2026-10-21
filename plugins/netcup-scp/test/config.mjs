/**
 * Test config for plugins/netcup-scp — see packages/plugin-test-kit README.
 * T4 target: a plain-HTTP mock of the netcup SCP REST API (ping, server list +
 * detail with live info/interfaces, tasks). The mock is self-contained here
 * because the test kit has no shared SCP appliance yet.
 */

import http from 'node:http';

/** Minimal in-process SCP API mock — just enough for /monitoring to go green. */
export async function startScpMock() {
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push({ method: req.method, url: req.url });
    const send = (status, body) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };

    if (req.method === 'GET' && req.url === '/api/ping') return send(200, '"OK"');

    if (req.method === 'GET' && req.url.startsWith('/api/v1/servers/')) {
      // Strip the query string (?loadServerLiveInfo=true) before parsing the id.
      const pathOnly = req.url.split('?')[0];
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

    if (req.method === 'GET' && req.url.startsWith('/api/v1/servers')) {
      return send(200, [{ id: 1, name: 'vm-test', hostname: 'vm-test.example.com', nickname: 'Test VM', disabled: false }]);
    }

    if (req.method === 'GET' && req.url.startsWith('/api/v1/tasks')) {
      // No tasks → resolveUserId() returns null → firewall policy reads are skipped.
      return send(200, []);
    }

    if (req.method === 'GET' && req.url.includes('/interfaces')) {
      return send(200, [
        { mac: 'AA:BB:CC:DD:EE:01', driver: 'virtio', speedInMBits: 1000, ipv4Addresses: [{ id: 10, ip: '192.168.10.5', netmask: '255.255.255.0' }], ipv6Addresses: [] },
      ]);
    }

    return send(404, { code: 'error.not.found', message: `no mock route for ${req.method} ${req.url}` });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  return {
    name: 'scp-mock',
    port,
    requests,
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
        credentials: { apiKey: 'test-scp-token' }, // Bearer token (apiKeyNoSecret)
        expectHealth: 'ok',
        deadAddress: `http://127.0.0.1:${getDeadTcpPort()}`,
        expectDeadHealth: 'critical',
        extraChecks: async ({ rec }) => {
          const pings = ap.requests.filter((q) => q.url === '/api/ping');
          rec.check('X', 'mock received /api/ping probe(s)', pings.length > 0, `requests=${ap.requests.length}`);
          const serverList = ap.requests.filter((q) => q.method === 'GET' && q.url.startsWith('/api/v1/servers') && !q.url.includes('/interfaces'));
          rec.check('X', 'mock received server list + detail reads', serverList.length >= 2, `requests=${serverList.length}`);
        },
      },
    };
  },
};
