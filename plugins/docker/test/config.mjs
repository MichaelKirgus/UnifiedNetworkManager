/**
 * Test config for plugins/docker — see packages/plugin-test-kit README.
 * T4 target: a mock Docker Engine API (plain TCP) on an ephemeral port; the
 * plugin is pinned to transport 'tcp' so it never tries TLS/socket paths.
 */

export default {
  async setup({ startDockerDaemonMock }) {
    const daemon = await startDockerDaemonMock();
    return {
      mocks: [daemon],
      config: {
        monitoringAddress: '127.0.0.1',
        settings: { transport: 'tcp', port: daemon.port },
        expectHealth: 'ok',
        // Dead target: same transport, closed port → connection refused.
        deadAddress: '127.0.0.1',
        settingsForDead: { transport: 'tcp', port: 1 }, // port 1 = nothing listens
        extraChecks: async ({ url, rec }) => {
          const r = await fetch(`${url}/monitoring`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-unm-settings': JSON.stringify({ transport: 'tcp', port: daemon.port }) },
            body: JSON.stringify({ deviceId: 'x', managementAddress: '127.0.0.1', credentials: {} }),
          });
          const j = await r.json();
          // The fixture daemon serves 3 containers: two in the "radius" compose
          // project (→ one App row) + one standalone redis (→ its own row). So the
          // plugin must emit exactly 2 container rows, both RUNNING. Images: all 4
          // fixture images survive buildImageRows (dangling ones named by short id).
          const containers = j.metrics?.containers;
          rec.check('X', 'containers[] ingested from mock (2 App rows)', Array.isArray(containers) && containers.length === 2, JSON.stringify(containers?.length));
          rec.check('X', 'docker.containers.running === 2', j.metrics?.['docker.containers.running'] === 2, JSON.stringify(j.metrics?.['docker.containers.running']));
          rec.check('X', 'images[] ingested from mock (4 rows)', Array.isArray(j.metrics?.images) && j.metrics.images.length === 4, JSON.stringify(j.metrics?.images?.length));
        },
      },
    };
  },
};
