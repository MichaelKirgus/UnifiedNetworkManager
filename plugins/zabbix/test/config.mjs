/**
 * Test config for plugins/zabbix — see packages/plugin-test-kit README.
 * T4 target: a plain-HTTP mock Zabbix JSON-RPC endpoint at /zabbix/api_jsonrpc.php.
 * Explicit `http://` scheme so the SDK resolver uses it verbatim (default basePath
 * is `/zabbix`). Health is decisive on apiinfo.version; host.get/problem.get are
 * best-effort (non-auth failure → warning only).
 */

export default {
  async setup({ startZabbixMock }) {
    const ap = await startZabbixMock();
    return {
      mocks: [ap],
      config: {
        monitoringAddress: `http://127.0.0.1:${ap.port}`,
        credentials: { apiKey: 'test-zabbix-token' }, // Bearer token mode
        collectInventory: false,
        expectHealth: 'ok',
        expectDeadHealth: 'critical',
        extraChecks: async ({ rec }) => {
          const posts = ap.requests.filter((q) => q.method === 'POST' && q.url.startsWith('/zabbix/api_jsonrpc.php'));
          rec.check('X', 'mock received JSON-RPC POST(s)', posts.length > 0, `requests=${ap.requests.length}`);
        },
      },
    };
  },
};
