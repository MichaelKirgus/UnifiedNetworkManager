/**
 * Test config for plugins/ix-truenas — see packages/plugin-test-kit README.
 * T4 target: a mock TrueNAS appliance speaking JSON-RPC 2.0 over WebSocket at
 * /api/current. `transport:'http'` forces plain ws:// (the mock is not TLS); the
 * explicit port in the address is preserved verbatim. Health 'ok' requires the
 * core trio to succeed: system.info → object, pool.query → array, alert.list → [].
 */

export default {
  async setup({ startTruenasMock }) {
    const ap = await startTruenasMock();
    return {
      mocks: [ap],
      config: {
        monitoringAddress: `http://127.0.0.1:${ap.port}`, // → ws://127.0.0.1:<port>/api/current
        settings: { transport: 'http' },
        credentials: { username: 'admin', password: 'test-truenas-pass' },
        collectInventory: false, // core trio decides health; skip the large inventory batch
        expectHealth: 'ok',
        expectDeadHealth: 'critical',
        extraChecks: async ({ rec }) => {
          const methods = ap.requests.join(',');
          for (const m of ['auth.login_ex', 'system.info', 'pool.query', 'alert.list']) {
            rec.check(`X`, `mock received ${m}`, methods.includes(m), `methods=${ap.requests.length}`);
          }
        },
      },
    };
  },
};
