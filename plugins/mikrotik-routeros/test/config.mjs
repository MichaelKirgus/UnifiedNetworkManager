/**
 * Test config for plugins/mikrotik-routeros — see packages/plugin-test-kit README.
 * T4 target: a plain-HTTP mock RouterOS REST appliance (Basic auth). The address is
 * passed with an explicit `http://` scheme so the client's candidate list uses it
 * verbatim (a bare host would resolve HTTPS-first and never reach the plain-HTTP
 * mock). Health 'ok' needs the probe gate (`/rest/system/resource`) to return a
 * non-empty row AND at least one interface or an identity; unreachable → critical.
 */

export default {
  async setup({ startRouterOsMock, getDeadTcpPort }) {
    const ap = await startRouterOsMock();
    return {
      mocks: [ap],
      config: {
        monitoringAddress: `http://127.0.0.1:${ap.port}`,
        credentials: { username: 'admin', password: '' }, // empty password is legitimate on RouterOS
        collectInventory: false, // the live batch alone yields health ok; skip the slow inventory walk
        expectHealth: 'ok',
        // Default dead target (127.0.0.1:<closed-port>) → both HTTPS/HTTP candidates
        // refused → RouterOsUnreachableError → critical. No explicit deadAddress needed.
        expectDeadHealth: 'critical',
        extraChecks: async ({ rec }) => {
          const resource = ap.requests.filter((q) => q.url.startsWith('/rest/system/resource'));
          rec.check('X', 'mock received the /rest/system/resource probe gate', resource.length > 0, `requests=${ap.requests.length}`);
          const iface = ap.requests.filter((q) => q.url.startsWith('/rest/interface'));
          rec.check('X', 'mock received the /rest/interface inventory call', iface.length > 0, `requests=${ap.requests.length}`);
        },
      },
    };
  },
};
