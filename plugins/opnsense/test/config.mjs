/**
 * Test config for plugins/opnsense — see packages/plugin-test-kit README.
 * T4 target: a plain-HTTP mock OPNsense appliance (Basic auth). The address is
 * passed with an explicit `http://` scheme so the SDK resolver uses it verbatim
 * (a bare host would resolve HTTPS-first and never reach the plain-HTTP mock).
 * Health derives from GET /api/core/system/status → {metadata:{system:{status:2}}}.
 */

export default {
  async setup({ startOpnsenseMock }) {
    const ap = await startOpnsenseMock();
    return {
      mocks: [ap],
      config: {
        monitoringAddress: `http://127.0.0.1:${ap.port}`,
        credentials: { apiKey: 'test-key', apiSecret: 'test-secret' },
        collectInventory: false, // skip the slow inventory/security window — health comes from system.status
        expectHealth: 'ok',
        expectDeadHealth: 'critical',
        extraChecks: async ({ rec }) => {
          const status = ap.requests.filter((q) => q.url.startsWith('/api/core/system/status'));
          rec.check('X', 'mock received the /api/core/system/status health probe', status.length > 0, `requests=${ap.requests.length}`);
        },
      },
    };
  },
};
