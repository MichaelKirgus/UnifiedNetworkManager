/**
 * Test config for plugins/mailcow — see packages/plugin-test-kit README.
 * T4 target: a plain-HTTP mock mailcow (X-API-Key auth). Explicit `http://`
 * scheme so the SDK resolver uses it verbatim. Health is decisive on
 * GET /api/v1/get/status/version → {version:'<string>'}.
 */

export default {
  async setup({ startMailcowMock }) {
    const ap = await startMailcowMock();
    return {
      mocks: [ap],
      config: {
        monitoringAddress: `http://127.0.0.1:${ap.port}`,
        credentials: { apiKey: 'test-mailcow-key' },
        collectInventory: false, // version probe alone decides health; skip the list endpoints
        expectHealth: 'ok',
        expectDeadHealth: 'critical',
        extraChecks: async ({ rec }) => {
          const v = ap.requests.filter((q) => q.url.startsWith('/api/v1/get/status/version'));
          rec.check('X', 'mock received the /status/version liveness probe', v.length > 0, `requests=${ap.requests.length}`);
        },
      },
    };
  },
};
