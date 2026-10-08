/**
 * Test config for plugins/generic-http — see packages/plugin-test-kit README.
 * T4 target: a plain-HTTP mock on an ephemeral port, addressed with an explicit
 * scheme+port so the plugin probes EXACTLY that endpoint (a bare address would
 * also probe :443 and report warning). The setup() closure keeps the request
 * log for post-suite assertions.
 */

export default {
  async setup({ startHttpMock }) {
    const http = await startHttpMock({ body: { service: 'unm-test', status: 'up' } });
    return {
      mocks: [http],
      config: {
        monitoringAddress: `http://127.0.0.1:${http.port}`,
        expectHealth: 'ok',
        expectDeadHealth: 'critical', // nothing answers on the dead port → unreachable
        extraChecks: async ({ rec }) => {
          // T4 (and T3) already polled — prove the plugin actually hit the mock.
          const gets = http.requests.filter((q) => q.method === 'GET');
          rec.check('X', 'mock appliance received GET probe(s)', gets.length > 0, `requests=${http.requests.length}`);
        },
      },
    };
  },
};
