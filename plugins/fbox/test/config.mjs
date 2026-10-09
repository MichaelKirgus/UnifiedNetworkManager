/**
 * Test config for plugins/fbox — see packages/plugin-test-kit README.
 * T4 target: a plain-HTTP mock FRITZ!Box (webui mode, classic-UI session flow).
 * fbox strips any scheme from the address and derives the base from `transport` +
 * `httpPort`, so we pass a bare host and force plain HTTP via settings. Health is
 * decisive on GET /systeminfo64.json after the /login_sid.lua SID handshake.
 */

export default {
  async setup({ startFboxMock }) {
    const ap = await startFboxMock();
    return {
      mocks: [ap],
      config: {
        monitoringAddress: '127.0.0.1', // bare host — fbox applies transport + httpPort below
        settings: { apiMode: 'webui', transport: 'http', httpPort: ap.port },
        credentials: { username: 'admin', password: 'test-fritz-pass' },
        collectInventory: false,
        expectHealth: 'ok',
        expectDeadHealth: 'critical',
        extraChecks: async ({ rec }) => {
          const login = ap.requests.filter((q) => q.url.startsWith('/login_sid.lua'));
          const sysinfo = ap.requests.filter((q) => q.url.startsWith('/systeminfo64.json'));
          rec.check('X', 'mock received the /login_sid.lua SID handshake', login.length > 0, `requests=${ap.requests.length}`);
          rec.check('X', 'mock received the /systeminfo64.json health probe', sysinfo.length > 0, `requests=${ap.requests.length}`);
        },
      },
    };
  },
};
