/**
 * Test config for plugins/openwrt — see packages/plugin-test-kit README.
 * T4 target: a plain-HTTP mock LuCI (session flow: stok → login SID → ubus).
 * `transport:'luci'` forces the HTTP backend (no SSH); an explicit `http://`
 * address makes the resolver emit that single candidate verbatim, so the plugin
 * never wastes time on an https attempt. Health is 'ok' once any metric lands —
 * the system.board ubus probe alone suffices.
 */

export default {
  async setup({ startOpenwrtMock, getDeadTcpPort }) {
    const ap = await startOpenwrtMock();
    return {
      mocks: [ap],
      config: {
        monitoringAddress: `http://127.0.0.1:${ap.port}`,
        settings: { transport: 'luci' },
        // T5 polls with settingsForDead (NOT settings) — force the same luci mode so a
        // dead target deterministically throws → critical (auto mode degrades gracefully).
        settingsForDead: { transport: 'luci' },
        credentials: { username: 'root', password: 'test-openwrt-pass' },
        collectInventory: false, // board probe + traffic counters yield health ok; skip inventory
        expectHealth: 'ok',
        expectDeadHealth: 'critical',
        // openwrt caches transport state per BARE HOST (port stripped) for 5 min,
        // so a dead target on the same host would reuse T4's live session. Use a
        // distinct loopback IP with a closed port to exercise real failure handling.
        deadAddress: `127.0.0.2:${await getDeadTcpPort()}`,
        extraChecks: async ({ rec }) => {
          const ubus = ap.requests.filter((q) => q.url.startsWith('/ubus/'));
          rec.check('X', 'mock received a LuCI /ubus/ call (system.board probe)', ubus.length > 0, `requests=${ap.requests.length}`);
        },
      },
    };
  },
};
