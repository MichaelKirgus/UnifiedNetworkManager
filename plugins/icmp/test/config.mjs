/**
 * Test config for plugins/icmp — see packages/plugin-test-kit README.
 * The plugin shells out to `ping`, so no appliance mock is needed: T4 targets
 * 127.0.0.1 (loopback always answers) and T5 targets a non-routable address in
 * the TEST-NET-1 range (RFC 5737 — guaranteed black hole, fast timeout).
 */

export default {
  monitoringAddress: '127.0.0.1',
  settings: { pingCount: 2, timeoutMs: 1000 }, // keep the suite fast
  expectHealth: 'ok',
  deadAddress: '192.0.2.1',
  settingsForDead: { pingCount: 2, timeoutMs: 500 },
  expectDeadHealth: 'critical', // 100% loss → critical per the plugin's mapping
};
