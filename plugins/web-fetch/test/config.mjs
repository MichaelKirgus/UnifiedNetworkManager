/**
 * Test config for plugins/web-fetch — see packages/plugin-test-kit README.
 * The plugin is a global egress service: /monitoring reports its own fetch
 * counters, so T5 (dead target) does not apply and no appliance mock is needed
 * in Phase 1. Its real work (POST /fetch against an external URL) is covered by
 * the API-level integration tests instead.
 */

export default {
  assumeCaps: ['monitoring'], // serves /monitoring but advertises only 'webFetch'
  monitoringAddress: '127.0.0.1',
  expectHealth: 'ok', // fresh process: zero fetch failures → ok
  skipDeadTarget: true,
};
