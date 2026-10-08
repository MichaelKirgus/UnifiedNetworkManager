/**
 * Test config for plugins/flow-collector — see packages/plugin-test-kit README.
 * The plugin is a UDP LISTENER (sFlow/NetFlow), not a device prober: /monitoring
 * reports the collector's own health, so T5 (dead target) does not apply and no
 * appliance mock is needed for Phase 1. Its sFlow socket binds SFLOW_PORT — we
 * give it an ephemeral one so parallel runs never collide.
 */

export default {
  async setup({ getDeadUdpPort }) {
    return {
      config: {
        env: { SFLOW_PORT: String(await getDeadUdpPort()) },
        assumeCaps: ['monitoring'], // serves /monitoring but advertises no capabilities
        monitoringAddress: '127.0.0.1',
        expectHealth: 'ok', // fresh collector: zero dropped tuples → ok
        skipDeadTarget: true,
      },
    };
  },
};
