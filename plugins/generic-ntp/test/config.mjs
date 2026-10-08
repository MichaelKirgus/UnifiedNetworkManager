/**
 * Test config for plugins/generic-ntp — see packages/plugin-test-kit README.
 * T4 target: an in-process SNTP mock (RFC 1305 stratum-2 reply, current time).
 * The address carries an explicit port so the plugin queries exactly the mock.
 */

export default {
  async setup({ startNtpMock, getDeadUdpPort }) {
    const ntp = await startNtpMock();
    return {
      mocks: [ntp],
      config: {
        monitoringAddress: `127.0.0.1:${ntp.port}`,
        expectHealth: 'ok', // mock serves current time → no drift warning
        deadAddress: `127.0.0.1:${await getDeadUdpPort()}`,
        settingsForDead: { timeoutMs: 500 }, // keep the dead-target poll fast
        expectDeadHealth: 'critical',
      },
    };
  },
};
