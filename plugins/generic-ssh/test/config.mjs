/**
 * Test config for plugins/generic-ssh — see packages/plugin-test-kit README.
 * T4 target: an in-process mock SSH appliance (ssh2 Server) that accepts any
 * password auth and answers exec channels with canned output, including the
 * marker-batched live-metrics script (meminfo/loadavg/stat/counters/date/tz).
 * Health 'ok' needs at least one of cpu.percent / memory.total — the meminfo
 * section supplies memory.total. The privilege probe (`id -u` → 0) runs first and
 * is answered so no sudo wrapping occurs.
 */

export default {
  async setup({ startSshMock, getDeadTcpPort }) {
    const ssh = await startSshMock();
    return {
      mocks: [ssh],
      config: {
        monitoringAddress: '127.0.0.1', // bare host — port comes from settings.sshPort
        settings: { sshPort: ssh.port },
        settingsForDead: { sshPort: await getDeadTcpPort() }, // closed → refused → critical
        credentials: { username: 'root', password: 'test-ssh-pass' },
        collectInventory: false, // live batch alone yields health ok; skip the slow inventory
        expectHealth: 'ok',
        // A dead target with creds bound can NEVER be critical here: collectMonitoring
        // unconditionally emits system.privilege (a stored field), so metrics is always
        // non-empty → floor is 'warning' ("answers SSH but yields no /proc data"). Only a
        // MISSING credential yields critical. Assert the real contract, not an idealized one.
        expectDeadHealth: 'warning',
        extraChecks: async ({ rec }) => {
          const cmds = ssh.requests.join('\n');
          rec.check('X', 'mock received the privilege probe (id -u)', /(^|\n)id -u/.test(cmds), `execs=${ssh.requests.length}`);
          rec.check('X', 'mock received a marker-batched live-metrics exec', cmds.includes('UNM_SECTION:'), `execs=${ssh.requests.length}`);
        },
      },
    };
  },
};
