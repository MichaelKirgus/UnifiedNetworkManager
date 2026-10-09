/**
 * Test config for plugins/generic-snmp — see packages/plugin-test-kit README.
 * T4 target: a pure-JS SNMP v2c agent serving a standard IF-MIB / SNMPv2-MIB
 * profile (sysDescr/sysName + one ifTable row). The address is a bare host — the
 * SNMP port comes from settings (snmpPort), never from the address. Health 'ok'
 * needs the system group + ≥1 interface; a dead target yields 'critical'.
 */

import { genericSnmpMib } from '../../../packages/plugin-test-kit/src/mocks/standardIfMib.js';

export default {
  async setup({ startSnmpMock, getDeadUdpPort }) {
    const snmp = await startSnmpMock({ mib: genericSnmpMib() });
    return {
      mocks: [snmp],
      config: {
        monitoringAddress: '127.0.0.1', // bare host — port from settings.snmpPort
        deadAddress: '127.0.0.2', // distinct bare host — the snapshot cache is keyed by HOST (not port), so T5 must not reuse T4's cached live snapshot
        settings: { snmpPort: snmp.port, timeoutMs: 1500, retries: 1 },
        settingsForDead: { snmpPort: await getDeadUdpPort(), timeoutMs: 1000, retries: 0 }, // closed → fast fail
        credentials: { version: 'v2c', community: 'public' },
        expectHealth: 'ok',
        expectDeadHealth: 'critical',
        extraChecks: async ({ rec }) => {
          const walks = snmp.requests.filter((r) => r.pdu === 'getbulk');
          rec.check('X', 'mock received a GetBulk walk (system + ifTable)', walks.length >= 2, `requests=${snmp.requests.length}`);
        },
      },
    };
  },
};
