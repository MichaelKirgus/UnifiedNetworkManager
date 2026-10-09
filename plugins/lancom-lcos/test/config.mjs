/**
 * Test config for plugins/lancom-lcos — see packages/plugin-test-kit README.
 * T4 target: a pure-JS SNMP v2c agent (RFC 3416 wire format) serving the LCOS
 * MIB profile. The address is a bare host — the SNMP port comes from settings
 * (snmpPort), never from the address. Health 'ok' needs the probe scalar
 * (swVersion), the quality-gate serial, and ≥1 LAN port row.
 */

import { lcosMib } from '../../../packages/plugin-test-kit/src/mocks/lancomMibs.js';

export default {
  async setup({ startSnmpMock, getDeadUdpPort }) {
    const snmp = await startSnmpMock({ mib: lcosMib() });
    return {
      mocks: [snmp],
      config: {
        monitoringAddress: '127.0.0.1', // bare host — port from settings.snmpPort
        deadAddress: '127.0.0.2', // distinct bare host — the snapshot cache is keyed by HOST (not port), so T5 must not reuse T4's cached live snapshot
        settings: { snmpPort: snmp.port, timeoutMs: 1500, retries: 1 },
        settingsForDead: { snmpPort: await getDeadUdpPort(), timeoutMs: 1000, retries: 0 }, // closed → fast fail
        credentials: { version: 'v2c', community: 'public' },
        collectInventory: false, // system scalars + LAN ports alone yield health ok; skip the slow inventory window
        expectHealth: 'ok',
        // A failed probe maps to 'unknown' (not 'critical') by design — the handler
        // can't tell "dead device" from "wrong device type", so it reports unknown.
        expectDeadHealth: 'unknown',
        extraChecks: async ({ rec }) => {
          const probe = snmp.requests.filter((r) => r.pdu === 'get');
          rec.check('X', 'mock received an SNMP GET (probe)', probe.length > 0, `requests=${snmp.requests.length}`);
          rec.check('X', 'mock received a GetBulk inventory walk', snmp.requests.some((r) => r.pdu === 'getbulk'), `requests=${snmp.requests.length}`);
        },
      },
    };
  },
};
