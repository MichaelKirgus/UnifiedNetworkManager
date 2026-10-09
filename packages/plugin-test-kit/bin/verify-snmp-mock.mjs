/**
 * Standalone verification of the pure-JS SNMP v2c agent mock against the REAL
 * @unm/snmp-client (net-snmp). Proves:
 *   1. snmpGet returns exact scalar values;
 *   2. snmpWalkMulti over N subtrees of DIFFERENT lengths returns every entry,
 *      with no cross-cursor leakage and correct EOM termination (multi-PDU).
 * Run: node packages/plugin-test-kit/bin/verify-snmp-mock.mjs
 */
import { startSnmpMock } from '../src/mocks/snmpMock.js';
import { snmpGet, snmpWalkMulti } from '../../snmp-client/dist/index.js';

const creds = { version: 'v2c', community: 'public' };
// `port` MUST point at the mock's ephemeral socket — createSession defaults to 161.
let opts; // set after startSnmpMock (needs the port)

// Two subtrees of different lengths + scalars OUTSIDE both (must never leak in).
const mib = [
  // subtree A (.1.3.6.1.4.1.2356.11.1.50) — 3 rows, cols .1/.2
  { oid: '.1.3.6.1.4.1.2356.11.1.50.1.1', value: { type: 'int', data: 1 } },
  { oid: '.1.3.6.1.4.1.2356.11.1.50.1.2', value: { type: 'str', data: 'LAN-1' } },
  { oid: '.1.3.6.1.4.1.2356.11.1.50.2.1', value: { type: 'int', data: 2 } },
  // subtree B (.1.3.6.1.4.1.2356.11.1.51) — 1 row (shorter than A)
  { oid: '.1.3.6.1.4.1.2356.11.1.51.1.1', value: { type: 'int', data: 7 } },
  // scalar OUTSIDE both subtrees, BEFORE A in OID order (leak trap) — .49 < .50
  { oid: '.1.3.6.1.4.1.2356.11.1.49', value: { type: 'str', data: 'BEFORE' } },
  // scalar OUTSIDE both, after B (leak trap) — .52 > .51
  { oid: '.1.3.6.1.4.1.2356.11.1.52.0', value: { type: 'str', data: 'AFTER' } },
];

const mock = await startSnmpMock({ mib });
opts = { timeoutMs: 1500, retries: 1, maxRepetitions: 4, port: mock.port }; // small maxReps → forces multi-PDU
let pass = 0, fail = 0;
function check(label, cond, detail) {
  if (cond) { pass++; console.log('  ok   ' + label); }
  else { fail++; console.log('  FAIL ' + label + (detail ? ' — ' + detail : '')); }
}

try {
  // ── 1. snmpGet ────────────────────────────────────────────────
  const g = await snmpGet(mock.host, creds, ['.1.3.6.1.4.1.2356.11.1.50.1.1', '.1.3.6.1.4.1.2356.11.1.99'], opts);
  check('get: scalar value', g.get('.1.3.6.1.4.1.2356.11.1.50.1.1') === 1, `got ${g.get('.1.3.6.1.4.1.2356.11.1.50.1.1')}`);
  check('get: missing OID filtered', !g.has('.1.3.6.1.4.1.2356.11.1.99'));

  // ── 2. snmpWalkMulti (two subtrees, different lengths) ────────
  const bases = ['.1.3.6.1.4.1.2356.11.1.50', '.1.3.6.1.4.1.2356.11.1.51'];
  const w = await snmpWalkMulti(mock.host, creds, bases, opts);

  check('walk: A row .1.1', w.get('.1.3.6.1.4.1.2356.11.1.50.1.1') === 1);
  check('walk: A row .1.2 (str)', w.get('.1.3.6.1.4.1.2356.11.1.50.1.2') === 'LAN-1');
  check('walk: A row .2.1', w.get('.1.3.6.1.4.1.2356.11.1.50.2.1') === 2);
  check('walk: B row .1.1 (shorter subtree)', w.get('.1.3.6.1.4.1.2356.11.1.51.1.1') === 7);

  // Leak traps — entries outside the two subtrees must NOT appear.
  check('walk: no leak (.49 before A)', !w.has('.1.3.6.1.4.1.2356.11.1.49'));
  check('walk: no leak (.52.0 after B)', !w.has('.1.3.6.1.4.1.2356.11.1.52.0'));

  // Exactly the 4 in-subtree entries, nothing else.
  const keys = [...w.keys()].sort();
  check('walk: exactly 4 entries', keys.length === 4, `got ${keys.length}: ${keys.join(', ')}`);

  console.log(`\n${fail === 0 ? 'ALL PASS' : fail + ' FAILED'} (${pass} ok)`);
} finally {
  await mock.stop();
}
process.exit(fail === 0 ? 0 : 1);
