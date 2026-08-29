/**
 * Smoke test for @unm/snmp-client's native transport + typed value contract.
 *
 * Boots net-snmp's own in-process agent on 127.0.0.1:16100 with a small MIB
 * (scalars incl. Counter64, binary MacAddress, RFC-2578 raw counter bytes,
 * Boolean + IpAddress, one table) and exercises snmpGet / snmpWalk / snmpSet
 * over v2c community AND v3 authPriv (SHA/AES), plus the negative paths
 * (unknown community → timeout, DES privacy rejection).
 *
 * Run from packages/snmp-client AFTER `npm run build`:  npm run smoke
 */
import * as snmp from 'net-snmp';
import { snmpGet, snmpSet, snmpWalk, snmpWalkMulti, SnmpCredentials } from './dist/index';

const HOST = '127.0.0.1';
const PORT = 16100;
const OPTS = { timeoutMs: 2_000, retries: 1, port: PORT };

const V2C: SnmpCredentials = { version: 'v2c', community: 'public' };
const V3_AES: SnmpCredentials = {
  version: 'v3',
  username: 'smoke',
  securityLevel: 'authPriv',
  authProtocol: 'SHA',
  authPassword: 'authpass123',
  privProtocol: 'AES',
  privPassword: 'privpass123',
};

let passed = 0;
let failed = 0;
function check(name: string, cond: boolean, detail?: unknown): void {
  if (cond) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    failed++;
    console.error(`  FAIL ${name}${detail !== undefined ? ` — ${JSON.stringify(detail)}` : ''}`);
  }
}

async function expectThrow(name: string, fn: () => Promise<unknown>, needle?: string): Promise<void> {
  try {
    await fn();
    check(name, false, 'did not throw');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    check(name, !needle || msg.includes(needle), msg);
  }
}

async function main(): Promise<void> {
  // --- in-process agent ------------------------------------------------------
  const agent = snmp.createAgent(
    { port: PORT, address: '127.0.0.1', accessControlModelType: snmp.AccessControlModelType.Simple },
    err => {
      if (err) console.error('[agent]', err.message);
    }
  );
  const authorizer = agent.getAuthorizer();
  const acm = authorizer.getAccessControlModel();
  authorizer.addCommunity('public');
  acm.setCommunityAccess('public', snmp.AccessLevel.ReadWrite);
  // authKey/privKey are PASSPHRASES on the agent side too (same RFC 3414 derivation).
  authorizer.addUser({
    name: 'smoke',
    level: snmp.SecurityLevel.authPriv,
    authProtocol: snmp.AuthProtocols.sha,
    authKey: 'authpass123',
    privProtocol: snmp.PrivProtocols.aes,
    privKey: 'privpass123',
  });
  acm.setUserAccess('smoke', snmp.AccessLevel.ReadWrite);

  agent.registerProvider({ name: 'sysDescr', type: snmp.MibProviderType.Scalar, oid: '1.3.6.1.2.1.1.1', scalarType: snmp.ObjectType.OctetString, maxAccess: snmp.MaxAccess['read-write'] });
  agent.registerProvider({ name: 'sysName', type: snmp.MibProviderType.Scalar, oid: '1.3.6.1.2.1.1.5', scalarType: snmp.ObjectType.OctetString, maxAccess: snmp.MaxAccess['read-write'] });
  agent.registerProvider({ name: 'bigCounter', type: snmp.MibProviderType.Scalar, oid: '1.3.6.1.4.1.99999.1', scalarType: snmp.ObjectType.Counter64, maxAccess: snmp.MaxAccess['read-only'] });
  agent.registerProvider({ name: 'dnsServer', type: snmp.MibProviderType.Scalar, oid: '1.3.6.1.4.1.99999.2', scalarType: snmp.ObjectType.IpAddress, maxAccess: snmp.MaxAccess['read-write'] });
  agent.registerProvider({ name: 'macAddr', type: snmp.MibProviderType.Scalar, oid: '1.3.6.1.4.1.99999.3', scalarType: snmp.ObjectType.OctetString, maxAccess: snmp.MaxAccess['read-only'] });
  // RFC-2578 Counter64 as a plain OCTET STRING (tag 0x04 + 8 non-printable
  // bytes — how real devices encode it; must decode to bigint).
  agent.registerProvider({ name: 'rawC64', type: snmp.MibProviderType.Scalar, oid: '1.3.6.1.4.1.99999.4', scalarType: snmp.ObjectType.OctetString, maxAccess: snmp.MaxAccess['read-only'] });
  // Printable 8-char OCTET STRING (ifAlias-shaped) — must stay a string,
  // NOT be mis-decoded as a Counter64.
  agent.registerProvider({ name: 'alias8', type: snmp.MibProviderType.Scalar, oid: '1.3.6.1.4.1.99999.5', scalarType: snmp.ObjectType.OctetString, maxAccess: snmp.MaxAccess['read-only'] });
  agent.registerProvider({ name: 'flagBool', type: snmp.MibProviderType.Scalar, oid: '1.3.6.1.4.1.99999.6', scalarType: snmp.ObjectType.Boolean, maxAccess: snmp.MaxAccess['read-only'] });
  agent.registerProvider({
    name: 'ifTable',
    type: snmp.MibProviderType.Table,
    oid: '1.3.6.1.2.1.2.2.1',
    maxAccess: snmp.MaxAccess['not-accessible'],
    tableColumns: [
      { number: 1, name: 'ifIndex', type: snmp.ObjectType.Integer, maxAccess: snmp.MaxAccess['read-only'] },
      { number: 2, name: 'ifDescr', type: snmp.ObjectType.OctetString, maxAccess: snmp.MaxAccess['read-write'], defVal: 'lo' },
      { number: 10, name: 'ifInOctets', type: snmp.ObjectType.Counter, maxAccess: snmp.MaxAccess['read-only'] },
    ],
    tableIndex: [{ columnName: 'ifIndex' }],
  });

  const mib = agent.getMib();
  mib.setScalarValue('sysDescr', 'UNM smoke-test agent');
  mib.setScalarValue('sysName', 'smoke-host');
  // Counter64 stored as an 8-byte big-endian buffer (5_000_000_000 > 2^32 — proves the 64-bit path).
  const c64 = Buffer.alloc(8);
  c64.writeBigUInt64BE(5_000_000_000n); // 0x0000012A05F200
  mib.setScalarValue('bigCounter', c64);
  mib.setScalarValue('dnsServer', '192.168.1.1');
  // Raw 6-byte MacAddress (binary OCTET STRING) — must come back as the raw
  // Buffer (plugins consume it via normalizeMac, which accepts Buffers).
  mib.setScalarValue('macAddr', Buffer.from('AABBCCDDEEFF', 'hex'));
  const RAW_C64 = 0x012a05f2n; // 8 bytes with a non-printable tail (0xF2)
  const rawC64Buf = Buffer.alloc(8);
  rawC64Buf.writeBigUInt64BE(RAW_C64);
  mib.setScalarValue('rawC64', rawC64Buf);
  mib.setScalarValue('alias8', 'abcdefgh');
  mib.setScalarValue('flagBool', true);
  mib.addTableRow('ifTable', [1, 'lo', 12345]);
  mib.addTableRow('ifTable', [2, 'eth0', 67890]);

  await new Promise(r => setTimeout(r, 200)); // let the UDP socket bind

  const cases: Array<[string, SnmpCredentials]> = [
    ['v2c community', V2C],
    ['v3 authPriv SHA/AES', V3_AES],
  ];

  for (const [label, creds] of cases) {
    console.log(`\n=== ${label} ===`);

    // Reset shared agent state mutated by the previous case's set operations.
    mib.setScalarValue('sysName', 'smoke-host');
    mib.setScalarValue('dnsServer', '192.168.1.1');

    // get: present + missing OIDs — scalars are addressed with a trailing ".0"
    const g = await snmpGet(HOST, creds, ['.1.3.6.1.2.1.1.1.0', '.1.3.6.1.4.1.99999.1.0', '.1.3.6.1.4.1.99999.2.0', '.1.3.6.1.4.1.99999.3.0', '.1.3.6.1.4.1.99999.4.0', '.1.3.6.1.4.1.99999.5.0', '.1.3.6.1.4.1.99999.6.0', '.1.3.6.1.4.1.777'], OPTS);
    check('get sysDescr (string)', g.get('.1.3.6.1.2.1.1.1.0') === 'UNM smoke-test agent', g.get('.1.3.6.1.2.1.1.1.0'));
    check('get Counter64 > 2^32 as bigint', g.get('.1.3.6.1.4.1.99999.1.0') === 5_000_000_000n, g.get('.1.3.6.1.4.1.99999.1.0'));
    check('get IpAddress dotted-quad', g.get('.1.3.6.1.4.1.99999.2.0') === '192.168.1.1', g.get('.1.3.6.1.4.1.99999.2.0'));
    check('get binary MacAddress as raw Buffer', (v => Buffer.isBuffer(v) && v.equals(Buffer.from('AABBCCDDEEFF', 'hex')))(g.get('.1.3.6.1.4.1.99999.3.0')), g.get('.1.3.6.1.4.1.99999.3.0'));
    check('get RFC-2578 8-byte OCTET STRING as bigint', g.get('.1.3.6.1.4.1.99999.4.0') === RAW_C64, g.get('.1.3.6.1.4.1.99999.4.0'));
    check('get printable 8-char OCTET STRING stays string', g.get('.1.3.6.1.4.1.99999.5.0') === 'abcdefgh', g.get('.1.3.6.1.4.1.99999.5.0'));
    check('get Boolean as boolean true', g.get('.1.3.6.1.4.1.99999.6.0') === true, g.get('.1.3.6.1.4.1.99999.6.0'));
    check('get missing OID absent (no throw)', !g.has('.1.3.6.1.4.1.777'), [...g.keys()]);

    // walk: system subtree only — ifTable (…2.2.1) must NOT leak in.
    // Scalars are instances, so the walked OID carries the trailing ".0".
    const w = await snmpWalk(HOST, creds, ['.1.3.6.1.2.1.1'], OPTS);
    check('walk returns sysDescr', w.get('.1.3.6.1.2.1.1.1.0') === 'UNM smoke-test agent', [...w.entries()]);
    check('walk stays inside subtree (no ifTable leak)', [...w.keys()].every(k => k.startsWith('.1.3.6.1.2.1.1.')), [...w.keys()]);

    // walk: table with 2 rows × 3 cols = 6 entries, Counter32 as number
    const wt = await snmpWalk(HOST, creds, ['.1.3.6.1.2.1.2.2.1'], OPTS);
    check('walk table entry count (2×3)', wt.size === 6, [...wt.entries()]);
    check('walk Counter32 value as number', wt.get('.1.3.6.1.2.1.2.2.1.10.1') === 12345, wt.get('.1.3.6.1.2.1.2.2.1.10.1'));

    // walk: non-existent subtree → empty map, no throw
    const we = await snmpWalk(HOST, creds, ['.1.3.6.1.4.1.777'], OPTS);
    check('walk missing subtree → empty', we.size === 0, [...we.entries()]);

    // walkMulti: two subtrees in one combined stream — merged map, no leak.
    const wm = await snmpWalkMulti(HOST, creds, ['.1.3.6.1.2.1.1', '.1.3.6.1.2.1.2.2.1'], OPTS);
    check('walkMulti merges both subtrees (2 scalars + 6 table cells)', wm.size === 8, [...wm.entries()]);
    check('walkMulti keeps values typed', wm.get('.1.3.6.1.2.1.1.1.0') === 'UNM smoke-test agent' && wm.get('.1.3.6.1.2.1.2.2.1.10.1') === 12345, [...wm.entries()]);
    check('walkMulti no cross-subtree leak', [...wm.keys()].every(k => k.startsWith('.1.3.6.1.2.1.1.') || k.startsWith('.1.3.6.1.2.1.2.2.1.')), [...wm.keys()]);

    // walkMulti: missing subtree contributes nothing, no throw.
    const wmMissing = await snmpWalkMulti(HOST, creds, ['.1.3.6.1.4.1.777', '.1.3.6.1.2.1.1'], OPTS);
    check('walkMulti missing subtree → only the real one (2 entries)', wmMissing.size === 2 && wmMissing.get('.1.3.6.1.2.1.1.5.0') !== undefined, [...wmMissing.entries()]);

    // walkMulti: low maxRepetitions still yields the full table.
    const wmLow = await snmpWalkMulti(HOST, creds, ['.1.3.6.1.2.1.2.2.1'], { ...OPTS, maxRepetitions: 2 });
    check('walkMulti maxRepetitions=2 still full table (6 entries)', wmLow.size === 6 && wmLow.get('.1.3.6.1.2.1.2.2.1.10.2') === 67890, [...wmLow.entries()]);

    // set: string + IpAddress, with echo and persistence re-read (scalar instance OIDs)
    const s1 = await snmpSet(HOST, creds, '.1.3.6.1.2.1.1.5.0', 's', 'changed-by-smoke', OPTS);
    check('set string echoed', s1 === 'changed-by-smoke', s1);
    const g2 = await snmpGet(HOST, creds, ['.1.3.6.1.2.1.1.5.0'], OPTS);
    check('set string persisted', g2.get('.1.3.6.1.2.1.1.5.0') === 'changed-by-smoke');
    const s2 = await snmpSet(HOST, creds, '.1.3.6.1.4.1.99999.2.0', 'a', '10.0.0.5', OPTS);
    check('set IpAddress echoed', s2 === '10.0.0.5', s2);
    const g3 = await snmpGet(HOST, creds, ['.1.3.6.1.4.1.99999.2.0'], OPTS);
    check('set IpAddress persisted', g3.get('.1.3.6.1.4.1.99999.2.0') === '10.0.0.5');
  }

  // set: table cell (string) via v2c
  const s3 = await snmpSet(HOST, V2C, '.1.3.6.1.2.1.2.2.1.2.1', 's', 'lo-renamed', OPTS);
  check('set table cell (string)', s3 === 'lo-renamed', s3);

  // walkMulti over v1 — no GetBulk, must fall back to sequential subtree walks.
  const wmV1 = await snmpWalkMulti(HOST, { version: 'v1', community: 'public' }, ['.1.3.6.1.2.1.1', '.1.3.6.1.2.1.2.2.1'], OPTS);
  check('walkMulti v1 fallback merges both subtrees (8 entries)', wmV1.size === 8 && wmV1.get('.1.3.6.1.2.1.2.2.1.10.1') === 12345, [...wmV1.entries()]);

  // negative paths
  await expectThrow('unknown community rejected (timeout)', () => snmpGet(HOST, { version: 'v2c', community: 'wrong' }, ['.1.3.6.1.2.1.1.1.0'], OPTS));
  await expectThrow(
    'DES privacy rejected with clear error',
    () => snmpGet(HOST, { ...V3_AES, privProtocol: 'DES' }, ['.1.3.6.1.2.1.1.1.0'], OPTS),
    'AES'
  );

  console.log(`\n${passed} passed, ${failed} failed`);
  agent.close();
  process.exit(failed ? 1 : 0);
}

main().catch(err => {
  console.error('smoke test crashed:', err);
  process.exit(1);
});
