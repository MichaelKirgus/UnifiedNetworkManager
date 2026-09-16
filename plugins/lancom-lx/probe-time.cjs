/**
 * One-off probe (SDK-based): verify the LANCOM-LX time OIDs on live APs using
 * @unm/snmp-client — the exact transport the plugin uses in production.
 * Community "public" for all four devices (confirmed via decrypted secrets).
 */
const { snmpGet } = require('@unm/snmp-client');

const L = '.1.3.6.1.4.1.2356.13';
const OIDS = [
  ['sysDescr', '.1.3.6.1.2.1.1.1.0'], // sanity check — proves the request itself works
  ['currentTime', `${L}.1.18.0`], // lcosLXStatusCurrentTime — OCTET STRING (SIZE(0..20))
  ['epoch', `${L}.1.19.0`], // lcosLXStatusCurrentTimeEpoch — Unsigned32
  ['offset', `${L}.1.20.0`], // lcosLXStatusCurrentTimeOffset — Integer32
  ['tzEnum', `${L}.2.14.20.0`], // lcosLXSetupTimeTimezone — INTEGER enum (IANA-ish)
];

const DEVICES = [
  { name: 'AP_Sideboard', host: '10.25.1.1', version: 'v1' },
  { name: 'AP_Wohnzimmer', host: '10.25.1.2', version: 'v1' },
  { name: 'AP_Zimmer_Michael', host: '10.25.1.3', version: 'v1' },
  { name: 'AP_Ralf', host: '10.28.1.1', version: 'v2c' },
];

const opts = { timeoutMs: 4000, retries: 1 };

function fmt(v) {
  if (typeof v === 'string') return `STRING: ${JSON.stringify(v)}`;
  if (typeof v === 'number') return `INTEGER: ${v}`;
  if (typeof v === 'bigint') return `COUNTER64: ${v.toString()}`;
  if (Buffer.isBuffer(v)) return `OCTET: hex=${v.toString('hex')} ascii=${JSON.stringify(v.toString('utf8'))}`;
  return `${typeof v}: ${String(v)}`;
}

(async () => {
  for (const d of DEVICES) {
    const creds = { version: d.version, community: 'public' };
    console.log(`\n=== ${d.name} (${d.host}) ${d.version}/"public"`);
    try {
      const res = await snmpGet(d.host, creds, OIDS.map(([, o]) => o), opts);
      for (const [label, oid] of OIDS) {
        const v = res.get(oid);
        console.log(`  ${label.padEnd(10)} ${oid} → ${v === undefined ? 'NO SUCH OBJECT' : fmt(v)}`);
      }
    } catch (e) {
      console.log(`  probe failed: ${e.message}`);
    }
  }
})();
