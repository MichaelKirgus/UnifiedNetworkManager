/**
 * @unm/plugin-test-kit — standard IF-MIB / SNMPv2-MIB profile for generic-snmp.
 *
 * Unlike the LANCOM profiles (column-first `<table>.1.<col>.<idx>`), generic-snmp
 * walks the STANDARD MIBs with the usual `<table>.<field>.<ifIndex>` layout:
 *   - SNMPv2-MIB system group (.1.3.6.1.2.1.1) — scalar instances at `.0`;
 *   - IF-MIB ifTable (.1.3.6.1.2.1.2.2.1) + ifXTable (.1.3.6.1.2.1.31.1.1.1).
 * Health 'ok' needs the system group (sysDescr/sysName present) and ≥1 interface
 * row; a dead target yields 'critical'.
 */

/** A MAC as a raw 6-byte Buffer (normalizeMac() accepts Buffers). */
const mac = (hex) => ({ type: 'str', data: Buffer.from(hex, 'hex') });

export function genericSnmpMib() {
  const SYS = '.1.3.6.1.2.1.1'; // SNMPv2-MIB system group
  const IF = '.1.3.6.1.2.1.2.2.1'; // ifTable
  return [
    // System group (scalar instances carry a trailing ".0").
    { oid: `${SYS}.1.0`, value: { type: 'str', data: 'generic-snmp test device' } }, // sysDescr
    { oid: `${SYS}.2.0`, value: { type: 'str', data: '.1.3.6.1.4.1.9999' } }, // sysObjectID (OID-as-string)
    { oid: `${SYS}.3.0`, value: { type: 'int', data: 86_400_00 } }, // sysUpTime (timeticks, 1/100 s = 24h)
    { oid: `${SYS}.5.0`, value: { type: 'str', data: 'generic-snmp' } }, // sysName
    // One interface row (ifIndex 2): ifDescr + ifType + ifSpeed + MAC + operStatus up.
    { oid: `${IF}.2.2`, value: { type: 'str', data: 'eth0' } }, // ifDescr
    { oid: `${IF}.3.2`, value: { type: 'int', data: 6 } }, // ifType ethernetCsmacd
    { oid: `${IF}.5.2`, value: { type: 'int', data: 1_000_000_000 } }, // ifSpeed (bits/s)
    { oid: `${IF}.6.2`, value: mac('001122334455') }, // ifPhysAddress
    { oid: `${IF}.8.2`, value: { type: 'int', data: 1 } }, // ifOperStatus up
    { oid: `${IF}.10.2`, value: { type: 'int', data: 1_000_000 } }, // ifInOctets (32-bit counter)
    { oid: `${IF}.16.2`, value: { type: 'int', data: 2_000_000 } }, // ifOutOctets
  ];
}
