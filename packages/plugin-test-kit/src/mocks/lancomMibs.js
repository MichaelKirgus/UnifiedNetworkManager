/**
 * @unm/plugin-test-kit — LANCOM MIB profiles for the pure-JS SNMP v2c agent.
 *
 * Each `*Mib()` returns an array of `{ oid, value }` rows (the shape
 * startSnmpMock consumes) that is just rich enough to satisfy a plugin's T4
 * happy path: the probe scalar, the quality-gate serial, a device name, and at
 * least one port/radio row so the "no ports reported" warning never fires.
 *
 * Row addressing (LANCOM convention — see each plugin's *Oids.ts): tables are
 * COLUMN-FIRST, `<table>.1.<column>.<index…>`. Two index encodings:
 *   - text index ("LAN-1", "WLAN-1"): first sub-id = byte length, then one
 *     sub-id per character (ASCII code) — decoded by decodeSingleText().
 *   - integer index (SX4 ports): a single numeric sub-id.
 */

/** Encode a length-prefixed text index into its OID suffix ("LAN-1" → "5.76.65.78.45.49"). */
function textIndex(s) {
  const codes = [...s].map((c) => c.charCodeAt(0));
  return [codes.length, ...codes].join('.');
}

/** A MAC as a raw 6-byte Buffer (normalizeMac() accepts Buffers). */
const mac = (hex) => ({ type: 'str', data: Buffer.from(hex, 'hex') });

// ── LCOS router (base .1.3.6.1.4.1.2356.11) ───────────────────────────────────
export function lcosMib() {
  const B = '.1.3.6.1.4.1.2356.11';
  const lanIfc = textIndex('LAN-1'); // "5.76.65.78.45.49"
  return [
    // Probe scalar (getLcosInventory probe gate) + quality-gate serial.
    { oid: `${B}.1.47.9.0`, value: { type: 'str', data: '10.94.0327RU4' } }, // HW.swVersion
    { oid: `${B}.1.47.7.0`, value: { type: 'str', data: 'LCOS-SN-0001' } }, // HW.serialNumber
    { oid: `${B}.2.1.0`, value: { type: 'str', data: 'lcos-router' } }, // SYS.setupName (device name)
    // System scalars (cpu / memory — not health-gated, but keep the view realistic).
    { oid: `${B}.1.47.4.0`, value: { type: 'int', data: 512000 } }, // totalMemoryKbytes
    { oid: `${B}.1.47.5.0`, value: { type: 'int', data: 384000 } }, // freeMemoryKbytes
    { oid: `${B}.1.47.14.0`, value: { type: 'int', data: 23 } }, // cpuLoad60sPercent
    // One LAN port row (link up) — satisfies "no LAN ports or WAN interfaces" gate.
    { oid: `${B}.1.5.51.1.3.${lanIfc}`, value: { type: 'int', data: 1 } }, // COL_LINK_ACTIVE eYes
    { oid: `${B}.1.5.51.1.4.${lanIfc}`, value: { type: 'int', data: 0 } }, // COL_CONNECTOR
    { oid: `${B}.1.5.51.1.13.${lanIfc}`, value: mac('001122334455') }, // COL_MAC
  ];
}

// ── LCOS-SX switch, unified 4.x tree (base .1.3.6.1.4.1.2356.14) ───────────────
export function sx4Mib() {
  const B = '.1.3.6.1.4.1.2356.14';
  return [
    // Variant-detection probe (detectVariant probes this FIRST — must be present).
    { oid: `${B}.1.1.1.2.0`, value: { type: 'str', data: 'GS-3510XP' } }, // DETECT.sx4Model / SX4_SYS.model
    // Quality-gate serial + name + firmware (health gate needs name||fw + ≥1 port).
    { oid: `${B}.1.1.1.13.0`, value: { type: 'str', data: 'SX-SN-0001' } }, // SX4_SYS.serialNumber
    { oid: `${B}.1.1.1.6.0`, value: { type: 'str', data: 'sx-switch' } }, // SX4_SYS.name
    { oid: `${B}.1.1.1.10.0`, value: { type: 'str', data: 'v3.34.0326' } }, // SX4_SYS.firmwareVersion
    // One port row (integer index 1) — satisfies "no ports reported" gate.
    { oid: `${B}.2.1.1.1.2.1`, value: { type: 'str', data: 'Port 1' } }, // COL_DESCRIPTION
    { oid: `${B}.2.1.1.1.3.1`, value: { type: 'str', data: 'Up' } }, // COL_LINK
    { oid: `${B}.2.1.1.1.4.1`, value: { type: 'str', data: '1Gbps' } }, // COL_SPEED_STATUS
  ];
}

// ── LCOS-LX access point (base .1.3.6.1.4.1.2356.13) ───────────────────────────
export function lxMib() {
  const B = '.1.3.6.1.4.1.2356.13';
  const ethIfc = textIndex('ETH1'); // "4.69.84.72.49"
  return [
    // Probe scalar (snmpCollector probe gate) + quality-gate serial.
    { oid: `${B}.1.47.9.0`, value: { type: 'str', data: '7.14.0036RU1' } }, // HW.swVersion
    { oid: `${B}.1.47.7.0`, value: { type: 'str', data: 'LX-SN-0001' } }, // HW.serialNumber
    { oid: `${B}.2.1.0`, value: { type: 'str', data: 'lx-ap' } }, // SYS.setupName (device name)
    // One LAN port row (link up) — satisfies "no radios or LAN ports reported" gate.
    { oid: `${B}.1.5.99.1.2.${ethIfc}`, value: { type: 'int', data: 1 } }, // LAN_PORTS.linkActive
    { oid: `${B}.1.5.99.1.4.${ethIfc}`, value: mac('aabbccddeeff') }, // LAN_PORTS.macAddress
  ];
}
