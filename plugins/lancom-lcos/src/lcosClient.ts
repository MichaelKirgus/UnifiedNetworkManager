/**
 * LCOS unified-MIB collection for Lancom LCOS routers.
 *
 * Two tiers (mirrors the generic SNMP plugin and lancom-lx):
 *  - SLOW path: targeted parallel walks over exactly the subtrees we use,
 *    TTL-cached per host. A broad `11.1` walk is NOT viable — it drags in huge
 *    tables we never read (WLAN client translation tables, RADIUS logs, …) and
 *    would blow the API's 10s poll budget on a real router; the targeted set
 *    below completes in ~2-3s.
 *  - FAST path (every poll): byte-counter walks for LAN + WAN interfaces →
 *    rx/tx rates via per-host baseline deltas (reset/wrap ⇒ skip).
 *
 * The MIB is read-only here; the writable lcsSetup objects are used by the
 * config actions in src/actions/, never by this module. Sensitive config-mirror
 * fields (WPA keys, RADIUS secrets, admin hashes) are never walked — only the
 * status tables and a handful of non-secret setup scalars.
 */

import { SnmpCredentials, SnmpValue, TransportOptions, snmpGet, snmpWalkMulti, suffixOf, normalizeMac } from '@unm/snmp-client';
import { CounterTracker } from '@unm/plugin-sdk';
import {
  splitRow, decodeSingleText, decodePrefixedText, decodeIpIndex, decodeIpTextIndex, label, toInt, netmaskToPrefix,
  createSnapshotCaches, runSlowPath, accumulateRate, LcosLogSink, ProbeOutcome,
} from '@unm/lancom-shared';
import {
  LCOS_BASE, SYS, HW, FIRMWARE, LAN_IF, LAN_BYTES, WAN_BYTES, WAN_IP,
  NET_LIST, ARP, DHCP, VPN_CONN, IP_ROUTES, IP_CIDR_ROUTES, WLAN_NET, WLAN_RADIO, WLAN_STATION, TEMP_EXTREMES,
  IPV6_PREFIX, TIME, lcosTimezoneToMinutes,
} from './lcosOids';

/* ------------------------------------------------------------------ *
 * Options + result types
 * ------------------------------------------------------------------ */

export interface LcosOptions extends TransportOptions {
  /** How long the slow-path snapshot stays fresh. */
  inventoryTtlMs: number;
}

/** One LAN port from lcsStatusLanInterfacesTable (+ byte counters). */
export interface LcosLanPort {
  name: string; // "LAN-1" etc.
  linkUp: boolean | null;
  connectorLabel: string; // '1 Gbit FD' etc., '' when unknown
  mac: string; // '' when unavailable
}

/** One WAN IP row from lcsStatusWanIpAddressesIpv4Table. */
export interface LcosWanIp {
  peer: string; // "WAN" / "WAN-2" …
  typeLabel: string; // 'static' | 'dhcp' | 'ppp' | 'autoconfig'
  address: string;
  netmask: string;
  gateway: string;
}

/** One configured network from lcsStatusTcpIpNetworkListTable. */
export interface LcosNetwork {
  name: string; // "LAN" / "VLAN-10" …
  ip: string;
  prefix: number | null; // derived from netmask
  vlanId: number | null;
  ifcLabel: string; // 'LAN-1' etc., '' when unknown
}

/** One advertised/delegated IPv6 prefix from lcsStatusIpv6PrefixTable. */
export interface LcosIpv6Prefix {
  name: string; // network name, e.g. "NET_INTRANET"
  cidr: string; // full CIDR with prefix length, e.g. "fdf8:f53b:70e4:1::/64"
}

/** One ARP cache row. */
export interface LcosArpEntry {
  ip: string;
  mac: string;
  portLabel: string; // 'ETH-1' / 'WAN' …, '' when unknown
}

/** One active DHCP lease. */
export interface LcosDhcpLease {
  ip: string;
  mac: string;
  hostname: string; // '' when absent
  expirySeconds: number | null; // remaining lease time as reported by the agent
  networkName: string; // '' when absent
}

/** One active VPN connection. */
export interface LcosVpnConn {
  peer: string; // "IPSEC-1" …
  physConn: string;
  ikeType: string; // 'IKEv2' etc., '' when unknown
  cryptAlg: string; // 'AES-128' …, '' when unknown
  stateLabel: string; // 'connected' etc.
  modeLabel: string; // 'active' | 'passive'
  connTimeSeconds: number | null;
}

/** One radio from lcsStatusWlanRadiosTable (built-in radios only). */
export interface LcosRadio {
  ifc: string; // "WLAN-1" …
  bandLabel: string; // '2.4 GHz' / '5 GHz' / 'dual'
  channel: number | null;
  bandwidthMhz: number | null; // 20/40/80 — enum mapping verified live on GS hardware
  noiseFloorDbm: number | null;
  modemLoadPct: number | null;
  txPower: string; // DisplayString as reported, '' when unknown
  utilizationPct: number | null;
}

/** One SSID/network from lcsStatusWlanNetworksTable. */
export interface LcosSsid {
  ifc: string; // radio it is broadcast on
  name: string;
  operating: boolean | null;
  bssid: string; // '' when unavailable
  stations: number | null;
  vlanId: number | null;
}

/** One associated client from lcsStatusWlanStationTable. */
export interface LcosClient {
  mac: string; // normalized aa:bb:cc:dd:ee:ff
  ifc: string; // "WLAN-1" …, '' when unknown
  hostname: string; // DHCP name / 802.1X user, '' when absent
  ip4: string; // '' when not yet assigned
  ip6: string;
  signalDbm: number | null;
  txRateMbps: number | null;
  rxRateMbps: number | null;
  vlanId: number | null;
}

/** One temperature extreme (min or max) from the monitor table. */
export interface LcosTempExtreme {
  sensor: number; // 1-based sensor index derived from the type code
  kind: 'min' | 'max';
  valueTenthsC: number | null;
}

/** One entry of the router's active routing table (IPv4 only — no v6 table in the MIB). */
export interface LcosRoute {
  destination: string; // CIDR built from the ip + netmask columns
  gateway: string;     // '' = directly connected / unknown
  protocol: 'static' | 'connected' | 'rip' | 'bgp' | 'ospf' | 'other'; // mapped from the Type enum (or next-hop presence on the standard-table fallback)
  distance: number | null;
  metric: number | null;   // routing cost — only set by the ipCidrRouteTable fallback
  rtgTag: number | null;   // routing-table tag (0 = default table)
  peer: string;            // DisplayString peer/interface name, '' when unset
  rawTypeLabel: string;    // human label of the MIB Type value (for 'other' rows)
}

/** The full slow-path snapshot for one host. */
export interface LcosRouterSnapshot {
  collectedAt: number;
  isLancom: boolean; // false → device exposes no LCOS tree (wrong plugin target)
  system: {
    name: string;
    swVersion: string;
    serialNumber: string;
    modelNumber: string;
    cpuType: string;
    uptimeText: string; // DisplayString as reported ("3 days, 4 hours")
    systemDate: string; // device wall clock (DisplayString), '' when absent — Time page
    timezoneMinutes: number | null; // UTC offset in minutes from the lcsStatusTime enum
    cpuLoadPct: number | null;
    memoryTotalKb: number | null;
    memoryFreeKb: number | null;
    securityEngine: boolean | null;
    bootCause: string;
    featureWord: string;
  };
  firmwareModules: Array<{ module: string; version: string }>;
  lanPorts: LcosLanPort[];
  wanIps: LcosWanIp[];
  networks: LcosNetwork[];
  ipv6Prefixes: LcosIpv6Prefix[]; // advertised/delegated v6 prefixes (Status/IPv6) — sparse by design
  arp: LcosArpEntry[];
  dhcpLeases: LcosDhcpLease[];
  vpnConnections: LcosVpnConn[];
  radios: LcosRadio[];
  ssids: LcosSsid[];
  clients: LcosClient[];
  routes: LcosRoute[]; // active routing table — vendor table when present, else standard ipCidrRouteTable fallback
  temperatureExtremes: LcosTempExtreme[];
}

/* ------------------------------------------------------------------ *
 * Enum label maps (from the MIB's SYNTAX INTEGER value blocks)
 * ------------------------------------------------------------------ */

const LAN_CONNECTORS: Record<number, string> = {
  0: 'none', 1: '10bT', 2: 'FD-10bTx', 3: '100bTx', 4: 'FD-100bTx', 6: 'FD-1000bTx',
  8: '1000bTx', 9: 'FD-2.5GbTx', 10: 'FD-5GbTx', 11: 'FD-10GbTx', 70: 'FD-1000bF',
  72: '1000bF', 75: 'FD-10GbF', 255: 'power down',
};

/** WAN ifc index values are spaced per technology (eCh01=257, eModem=513, …). */
const WAN_IFC_NAMES: Record<number, string> = {
  257: 'CH-1', 258: 'CH-2', 259: 'CH-3', 260: 'CH-4', 513: 'MODEM', 514: 'EXT-2',
};

const ARP_PORTS: Record<number, string> = {
  0: '', 1: 'UPLINK', 2: 'ETH-1', 3: 'ETH-2', 4: 'ETH-3', 5: 'ETH-4', 6: 'ETH-5',
  7: 'ETH-6', 8: 'ETH-7', 9: 'ETH-8', 16: 'WAN', 17: 'WAN-1', 18: 'WAN-2',
  32: 'SFP-1', 36: 'SFP-2',
};

const VPN_STATES: Record<number, string> = {
  0: 'init', 1: 'setup-wan', 2: 'ready', 3: 'wait-for-cb', 4: 'dial', 5: 'incoming-call',
  6: 'protocol', 7: 'connected', 8: 'disconnecting', 9: 'callback', 10: 'bundle-connect',
  11: 'protocol2', 12: 'reserved', 13: 'bundled',
};

const STATION_STATES: Record<number, string> = {
  0: 'none', 1: 'adhoc', 2: 'authenticated', 3: 'connected', 4: 'mac-check',
  8: 'key-handshake', 9: 'associated',
};

const RADIO_BANDS: Record<number, string> = { 0: '', 1: '2.4 GHz', 2: '5 GHz', 3: 'dual (2.4+5 GHz)' };
// Channel-bandwidth enum — verified live on a GS-series router (WLAN-1=0→20,
// WLAN-2=2→80). Values outside the map fall back to null.
const RADIO_BANDWIDTHS: Record<number, number> = { 0: 20, 1: 40, 2: 80 };

/** Active-routing-table Type enum (lcsStatusIpRouterActIpRoutingTabEntryType).
 *  Maps the MIB value to our normalized protocol; eDisabled(8) rows are SKIPPED
 *  entirely by the parser. Values outside the map → 'other' with a raw label. */
const IP_ROUTE_TYPES: Record<number, { protocol: LcosRoute['protocol']; label: string }> = {
  0: { protocol: 'other', label: 'unknown' },
  1: { protocol: 'static', label: 'static' },
  2: { protocol: 'rip', label: 'rip' },
  3: { protocol: 'other', label: 'vpn' },
  4: { protocol: 'other', label: 'capwap' },
  5: { protocol: 'other', label: 'ras' },
  6: { protocol: 'other', label: 'intranet' },
  7: { protocol: 'other', label: 'dmz' },
  // 8 = eDisabled — skipped, not mapped
  9: { protocol: 'bgp', label: 'ebgp' },
  10: { protocol: 'bgp', label: 'ibgp' },
  11: { protocol: 'ospf', label: 'ospf' },
  12: { protocol: 'other', label: 'lisp' },
  13: { protocol: 'other', label: 'dhcp' },
};

/* ------------------------------------------------------------------ *
 * OID row decoding (column-first + length-prefixed OCTET STRING / IP indices)
 * and enum/integer pickers now live in @unm/lancom-shared — imported above.
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ *
 * Slow path — targeted parallel walks of the runtime-status subtrees we use
 * ------------------------------------------------------------------ */

// Fresh-snapshot cache (TTL-gated) + a last-known map so a failed refresh can
// still fall back to the most recent data even after TTL expiry. Shared trio —
// see @unm/lancom-shared snapshotCache.ts.
const caches = createSnapshotCaches<LcosRouterSnapshot>();

/**
 * The exact subtrees the slow path needs — nothing else. Deliberately NOT a
 * single `11.1` walk: that subtree contains large tables we never read (WLAN
 * client translation tables, RADIUS logs, NetBIOS lists) and would take far
 * longer than the API's 10s poll budget on a real router. All entries are
 * walked together in one combined GetBulk stream (snmpWalkMulti).
 */
const INVENTORY_WALKS: string[] = [
  `${LCOS_BASE}.2.1`, // device name — single config-mirror scalar (no secrets)
  HW.base, // system/hardware scalars (mem, serial, sw version, CPU load, model)
  TIME.base, // wall clock + timezone (Time page)
  FIRMWARE.versionTableBase, // per-module firmware versions
  LAN_IF.base, // per-port link state + connector + MACs
  WAN_IP.base, // WAN IP configuration mirror
  NET_LIST.base, // configured networks (LAN/VLAN IPs)
  IPV6_PREFIX.base, // advertised/delegated v6 prefixes (Status/IPv6 — sparse; the Addresses table is deliberately NOT walked: no prefix lengths + link-local noise)
  ARP.base, // ARP cache → hosts inventory
  DHCP.base, // active DHCP leases → hosts inventory
  IP_ROUTES.base, // active routing table (static + OSPF/BGP/RIP) → routes inventory
  IP_CIDR_ROUTES.base, // standard ipCidrRouteTable — fallback when the vendor table is absent on this firmware
  VPN_CONN.base, // active VPN connections
  WLAN_NET.base, // per-radio SSIDs (built-in radios only — empty on pure routers)
  WLAN_RADIO.base, // per-radio RF status
  WLAN_STATION.base, // per-client stations
  TEMP_EXTREMES.base, // temperature min/max extremes
];

/**
 * Returns the cached LCOS snapshot for a host, re-walking only when the cache
 * is empty or older than `inventoryTtlMs`. Never throws — degrades to
 * stale/empty data with an explanatory error. Partial walk failures (some
 * subtrees missing) still yield a usable snapshot; total failure does not.
 *
 * The orchestration (cache → probe gate → combined walk → quality gate → stale
 * fallback) is the shared @unm/lancom-shared slow-path runner; only the probe
 * step and parser are LCOS-specific. All inventory subtrees go out in ONE
 * strictly-sequential combined GetBulk stream (~17 PDUs / ~1.2s live-profiled),
 * which never stresses the embedded agents' tiny concurrent-request queues.
 */
export async function getLcosInventory(
  host: string,
  creds: SnmpCredentials,
  opts: LcosOptions,
  log?: LcosLogSink
): Promise<{ snapshot: LcosRouterSnapshot | null; fromCache: boolean; error?: string }> {
  // Probe gate: one cheap snmpget against a scalar every LCOS router exposes
  // (hardware-info sw version). Non-LANCOM devices answer "No Such Object" in
  // ~100ms and are rejected here instead of burning ~13 walks × timeout
  // budget; unreachable hosts fail fast on the single PDU.
  const probe = async (): Promise<ProbeOutcome> => {
    let m: Map<string, SnmpValue>;
    try {
      m = await snmpGet(host, creds, [HW.swVersion], opts);
    } catch {
      return { kind: 'transport-error', error: 'SNMP query failed — device unreachable or credentials rejected.' };
    }
    if (m.size === 0) return { kind: 'not-device' }; // agent answered but has no LCOS tree
    return { kind: 'ok', seed: m };
  };

  return runSlowPath(caches, {
    host,
    creds,
    opts,
    log,
    probe,
    walks: () => INVENTORY_WALKS,
    parse: (out) => parseLcosStatus(out),
    // Quality gate: the serial number comes from the hardware-info WALK
    // (11.1.47), not the probe scalar — only cache when that walk succeeded.
    isComplete: (s) => s.system.serialNumber !== '',
    errors: {
      walkFailed: 'SNMP walk of the LCOS status tree failed.',
      notDevice: 'No LCOS MIB data on this device.',
      partial: 'Partial LCOS data — some SNMP walks failed; retrying next cycle.',
    },
  });
}

/** Parses the targeted LCOS walk output into a typed snapshot. */
function parseLcosStatus(out: Map<string, SnmpValue>): LcosRouterSnapshot {
  const get = (oid: string): SnmpValue => out.get(oid) ?? '';

  // --- System scalars -------------------------------------------------
  const memTotal = toInt(get(HW.totalMemoryKbytes));
  const memFree = toInt(get(HW.freeMemoryKbytes));
  const cpuRaw = toInt(get(HW.cpuLoad60sPercent));
  const secEngine = get(HW.securityEngine);

  // --- Firmware modules (index: ifc int, eIfc=1) -----------------------
  const firmwareBySlot = new Map<string, { module: string; version: string }>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, FIRMWARE.versionTableBase);
    if (!row || row.idx.length !== 1) continue;
    let m = firmwareBySlot.get(row.idx[0]);
    if (!m) { m = { module: '', version: '' }; firmwareBySlot.set(row.idx[0], m); }
    switch (row.col) {
      case FIRMWARE.COL_MODULE: m.module = String(value); break;
      case FIRMWARE.COL_VERSION: m.version = String(value); break;
    }
  }

  // --- LAN ports (index: ifc text "LAN-1", length-prefixed) -------------
  const lanPorts = new Map<string, Partial<LcosLanPort>>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, LAN_IF.base);
    if (!row) continue;
    const key = decodeSingleText(row.idx);
    if (!key) continue;
    let p = lanPorts.get(key);
    if (!p) { p = {}; lanPorts.set(key, p); }
    switch (row.col) {
      case LAN_IF.COL_LINK_ACTIVE: p.linkUp = Number(value) === 1; break;
      case LAN_IF.COL_CONNECTOR: p.connectorLabel = label(LAN_CONNECTORS, value); break;
      case LAN_IF.COL_MAC: p.mac = normalizeMac(value); break;
    }
  }

  // --- WAN IPs (index: peer text "WAN", length-prefixed) -----------------
  const wanIps = new Map<string, Partial<LcosWanIp>>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, WAN_IP.base);
    if (!row) continue;
    const key = decodeSingleText(row.idx);
    if (!key) continue;
    let w = wanIps.get(key);
    if (!w) { w = {}; wanIps.set(key, w); }
    switch (row.col) {
      case WAN_IP.COL_TYPE: w.typeLabel = label({ 1: 'static', 2: 'dhcp', 3: 'ppp', 4: 'autoconfig' }, value); break;
      case WAN_IP.COL_ADDR: w.address = String(value); break;
      case WAN_IP.COL_NETMASK: w.netmask = String(value); break;
      case WAN_IP.COL_GATEWAY: w.gateway = String(value); break;
    }
  }

  // --- Configured networks (index: networkName text) ---------------------
  const networks: LcosNetwork[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, NET_LIST.base);
    if (!row) continue;
    const key = decodeSingleText(row.idx);
    if (!key) continue;
    let n = networks.find((x) => x.name === key);
    if (!n) { n = { name: key, ip: '', prefix: null, vlanId: null, ifcLabel: '' }; networks.push(n); }
    switch (row.col) {
      case NET_LIST.COL_IP: n.ip = String(value); break;
      case NET_LIST.COL_NETMASK: n.prefix = netmaskToPrefix(value); break;
      case NET_LIST.COL_VLAN: n.vlanId = toInt(value); break;
      case NET_LIST.COL_IFC: n.ifcLabel = decodeNetIfc(value); break;
    }
  }

  // --- IPv6 prefixes (Status/IPv6 Prefix table, index: [name, cidr] text) --
  // Sparse by design — one row per advertised/delegated prefix, not per
  // address. These are the only v6 rows with real prefix lengths, so they are
  // what feeds the networks inventory (subnet overlap checks + suggestions).
  const ipv6Prefixes: LcosIpv6Prefix[] = [];
  for (const [oid] of out) {
    const row = splitRow(oid, IPV6_PREFIX.base);
    if (!row || row.col !== IPV6_PREFIX.COL_NAME) continue; // one row per index pair
    const d1 = decodePrefixedText(row.idx, 0);
    if (!d1) continue;
    const d2 = decodePrefixedText(row.idx, d1.next);
    if (!d2 || d2.next !== row.idx.length) continue; // composite [name, cidr] — both parts required
    const name = d1.text;
    const cidr = d2.text;
    if (cidr.includes('/') && !ipv6Prefixes.some((p) => p.name === name && p.cidr === cidr)) {
      ipv6Prefixes.push({ name, cidr });
    }
  }

  // --- ARP cache (index: IP — four decimal octets) ------------------------
  const arp: LcosArpEntry[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, ARP.base);
    if (!row || row.idx.length !== 4) continue;
    const ip = decodeIpIndex(row.idx, 0);
    if (!ip) continue;
    let a = arp.find((x) => x.ip === ip);
    if (!a) { a = { ip, mac: '', portLabel: '' }; arp.push(a); }
    switch (row.col) {
      case ARP.COL_MAC: a.mac = normalizeMac(value); break;
      case ARP.COL_PORT: a.portLabel = label(ARP_PORTS, value); break;
    }
  }

  // --- DHCP leases (index: [ip(4 octets), networkName text]) --------------
  const dhcpLeases: LcosDhcpLease[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, DHCP.base);
    if (!row) continue;
    const key = decodeIpTextIndex(row.idx);
    if (!key) continue;
    let d = dhcpLeases.find((x) => x.ip === key.ip && x.networkName === key.text);
    if (!d) { d = { ip: key.ip, mac: '', hostname: '', expirySeconds: null, networkName: key.text }; dhcpLeases.push(d); }
    switch (row.col) {
      case DHCP.COL_MAC: d.mac = normalizeMac(value); break;
      case DHCP.COL_TIMEOUT: d.expirySeconds = toInt(value); break;
      case DHCP.COL_HOSTNAME: d.hostname = String(value); break;
    }
  }

  // --- VPN connections (index: peer text "IPSEC-1") -----------------------
  const vpnConnections: LcosVpnConn[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, VPN_CONN.base);
    if (!row) continue;
    const key = decodeSingleText(row.idx);
    if (!key) continue;
    let v = vpnConnections.find((x) => x.peer === key);
    if (!v) {
      v = { peer: key, physConn: '', ikeType: '', cryptAlg: '', stateLabel: '', modeLabel: '', connTimeSeconds: null };
      vpnConnections.push(v);
    }
    switch (row.col) {
      case VPN_CONN.COL_PHYS: v.physConn = String(value); break;
      case VPN_CONN.COL_CRYPT_ALG: v.cryptAlg = String(value); break;
      case VPN_CONN.COL_STATE: v.stateLabel = label(VPN_STATES, value); break;
      case VPN_CONN.COL_MODE: v.modeLabel = Number(value) === 128 ? 'active' : 'passive'; break; // ePassive(0)/eActive(128)
      case VPN_CONN.COL_CONN_TIME: v.connTimeSeconds = toInt(value); break;
      case VPN_CONN.COL_IKE_TYPE: v.ikeType = String(value); break;
    }
  }

  // --- WLAN (built-in radios only — pure routers report nothing) ----------
  const ssids: LcosSsid[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, WLAN_NET.base);
    if (!row) continue;
    const key = decodeSingleText(row.idx);
    if (!key) continue;
    let s = ssids.find((x) => x.ifc === key && x.name === '');
    // One row per (radio, network) — the table is indexed by radio only in
    // this MIB revision, so a second SSID on the same radio overwrites col 3;
    // keep the first non-empty name seen.
    if (!s) { s = { ifc: key, name: '', operating: null, bssid: '', stations: null, vlanId: null }; ssids.push(s); }
    switch (row.col) {
      case WLAN_NET.COL_OPERATING: s.operating = Number(value) === 1; break;
      case WLAN_NET.COL_NAME: if (!s.name) s.name = String(value); break;
      case WLAN_NET.COL_STATIONS: s.stations = toInt(value); break;
      case WLAN_NET.COL_BSSID: s.bssid = normalizeMac(value); break;
      case WLAN_NET.COL_VLAN: s.vlanId = toInt(value); break;
    }
  }

  const radios: LcosRadio[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, WLAN_RADIO.base);
    if (!row) continue;
    const key = decodeSingleText(row.idx);
    if (!key) continue;
    let r = radios.find((x) => x.ifc === key);
    if (!r) {
      r = { ifc: key, bandLabel: '', channel: null, bandwidthMhz: null, noiseFloorDbm: null, modemLoadPct: null, txPower: '', utilizationPct: null };
      radios.push(r);
    }
    switch (row.col) {
      case WLAN_RADIO.COL_BAND: r.bandLabel = label(RADIO_BANDS, value); break;
      case WLAN_RADIO.COL_CHANNEL: r.channel = toInt(value); break;
      case WLAN_RADIO.COL_NOISE: r.noiseFloorDbm = toInt(value); break;
      case WLAN_RADIO.COL_MODEM_LOAD: r.modemLoadPct = toInt(value); break;
      case WLAN_RADIO.COL_TX_POWER: r.txPower = String(value); break;
      case WLAN_RADIO.COL_UTILIZATION: r.utilizationPct = toInt(value); break;
      case WLAN_RADIO.COL_BANDWIDTH: {
        const n = toInt(value);
        if (n !== null) r.bandwidthMhz = RADIO_BANDWIDTHS[n] ?? null;
      } break;
    }
  }

  const clientBySlot = new Map<string, LcosClient>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, WLAN_STATION.base);
    if (!row || row.idx.length !== 1) continue; // index is a plain Integer32
    let c = clientBySlot.get(row.idx[0]);
    if (!c) {
      c = { mac: '', ifc: '', hostname: '', ip4: '', ip6: '', signalDbm: null, txRateMbps: null, rxRateMbps: null, vlanId: null };
      clientBySlot.set(row.idx[0], c);
    }
    switch (row.col) {
      case WLAN_STATION.COL_MAC: c.mac = normalizeMac(value); break;
      case WLAN_STATION.COL_IFC: c.ifc = `WLAN-${Number(value) + 1}`; break; // eWlan1(0)…eWlan4(3)
      case WLAN_STATION.COL_SIGNAL: c.signalDbm = toInt(value); break;
      case WLAN_STATION.COL_IP4: { const v = String(value).trim(); if (v && v !== '0.0.0.0') c.ip4 = v; } break;
      case WLAN_STATION.COL_VLAN: c.vlanId = toInt(value); break;
      case WLAN_STATION.COL_USER: if (!c.hostname) c.hostname = String(value).trim(); break;
      case WLAN_STATION.COL_EFF_TX: c.txRateMbps = toInt(value); break;
      case WLAN_STATION.COL_EFF_RX: c.rxRateMbps = toInt(value); break;
      case WLAN_STATION.COL_IP6: { const v = String(value).trim(); if (v && v !== '::') c.ip6 = v; } break;
      case WLAN_STATION.COL_HOSTNAME: if (!c.hostname) c.hostname = String(value).trim(); break;
    }
  }

  // --- Active routing table (index: [ip(4 octets), netmask(4 octets), rtgTag]) --
  // One walk yields static AND dynamically-learned routes; the per-row Type
  // enum labels the protocol. IPv4 only — the MIB has no v6 route table.
  type LcosRouteRow = LcosRoute & { key: string }; // internal dedup key, stripped at return
  const routes: LcosRouteRow[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, IP_ROUTES.base);
    if (!row || row.idx.length !== 9) continue; // ip(4) + netmask(4) + rtgTag
    const ip = decodeIpIndex(row.idx, 0);
    const netmask = decodeIpIndex(row.idx, 4);
    if (!ip || !netmask) continue;
    const tag = Number(row.idx[8]);
    const key = `${ip}|${netmask}|${tag}`;
    let r = routes.find((x) => x.key === key);
    if (!r) {
      // Build the CIDR up front — both index columns are always present in a
      // complete row, and netmaskToPrefix is hoisted (function declaration).
      const prefix = netmaskToPrefix(netmask);
      r = { key, destination: ip + (prefix !== null ? `/${prefix}` : ''), gateway: '', protocol: 'other', distance: null, metric: null, rtgTag: Number.isFinite(tag) ? tag : null, peer: '', rawTypeLabel: '' };
      routes.push(r);
    }
    switch (row.col) {
      case IP_ROUTES.COL_GATEWAY: { const v = String(value).trim(); r.gateway = v === '0.0.0.0' ? '' : v; } break;
      case IP_ROUTES.COL_PEER: r.peer = String(value).trim(); break;
      case IP_ROUTES.COL_DISTANCE: r.distance = toInt(value); break;
      case IP_ROUTES.COL_TYPE: {
        const n = Number(value);
        if (Number.isInteger(n) && n === 8) { routes.splice(routes.indexOf(r), 1); } // eDisabled — drop the row
        else {
          const m = IP_ROUTE_TYPES[n];
          r.protocol = m ? m.protocol : 'other';
          r.rawTypeLabel = m ? m.label : String(value);
        }
        break;
      }
    }
  }

  // --- Standard ipCidrRouteTable fallback ---------------------------------
  // Firmware that lacks the vendor active-routing table (11.1.10.30 — e.g.
  // LCOS 10.94 on some models) still implements the standard IP-FORWARD-MIB
  // table; parse it when the vendor walk yielded no rows. Row layout is
  // non-standard (see IP_CIDR_ROUTES in lcosOids.ts): the index embeds
  // dest+mask+nextHop and columns follow RFC 2993 numbering. The agent's
  // proto/type enums do not follow RFC semantics, so protocol comes from
  // next-hop presence; raw values are kept for transparency.
  const standardRoutes: LcosRouteRow[] = [];
  const stdInvalidKeys = new Set<string>(); // ipCidrRouteType invalid(1) rows — dropped at return
  for (const [oid, value] of out) {
    const suffix = suffixOf(oid, IP_CIDR_ROUTES.base); // "4.1.<col>.<idx…>"
    if (!suffix) continue;
    const parts = suffix.split('.');
    if (parts.length < 3 || parts[0] !== '4' || parts[1] !== '1') continue;
    const col = Number(parts[2]);
    const idx = parts.slice(3);
    if (idx.length !== 13) continue; // dest(4)+mask(4)+filler(1)+nextHop(4)
    const ip = decodeIpIndex(idx, 0);
    const netmask = decodeIpIndex(idx, 4);
    const nextHopRaw = decodeIpIndex(idx, 9);
    if (!ip || !netmask || !nextHopRaw) continue;
    const key = `std|${ip}|${netmask}`;
    let r = standardRoutes.find((x) => x.key === key);
    if (!r) {
      const prefix = netmaskToPrefix(netmask);
      const connected = nextHopRaw === '0.0.0.0' || nextHopRaw === '255.255.255.255';
      r = { key, destination: ip + (prefix !== null ? `/${prefix}` : ''), gateway: connected ? '' : nextHopRaw, protocol: connected ? 'connected' : 'static', distance: null, metric: null, rtgTag: null, peer: '', rawTypeLabel: '' };
      standardRoutes.push(r);
    }
    switch (col) {
      case IP_CIDR_ROUTES.COL_TYPE: if (Number(value) === 1) stdInvalidKeys.add(key); break; // invalid — drop the row
      case IP_CIDR_ROUTES.COL_PROTO: {
        const n = Number(value);
        // Only RFC static(2) is trusted for rows with a real next hop; the
        // agent's other values don't follow the enum (e.g. it reports 2 for
        // everything), so anything else degrades to 'other' + raw label.
        if (r.gateway !== '' && !(Number.isInteger(n) && n === 2)) { r.protocol = 'other'; r.rawTypeLabel = `proto=${value}`; }
        break;
      }
      case IP_CIDR_ROUTES.COL_METRIC1: { const m = toInt(value); if (m !== null && m > 0) r.metric = m; } break; // -1/0 = unset per RFC
    }
  }

// --- Temperature extremes (index: type int — min/max per sensor) --------
  const temperatureExtremes: LcosTempExtreme[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, TEMP_EXTREMES.base);
    if (!row || row.idx.length !== 1) continue;
    const typeCode = Number(row.idx[0]);
    if (!Number.isFinite(typeCode)) continue;
    // eMinimum1=1, eMaximum1=2, +256 per additional sensor.
    const sensor = Math.floor((typeCode - 1) / 2) + 1;
    const kind: 'min' | 'max' = typeCode % 2 === 1 ? 'min' : 'max';
    let t = temperatureExtremes.find((x) => x.sensor === sensor && x.kind === kind);
    if (!t) { t = { sensor, kind, valueTenthsC: null }; temperatureExtremes.push(t); }
    if (row.col === TEMP_EXTREMES.COL_VALUE) t.valueTenthsC = toInt(value);
  }

  return {
    collectedAt: Date.now(),
    isLancom: true,
    system: {
      name: String(get(SYS.setupName)),
      swVersion: String(get(HW.swVersion)),
      serialNumber: String(get(HW.serialNumber)),
      modelNumber: String(get(HW.modelNumber)),
      cpuType: String(get(HW.cpuType)),
      uptimeText: String(get(SYS.operatingTime)),
      systemDate: String(get(TIME.currentTime)).trim(),
      timezoneMinutes: lcosTimezoneToMinutes(toInt(get(TIME.timezone))),
      cpuLoadPct: cpuRaw,
      memoryTotalKb: memTotal,
      memoryFreeKb: memFree,
      securityEngine: secEngine === '' ? null : Number(secEngine) === 1,
      bootCause: String(get(FIRMWARE.bootCause)),
      featureWord: String(get(FIRMWARE.featureWord)),
    },
    firmwareModules: [...firmwareBySlot.values()],
    lanPorts: [...lanPorts.entries()].map(([name, p]) => ({ name, ...p } as LcosLanPort)),
    wanIps: [...wanIps.entries()].map(([peer, w]) => ({ peer, ...w } as LcosWanIp)),
    networks,
    ipv6Prefixes,
    arp,
    dhcpLeases,
    vpnConnections,
    radios,
    ssids,
    clients: [...clientBySlot.values()],
    // Vendor active-routing table wins when it yields rows (richer protocol
    // labels + admin distance); otherwise fall back to the standard table.
    routes: (routes.length > 0 ? routes : standardRoutes.filter((x) => !stdInvalidKeys.has(x.key))).map((row) => ({ destination: row.destination, gateway: row.gateway, protocol: row.protocol, distance: row.distance, metric: row.metric, rtgTag: row.rtgTag, peer: row.peer, rawTypeLabel: row.rawTypeLabel })),
    temperatureExtremes,
  };
}

/**
 * Decodes the network-list interface enum (verified against the MIB):
 *   eLan1(256)…eLan16(271) → "LAN-<n-255>"
 *   eWlan1(512)/eWlan2(513) → "WLAN-1"/"WLAN-2" (higher WLAN/P2P values use an
 *   ambiguous radio/ifc encoding — return '' rather than guess a wrong label).
 */
function decodeNetIfc(raw: SnmpValue | undefined): string {
  const n = Number(raw ?? '');
  if (!Number.isInteger(n)) return '';
  if (n >= 256 && n <= 511) return `LAN-${n - 255}`;
  if (n === 512 || n === 513) return `WLAN-${n - 511}`;
  return '';
}

/* ------------------------------------------------------------------ *
 * Fast path — byte-counter walks every poll → rx/tx rates (bits/s)
 * ------------------------------------------------------------------ */

// Shared counter-delta tracker (@unm/plugin-sdk): first sample → null,
// reset/wrap skipped, baseline always refreshed, stale hosts evicted.
const rateTracker = new CounterTracker(); // octets/s → bits/s

/** One rate sample per interface: bits/s in each direction (null when unknown). */
export type LcosRates = Record<string, { rx: number | null; tx: number | null }>;

/**
 * Walks the LAN + WAN byte-counter tables and computes rates against a
 * per-host baseline. Counter resets/wraps yield null for that sample (the
 * next cycle re-baselines). Never throws — returns empty maps on failure so
 * monitoring degrades to slow-path data only.
 */
export async function walkLcosCounters(
  host: string,
  creds: SnmpCredentials,
  opts: LcosOptions
): Promise<{ lanRates: LcosRates; wanRates: LcosRates }> {
  const empty = { lanRates: {} as LcosRates, wanRates: {} as LcosRates };
  let out: Map<string, SnmpValue>;
  try {
    // Both byte-counter tables in one combined walk (shared session).
    out = await snmpWalkMulti(host, creds, [LAN_BYTES.base, WAN_BYTES.base], opts);
  } catch {
    return empty; // counters unavailable this cycle — rates stay null
  }

  const now = Date.now();
  rateTracker.evictStale(now);

  const lanRates: LcosRates = {};
  for (const [oid, value] of out) {
    const row = splitRow(oid, LAN_BYTES.base);
    if (!row || row.col !== LAN_BYTES.COL_RX && row.col !== LAN_BYTES.COL_TX) continue;
    const key = decodeSingleText(row.idx);
    if (!key) continue;
    const n = Number(value);
    if (!Number.isFinite(n)) continue;
    const dir = row.col === LAN_BYTES.COL_RX ? 'rx' : 'tx';
    // Integer bits/s, as before — the tracker returns a float rate.
    accumulateRate(lanRates, key, dir, rateTracker.sample(`lan:${key}:${dir}`, n, now));
  }

  const wanRates: LcosRates = {};
  for (const [oid, value] of out) {
    const row = splitRow(oid, WAN_BYTES.base);
    if (!row || row.idx.length !== 1) continue;
    // Prefer the high-resolution Counter64 columns when present.
    if (row.col !== WAN_BYTES.COL_HRX && row.col !== WAN_BYTES.COL_HTx) continue;
    const key = decodeWanIfc(row.idx[0]);
    const n = Number(value);
    if (!Number.isFinite(n)) continue;
    const dir = row.col === WAN_BYTES.COL_HRX ? 'rx' : 'tx';
    accumulateRate(wanRates, key, dir, rateTracker.sample(`wan:${key}:${dir}`, n, now));
  }

  return { lanRates, wanRates };
}

/** Decodes a WAN ifc index value to a display name (eCh01=257 → "CH-1", …). */
function decodeWanIfc(raw: string): string {
  const n = Number(raw);
  if (!Number.isInteger(n)) return `ifc-${raw}`;
  if (WAN_IFC_NAMES[n]) return WAN_IFC_NAMES[n];
  // DSL/XDSL/ADSL/VDSL channels are spaced per technology — fall back to the raw value.
  return `WAN-ifc${n}`;
}
