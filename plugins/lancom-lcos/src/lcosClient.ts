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

import { SnmpCredentials, TransportOptions, snmpGet, snmpWalk, suffixOf, normalizeMac } from '@unm/snmp-client';
import {
  LCOS_BASE, SYS, HW, FIRMWARE, LAN_IF, LAN_BYTES, WAN_BYTES, WAN_IP,
  NET_LIST, ARP, DHCP, VPN_CONN, WLAN_NET, WLAN_RADIO, WLAN_STATION, TEMP_EXTREMES,
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
  arp: LcosArpEntry[];
  dhcpLeases: LcosDhcpLease[];
  vpnConnections: LcosVpnConn[];
  radios: LcosRadio[];
  ssids: LcosSsid[];
  clients: LcosClient[];
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

function label(map: Record<number, string>, raw: string | undefined): string {
  if (raw === undefined || raw === '') return '';
  const n = Number(raw);
  return Number.isFinite(n) ? map[n] ?? String(n) : raw;
}

function toInt(value: string | undefined): number | null {
  if (value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

/* ------------------------------------------------------------------ *
 * OID row decoding — LANCOM's LCOS agent addresses table rows COLUMN-FIRST:
 *   <table>.1.<column>.<index…>          (standard SNMP is index-first!)
 * and encodes OCTET STRING indices as LENGTH-PREFIXED decimal octets:
 *   "WLAN-1" → 6.87.76.65.78.45.49       (len=6, then ASCII bytes)
 * IP-address indices are the raw four decimal octets ("10.25.1.1" → 10.25.1.1).
 * Index columns are not-accessible, so row keys can ONLY be recovered from
 * the OID suffix — every table above has its index shape verified against the MIB.
 * ------------------------------------------------------------------ */

/** Decodes one length-prefixed OCTET STRING index component (e.g. "WLAN-1"). */
function decodePrefixedText(parts: string[], start: number): { text: string; next: number } | null {
  const len = Number(parts[start]);
  if (!Number.isInteger(len) || len <= 0 || len > 64 || start + 1 + len > parts.length) return null;
  let text = '';
  for (let i = 1; i <= len; i++) {
    const p = parts[start + i];
    if (!/^\d+$/.test(p)) return null;
    const n = Number(p);
    text += n >= 32 && n <= 126 ? String.fromCharCode(n) : ''; // non-printable → drop
  }
  return { text, next: start + 1 + len };
}

/** Decodes a raw four-octet IPv4 index run to dotted-quad (or null). */
function decodeIpIndex(parts: string[], start: number): string | null {
  if (start + 4 > parts.length) return null;
  const octets = parts.slice(start, start + 4);
  if (!octets.every((p) => /^\d+$/.test(p) && Number(p) <= 255)) return null;
  return octets.map(Number).join('.');
}

/**
 * Splits a column-first row OID into column number + index components.
 * Row shape relative to the table base: `<base>.1.<column>.<index…>` — the
 * leading "1" is the (not-accessible) entry object, always sub-identifier 1
 * in every LCOS table (`::= { <table> 1 }`).
 */
function splitRow(oid: string, base: string): { col: number; idx: string[] } | null {
  const suffix = suffixOf(oid, base); // "<entry>.<col>.<idx…>"
  if (!suffix) return null;
  const parts = suffix.split('.');
  if (parts.length < 3 || parts[0] !== '1') return null; // entry + col + ≥1 idx part
  const col = Number(parts[1]);
  if (!Number.isInteger(col)) return null;
  return { col, idx: parts.slice(2) };
}

/** Decodes a single-component text index ("WLAN-1", "LAN-1", peer names). */
function decodeSingleText(idx: string[]): string | null {
  const d = decodePrefixedText(idx, 0);
  return d && d.next === idx.length ? d.text : null;
}

/** Decodes a [ip(4 octets), text] index (DHCP leases). */
function decodeIpTextIndex(idx: string[]): { ip: string; text: string } | null {
  const ip = decodeIpIndex(idx, 0);
  if (!ip) return null;
  const d = decodePrefixedText(idx, 4);
  return d && d.next === idx.length ? { ip, text: d.text } : null;
}

/* ------------------------------------------------------------------ *
 * Slow path — targeted parallel walks of the runtime-status subtrees we use
 * ------------------------------------------------------------------ */

const inventoryCache = new Map<string, LcosRouterSnapshot>();

/**
 * The exact subtrees the slow path needs — nothing else. Deliberately NOT a
 * single `11.1` walk: that subtree contains large tables we never read (WLAN
 * client translation tables, RADIUS logs, NetBIOS lists) and would take far
 * longer than the API's 10s poll budget on a real router. Each entry is one
 * snmpwalk; they run in parallel batches (separate processes).
 */
const INVENTORY_WALKS: string[] = [
  `${LCOS_BASE}.2.1`, // device name — single config-mirror scalar (no secrets)
  HW.base, // system/hardware scalars (mem, serial, sw version, CPU load, model)
  FIRMWARE.versionTableBase, // per-module firmware versions
  LAN_IF.base, // per-port link state + connector + MACs
  WAN_IP.base, // WAN IP configuration mirror
  NET_LIST.base, // configured networks (LAN/VLAN IPs)
  ARP.base, // ARP cache → hosts inventory
  DHCP.base, // active DHCP leases → hosts inventory
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
 */
export async function getLcosInventory(
  host: string,
  creds: SnmpCredentials,
  opts: LcosOptions
): Promise<{ snapshot: LcosRouterSnapshot | null; fromCache: boolean; error?: string }> {
  const cached = inventoryCache.get(host);
  if (cached && Date.now() - cached.collectedAt < opts.inventoryTtlMs) {
    return { snapshot: cached, fromCache: true };
  }

  // Probe gate: one cheap snmpget against a scalar every LCOS router exposes
  // (hardware-info sw version). Non-LANCOM devices answer "No Such Object" in
  // ~100ms and are rejected here instead of burning ~13 walks × timeout
  // budget; unreachable hosts fail fast on the single PDU.
  let probe: Map<string, string>;
  try {
    probe = await snmpGet(host, creds, [HW.swVersion], opts);
  } catch {
    return {
      snapshot: cached ?? null,
      fromCache: cached !== undefined,
      error: 'SNMP query failed — device unreachable or credentials rejected.',
    };
  }
  if (probe.size === 0) {
    // Agent answered but has no LCOS tree — not a Lancom LCOS router.
    return { snapshot: null, fromCache: false, error: 'No LCOS MIB data on this device.' };
  }

  const out = new Map<string, string>();
  for (const [k, v] of probe) out.set(k, v); // reuse the probed scalar

  // Walks run in small batches rather than all at once: embedded router agents
  // have tiny concurrent-request queues, and a burst of ~13 parallel walks
  // makes them answer some walks with EMPTY views instead of timing out.
  // Batches of 4 keep total wall time around ~2-3s while staying well under
  // the agent's concurrency limit.
  const BATCH = 4;
  const failed: string[] = [];
  for (let i = 0; i < INVENTORY_WALKS.length; i += BATCH) {
    const chunk = INVENTORY_WALKS.slice(i, i + BATCH);
    const results = await Promise.allSettled(chunk.map((oid) => snmpWalk(host, creds, [oid], opts)));
    for (let j = 0; j < results.length; j++) {
      const r = results[j];
      if (r.status === 'fulfilled') {
        for (const [k, v] of r.value) out.set(k, v);
        continue;
      }
      console.error(`[lancom-lcos] inventory walk ${chunk[j]} failed:`, r.reason?.message ?? r.reason);
      failed.push(chunk[j]);
    }
  }

  // One sequential retry for anything that threw (empty-but-successful walks
  // are indistinguishable from "table genuinely empty" — the quality gate
  // below catches those via missing system scalars).
  let failures = 0;
  for (const oid of failed) {
    try {
      const retry = await snmpWalk(host, creds, [oid], opts);
      for (const [k, v] of retry) out.set(k, v);
    } catch {
      failures++; // still failing after the retry — subtree stays empty this cycle
    }
  }

  if (out.size === 0 && failures > 0) {
    return {
      snapshot: cached ?? null,
      fromCache: cached !== undefined,
      error: 'SNMP walk of the LCOS status tree failed.',
    };
  }

  if (out.size === 0) {
    // Walks succeeded but returned nothing — this device is not a Lancom router.
    return { snapshot: null, fromCache: false, error: 'No LCOS MIB data on this device.' };
  }

  const snapshot = parseLcosStatus(out);

  // Quality gate before caching: the serial number comes from the hardware-info
  // WALK (11.1.47), not from the probe scalar — so a cached snapshot is only
  // stored when that walk actually succeeded. A partial-failure artifact must
  // never be served from cache for the whole TTL; it's returned once and the
  // next poll retries fresh.
  const complete = snapshot.system.serialNumber !== '';
  if (complete) inventoryCache.set(host, snapshot);

  return {
    snapshot,
    fromCache: false,
    error: complete ? undefined : 'Partial LCOS data — some SNMP walks failed; retrying next cycle.',
  };
}

/** Parses the targeted LCOS walk output into a typed snapshot. */
function parseLcosStatus(out: Map<string, string>): LcosRouterSnapshot {
  const get = (oid: string): string => out.get(oid) ?? '';

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
      case FIRMWARE.COL_MODULE: m.module = value; break;
      case FIRMWARE.COL_VERSION: m.version = value; break;
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
      case LAN_IF.COL_LINK_ACTIVE: p.linkUp = value === '1'; break;
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
      case WAN_IP.COL_ADDR: w.address = value; break;
      case WAN_IP.COL_NETMASK: w.netmask = value; break;
      case WAN_IP.COL_GATEWAY: w.gateway = value; break;
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
      case NET_LIST.COL_IP: n.ip = value; break;
      case NET_LIST.COL_NETMASK: n.prefix = netmaskToPrefix(value); break;
      case NET_LIST.COL_VLAN: n.vlanId = toInt(value); break;
      case NET_LIST.COL_IFC: n.ifcLabel = decodeNetIfc(value); break;
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
      case DHCP.COL_HOSTNAME: d.hostname = value; break;
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
      case VPN_CONN.COL_PHYS: v.physConn = value; break;
      case VPN_CONN.COL_CRYPT_ALG: v.cryptAlg = value; break;
      case VPN_CONN.COL_STATE: v.stateLabel = label(VPN_STATES, value); break;
      case VPN_CONN.COL_MODE: v.modeLabel = value === '128' ? 'active' : 'passive'; break;
      case VPN_CONN.COL_CONN_TIME: v.connTimeSeconds = toInt(value); break;
      case VPN_CONN.COL_IKE_TYPE: v.ikeType = value; break;
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
      case WLAN_NET.COL_OPERATING: s.operating = value === '1'; break;
      case WLAN_NET.COL_NAME: if (!s.name) s.name = value; break;
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
      case WLAN_RADIO.COL_TX_POWER: r.txPower = value; break;
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
      case WLAN_STATION.COL_IP4: if (value && value !== '0.0.0.0') c.ip4 = value; break;
      case WLAN_STATION.COL_VLAN: c.vlanId = toInt(value); break;
      case WLAN_STATION.COL_USER: if (!c.hostname) c.hostname = value; break;
      case WLAN_STATION.COL_EFF_TX: c.txRateMbps = toInt(value); break;
      case WLAN_STATION.COL_EFF_RX: c.rxRateMbps = toInt(value); break;
      case WLAN_STATION.COL_IP6: if (value && value !== '::') c.ip6 = value; break;
      case WLAN_STATION.COL_HOSTNAME: if (!c.hostname) c.hostname = value; break;
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
      name: get(SYS.setupName),
      swVersion: get(HW.swVersion),
      serialNumber: get(HW.serialNumber),
      modelNumber: get(HW.modelNumber),
      cpuType: get(HW.cpuType),
      uptimeText: get(SYS.operatingTime),
      cpuLoadPct: cpuRaw,
      memoryTotalKb: memTotal,
      memoryFreeKb: memFree,
      securityEngine: secEngine === '' ? null : secEngine === '1',
      bootCause: get(FIRMWARE.bootCause),
      featureWord: get(FIRMWARE.featureWord),
    },
    firmwareModules: [...firmwareBySlot.values()],
    lanPorts: [...lanPorts.entries()].map(([name, p]) => ({ name, ...p } as LcosLanPort)),
    wanIps: [...wanIps.entries()].map(([peer, w]) => ({ peer, ...w } as LcosWanIp)),
    networks,
    arp,
    dhcpLeases,
    vpnConnections,
    radios,
    ssids,
    clients: [...clientBySlot.values()],
    temperatureExtremes,
  };
}

/** Converts a dotted-quad netmask to its CIDR prefix length (null on bad input). */
function netmaskToPrefix(netmask: string): number | null {
  const parts = (netmask ?? '').split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  let prefix = 0;
  for (const part of parts) {
    let octet = part;
    while (octet & 0x80) { prefix++; octet = (octet << 1) & 0xff; }
    if (octet !== 0) return null; // non-contiguous mask — don't guess
  }
  return prefix === 0 ? null : prefix;
}

/**
 * Decodes the network-list interface enum (verified against the MIB):
 *   eLan1(256)…eLan16(271) → "LAN-<n-255>"
 *   eWlan1(512)/eWlan2(513) → "WLAN-1"/"WLAN-2" (higher WLAN/P2P values use an
 *   ambiguous radio/ifc encoding — return '' rather than guess a wrong label).
 */
function decodeNetIfc(raw: string): string {
  const n = Number(raw);
  if (!Number.isInteger(n)) return '';
  if (n >= 256 && n <= 511) return `LAN-${n - 255}`;
  if (n === 512 || n === 513) return `WLAN-${n - 511}`;
  return '';
}

/* ------------------------------------------------------------------ *
 * Fast path — byte-counter walks every poll → rx/tx rates (bits/s)
 * ------------------------------------------------------------------ */

interface CounterBaseline {
  ts: number;
  counters: Record<string, number>; // key = `${table}:${ifc}:${rx|tx}`
}

const counterCache = new Map<string, CounterBaseline>();

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
  let out: Map<string, string>;
  try {
    // Two small walks — run them concurrently (separate processes).
    const [lan, wan] = await Promise.all([
      snmpWalk(host, creds, [LAN_BYTES.base], opts),
      snmpWalk(host, creds, [WAN_BYTES.base], opts),
    ]);
    out = new Map<string, string>();
    for (const m of [lan, wan]) for (const [k, v] of m) out.set(k, v);
  } catch {
    return empty; // counters unavailable this cycle — rates stay null
  }

  const now = Date.now();
  const prev = counterCache.get(host);
  const next: CounterBaseline = { ts: now, counters: {} };

  const lanRates: LcosRates = {};
  for (const [oid, value] of out) {
    const row = splitRow(oid, LAN_BYTES.base);
    if (!row || row.col !== LAN_BYTES.COL_RX && row.col !== LAN_BYTES.COL_TX) continue;
    const key = decodeSingleText(row.idx);
    if (!key) continue;
    const n = Number(value);
    if (!Number.isFinite(n)) continue;
    const cKey = `lan:${key}:${row.col === LAN_BYTES.COL_RX ? 'rx' : 'tx'}`;
    next.counters[cKey] = n;
    rateFromBaseline(prev, now, cKey, n, lanRates, key);
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
    const cKey = `wan:${key}:${row.col === WAN_BYTES.COL_HRX ? 'rx' : 'tx'}`;
    next.counters[cKey] = n;
    rateFromBaseline(prev, now, cKey, n, wanRates, key);
  }

  counterCache.set(host, next);
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

/** Computes one direction's rate from the baseline, storing it into `rates`. */
function rateFromBaseline(
  prev: CounterBaseline | undefined,
  now: number,
  cKey: string,
  newVal: number,
  rates: LcosRates,
  ifcName: string
): void {
  const cur = rates[ifcName] ?? (rates[ifcName] = { rx: null, tx: null });
  if (!prev) return; // first sample — no baseline yet
  const oldVal = prev.counters[cKey];
  if (oldVal === undefined) return; // counter unseen in the previous cycle
  const dtSec = (now - prev.ts) / 1000;
  if (dtSec <= 0) return; // clock skew or duplicate poll within the same ms
  const delta = newVal - oldVal;
  if (delta < 0) return; // counter reset/wrap — skip this sample, re-baseline next cycle
  const bitsPerSec = Math.round((delta * 8) / dtSec);
  if (cKey.endsWith(':rx')) cur.rx = bitsPerSec;
  else cur.tx = bitsPerSec;
}
