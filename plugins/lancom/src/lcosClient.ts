/**
 * LCOS-LX-MIB collection for LANCOM LX-Series APs.
 *
 * Two tiers (mirrors the generic SNMP plugin):
 *  - SLOW path: targeted parallel walks over exactly the subtrees we use,
 *    TTL-cached per host. A broad `13.1` walk is NOT viable — it drags in
 *    huge tables we never read (bridge-VLAN membership ~2600 lines, an
 *    internal 13.1.100 table ~1400 lines) and takes ~30s RTT-bound on a real
 *    AP; the targeted set below completes in ~2s.
 *  - FAST path (every poll): counter-only walks for radio/port byte counters
 *    and the SNMP-event trap-counter table → rates + station event deltas.
 *
 * The MIB is read-only; this module only reads. Sensitive config-mirror fields
 * (WPA keys, RADIUS secrets, admin hashes, LMC tokens) are never walked — the
 * 13.2 setup tree is out of scope for monitoring by design.
 */

import { SnmpCredentials, TransportOptions, snmpGet, snmpWalk, suffixOf, normalizeMac } from '@unm/snmp-client';
import {
  LCOS_BASE, SYS, HW, STATION, RADIOS, WLAN_IF, CHANNEL_UTIL, ENV_SCAN, WDS,
  LAN_PORTS, LAN_BYTES, BRIDGE_VLAN, IP_ADDR, SNMP_EVENT,
  MGMT_STATE, AP_CONN, NET_PROFILE, LMC,
} from './lcosOids';

/* ------------------------------------------------------------------ *
 * Options + result types
 * ------------------------------------------------------------------ */

export interface LcosOptions extends TransportOptions {
  /** How long the slow-path snapshot stays fresh. */
  inventoryTtlMs: number;
  /** Cap for per-client / neighbor table payloads (rows). */
  maxClientRows: number;
}

/** One associated client from lcosLXStatusWLANStationTable. */
export interface LcosClient {
  mac: string; // normalized aa:bb:cc:dd:ee:ff
  ifc: string; // radio interface (e.g. "WLAN-1"), '' when absent
  hostname: string; // '' when absent (DHCP name / 802.1X user)
  username: string; // 802.1X identity, '' for PSK clients
  ip4: string; // '' when not yet assigned
  ip6: string;
  ssid: string;
  band: string; // '2.4 GHz' | '5 GHz' | '6 GHz' | ''
  signalDbm: number | null;
  txRateMbps: number | null;
  rxRateMbps: number | null;
  vlanId: number | null;
  wpa: string; // e.g. 'WPA2-PSK/CCMP', '' when unknown
  mode: string; // e11ax etc., '' when unknown
  sessionSeconds: number | null;
}

/** One radio from lcosLXStatusWLANRadios. */
export interface LcosRadio {
  ifc: string;
  band: string;
  channel: number | null;
  bandwidth: string; // '20 MHz'…'' when unknown
  mode: string; // e11ax etc., '' when unknown
  txPowerDbm: number | null;
  noiseFloorDbm: number | null;
  modemLoadPct: number | null;
  stations: number | null;
  temperatureC: number | null;
  dfsBlocked: boolean;
}

/** One SSID from lcosLXStatusWLANInterfaces (+ profile join). */
export interface LcosSsid {
  name: string; // networkName (profile) — display key
  ssid: string;
  bssid: string; // '' when unavailable
  band: string;
  vlanId: number | null;
  encryption: string; // 'WPA2-PSK' etc., '' when unknown
  maxStations: number | null;
  pskSuccess: number;
  pskFailures: number;
  pskWrongPassphrase: number;
}

/** One LAN port from lcosLXStatusLANPorts. */
export interface LcosPort {
  name: string;
  linkUp: boolean | null;
  speedLabel: string; // '1 Gbit' etc., '' when unknown
  mac: string; // '' when unavailable
}

/** One IP address row from lcosLXStatusIPConfigurationAddresses. */
export interface LcosIp {
  ifname: string;
  version: '4' | '6';
  address: string;
  gateway: string;
}

/** One WDS link from lcosLXStatusWLANWDSLinks. */
export interface LcosWdsLink {
  name: string;
  remoteMac: string;
  connected: boolean | null;
  signalDbm: number | null; // dBm (negated magnitude, verified live)
}

/** One neighbor AP from the environment scan table. */
export interface LcosNeighbor {
  bssid: string;
  ssid: string;
  channel: number | null;
  band: string;
  signalDbm: number | null;
}

/** CAPWAP/LMC management state summary. */
export interface LcosManagement {
  capwapState: string; // 'Run' | 'Off' | …, '' when not in CAPWAP mode
  controller: string; // IP of the WLC, '' when standalone
  lmcStatus: string; // combined management/control/monitor labels, '' when absent
}

/** The full slow-path snapshot for one host. */
export interface LcosSnapshot {
  collectedAt: number;
  isLancom: boolean; // false → device exposes no LCOS tree (wrong plugin target)
  system: {
    name: string;
    swVersion: string;
    serialNumber: string;
    uptimeSeconds: number | null;
    cpuLoadPct: number | null;
    memoryTotalKb: number | null;
    memoryFreeKb: number | null;
    bootcount: number | null;
  };
  radios: LcosRadio[];
  ssids: LcosSsid[];
  clients: LcosClient[];
  ports: LcosPort[];
  ips: LcosIp[];
  vlans: Array<{ ifname: string; vlanId: number; flags: string }>;
  wdsLinks: LcosWdsLink[];
  neighbors: LcosNeighbor[];
  channelUtilization: Array<{ channel: number; utilizationPct: number | null; overload: boolean }>;
  management: LcosManagement;
}

/* ------------------------------------------------------------------ *
 * Enum label maps (from the MIB's SYNTAX INTEGER value blocks)
 * ------------------------------------------------------------------ */

const RADIO_BANDS: Record<number, string> = { 1: '2.4 GHz', 2: '5 GHz', 3: '6 GHz' };
const BANDWIDTHS: Record<number, string> = { 0: '20 MHz', 1: '40 MHz', 2: '80 MHz', 3: '160 MHz', 255: 'auto' };
const PORT_SPEEDS: Record<number, string> = {
  1: '10 Mbit', 2: '10 Mbit FD', 3: '100 Mbit', 4: '100 Mbit FD', 6: '1 Gbit FD',
  9: '2.5 Gbit FD', 10: '5 Gbit FD', 11: '10 Gbit FD', 255: 'power down',
};
const STATION_STATES: Record<number, string> = {
  0: 'none', 2: 'authenticated', 3: 'connected', 8: 'key handshake', 9: 'associated', 10: '802.1X negotiation',
};
const ENCRYPTIONS: Record<number, string> = {
  0: 'WPA-PSK', 1: 'WPA-802.1X', 2: 'WEP-104', 3: 'WEP-40', 6: 'none', 7: 'enhanced open', 8: 'enhanced open (transitional)',
};
const CAPWAP_STATES: Record<number, string> = {
  0: 'unknown', 5: 'idle', 10: 'discovery', 15: 'DTLS setup', 20: 'join', 25: 'configure',
  30: 'image data', 35: 'reset', 40: 'DTLS teardown', 45: 'sulking', 100: 'run', 255: 'off',
};
const IP_VERSIONS: Record<number, '4' | '6'> = { 1: '4', 2: '6' };
const OP_MODES: Record<number, string> = { 1: '11b', 2: '11g', 3: '11a', 4: '11n', 5: '11ac', 6: '11ax', 7: '11be' };
const WPA_VERSIONS: Record<number, string> = { 0: '', 1: 'WPA1', 2: 'WPA2', 3: 'WPA3' };
/** LMC cloud status enums (shared by management/control/monitor scalars). */
const LMC_STATUS: Record<number, string> = {
  0: 'no LMC', 1: 'auth (inactive)', 2: 'disabled', 3: 'disabled by WLC', 4: 'operating',
  8: 'memory error', 9: 'waiting', 10: 'redirect', 11: 'auth error', 12: 'error',
  13: 'cert storage failed', 14: 'active', 15: 'cert gen aborted', 16: 'no activation code',
};

function label(map: Record<number, string>, raw: string | undefined): string {
  if (raw === undefined || raw === '') return '';
  const n = Number(raw);
  return Number.isFinite(n) ? map[n] ?? String(n) : raw;
}

/* ------------------------------------------------------------------ *
 * OID row decoding — LANCOM's LCOS agent addresses table rows COLUMN-FIRST:
 *   <table>.1.<column>.<index…>          (standard SNMP is index-first!)
 * and encodes OCTET STRING indices as LENGTH-PREFIXED decimal octets:
 *   "WLAN-1" → 6.87.76.65.78.45.49       (len=6, then ASCII bytes)
 * MAC-address indices are the raw six decimal octets (no length prefix):
 *   00:A0:57:7F:7E:51 → 0.160.87.127.126.81
 * Index columns are not-accessible, so row keys can ONLY be recovered from
 * the OID suffix — every table below has its index shape verified live.
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

/** Decodes a raw six-octet MAC index run to aa:bb:cc:dd:ee:ff (or null). */
function decodeMacIndex(parts: string[], start: number): string | null {
  if (start + 6 > parts.length) return null;
  const hex = parts.slice(start, start + 6).map((p) => Number(p).toString(16).padStart(2, '0')).join('');
  return normalizeMac(hex);
}

/** Decodes a length-prefixed colon-MAC text index ("c2:a0:57:7f:92:a0"). */
function decodeColonMacText(parts: string[], start: number): { mac: string; next: number } | null {
  const d = decodePrefixedText(parts, start);
  if (!d) return null;
  const mac = normalizeMac(d.text);
  return mac ? { mac, next: d.next } : null;
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

/** Decodes a single-component text index ("WLAN-1", "ETH1", profile names). */
function decodeSingleText(idx: string[]): string | null {
  const d = decodePrefixedText(idx, 0);
  return d && d.next === idx.length ? d.text : null;
}

/** Decodes a two-component [text, number] index (WLAN_IF: name + band). */
function decodeTextNumber(idx: string[]): { text: string; num: number } | null {
  const d = decodePrefixedText(idx, 0);
  if (!d || d.next !== idx.length - 1) return null;
  const n = Number(idx[d.next]);
  if (!Number.isInteger(n)) return null;
  return { text: d.text, num: n };
}

/** Decodes a [number, text] index (BRIDGE_VLAN: vlanId + ifname). */
function decodeNumberText(idx: string[]): { num: number; text: string } | null {
  const n = Number(idx[0]);
  if (!Number.isInteger(n) || idx.length < 2) return null;
  const d = decodePrefixedText(idx, 1);
  return d && d.next === idx.length ? { num: n, text: d.text } : null;
}

/** Decodes a [text, colon-MAC-text] index (WDS links — both parts prefixed). */
function decodeTextMac(idx: string[]): { text: string; mac: string } | null {
  const d = decodePrefixedText(idx, 0);
  if (!d) return null;
  const m = decodeColonMacText(idx, d.next);
  return m && m.next === idx.length ? { text: d.text, mac: m.mac } : null;
}

/** Decodes a single colon-MAC-text index (ENV_SCAN / COMPETING BSSIDs). */
function decodeBssidIndex(idx: string[]): string | null {
  const m = decodeColonMacText(idx, 0);
  return m && m.next === idx.length ? m.mac : null;
}

/** Decodes a [channel, ifcText, band] index (DFS scan results). */
function decodeChannelIfcBand(idx: string[]): { channel: number; ifc: string; band: number } | null {
  const ch = Number(idx[0]);
  if (!Number.isInteger(ch) || idx.length < 2) return null;
  const d = decodePrefixedText(idx, 1);
  if (!d || d.next !== idx.length - 1) return null;
  const band = Number(idx[d.next]);
  if (!Number.isInteger(band)) return null;
  return { channel: ch, ifc: d.text, band };
}

/** Decodes an IP_ADDR index [ifnameText, version, source, addrLiteral…]. */
function decodeIpAddrIndex(idx: string[]): { ifname: string; version: '4' | '6'; address: string } | null {
  const d = decodePrefixedText(idx, 0);
  if (!d) return null;
  const rest = idx.slice(d.next);
  if (rest.length < 3) return null; // need version + source + ≥1 addr part
  const version = IP_VERSIONS[Number(rest[0])];
  if (!version) return null;
  const addrParts = rest.slice(2);
  let address: string;
  if (version === '4') {
    if (addrParts.length !== 4 || !addrParts.every((p) => /^\d+$/.test(p) && Number(p) <= 255)) return null;
    address = addrParts.map(Number).join('.');
  } else {
    // IPv6 literal as ASCII octets ("fe80::2a0:…/64" / "::") — decode the text.
    const lit = decodePrefixedText(addrParts, 0);
    if (!lit || lit.next !== addrParts.length) return null;
    address = lit.text;
  }
  // The literal carries a CIDR prefix ("10.25.1.1/16") — strip it; the
  // generic inventory contract expects bare addresses.
  const slash = address.lastIndexOf('/');
  if (slash > 0) address = address.slice(0, slash);
  return { ifname: d.text, version, address };
}

/** Decodes an AP_CONN index (length-prefixed IP literal or hostname text). */
function decodeApConnIndex(idx: string[]): string | null {
  const d = decodePrefixedText(idx, 0);
  return d && d.next === idx.length ? d.text : null;
}

/** Decodes a STATION index (raw six-octet MAC) — the row key. */
function decodeStationIndex(idx: string[]): string | null {
  if (idx.length !== 6) return null;
  return decodeMacIndex(idx, 0);
}

/* ------------------------------------------------------------------ *
 * Slow path — one broad walk of the whole runtime-status subtree
 * ------------------------------------------------------------------ */

const inventoryCache = new Map<string, LcosSnapshot>();

/**
 * The exact subtrees the slow path needs — nothing else. Deliberately NOT a
 * single `13.1` walk: that subtree contains large tables we never read
 * (bridge-VLAN membership ~2600 lines, an internal 13.1.100 table ~1400 lines)
 * and takes ~30s RTT-bound on a real AP, while this set finishes in ~2s.
 * Each entry is one snmpwalk; they run in parallel (separate processes).
 */
const INVENTORY_WALKS: string[] = [
  `${LCOS_BASE}.1.2`, // uptime scalar
  `${LCOS_BASE}.2.1`, // device name — single config-mirror scalar (no secrets)
  `${LCOS_BASE}.3.10`, // firmware boot count — single config-mirror scalar
  HW.base, // system/hardware scalars (mem, serial, sw version, CPU load)
  RADIOS.base, // per-radio status
  WLAN_IF.base, // per-SSID runtime counters + BSSIDs
  STATION.base, // per-client station table
  CHANNEL_UTIL.base, // airtime utilization per channel
  ENV_SCAN.base, // neighbor APs (RF environment)
  // COMPETING + DFS tables are walked by the broad agent but not parsed yet —
  // they add ~1s of wall time for data no metric uses; re-enable with a parser.
  WDS.base, // WDS/mesh links
  LAN_PORTS.base, // per-port link state + MACs
  BRIDGE_VLAN.base, // VLAN membership (only .45.3 — NOT the whole 13.1.45 tree)
  IP_ADDR.base, // interface IP addresses + gateways
  MGMT_STATE, // CAPWAP mode scalar
  AP_CONN.base, // WTP→AC connections
  NET_PROFILE.base, // active SSID profiles (encryption, VLANs, limits)
  `${LCOS_BASE}.1.98`, // LMC cloud status scalars
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
): Promise<{ snapshot: LcosSnapshot | null; fromCache: boolean; error?: string }> {
  const cached = inventoryCache.get(host);
  if (cached && Date.now() - cached.collectedAt < opts.inventoryTtlMs) {
    return { snapshot: cached, fromCache: true };
  }

  // Probe gate: one cheap snmpget against a scalar every LX-Series AP exposes
  // (hardware-info sw version). Non-LANCOM devices answer "No Such Object" in
  // ~100ms and are rejected here instead of burning ~17 walks × timeout
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
    // Agent answered but has no LCOS tree — not a LANCOM LX AP.
    return { snapshot: null, fromCache: false, error: 'No LCOS-LX MIB data on this device.' };
  }

  const out = new Map<string, string>();
  for (const [k, v] of probe) out.set(k, v); // reuse the probed scalar

  // Walks run in small batches rather than all at once: embedded AP agents
  // have tiny concurrent-request queues, and a burst of ~19 parallel walks
  // (especially alongside the generic SNMP plugin polling the same agent)
  // makes them answer some walks with EMPTY views instead of timing out.
  // Batches of 4 keep total wall time around ~2s while staying well under
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
      console.error(`[lancom] inventory walk ${chunk[j]} failed:`, r.reason?.message ?? r.reason);
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
    } catch (err) {
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
    // Walks succeeded but returned nothing — this device is not a LANCOM LX AP.
    return { snapshot: null, fromCache: false, error: 'No LCOS-LX MIB data on this device.' };
  }

  const snapshot = parseLcosStatus(out, opts);

  // Quality gate before caching: the serial number comes from the hardware-info
  // WALK (13.1.47), not from the probe scalar — so a cached snapshot is only
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
function parseLcosStatus(out: Map<string, string>, opts: LcosOptions): LcosSnapshot {
  const get = (oid: string): string => out.get(oid) ?? '';

  // --- System scalars -------------------------------------------------
  const memTotal = Number(get(HW.totalMemoryKbytes));
  const memFree = Number(get(HW.freeMemoryKbytes));
  const cpuRaw = Number(get(HW.cpuLoad60sPercent));
  const uptime = Number(get(SYS.operatingTime));

  // --- Radios (index: ifc text "WLAN-1", length-prefixed) ---------------
  const radios = new Map<string, Partial<LcosRadio>>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, RADIOS.base);
    if (!row) continue;
    const key = decodeSingleText(row.idx);
    if (!key) continue;
    let r = radios.get(key);
    if (!r) { r = {}; radios.set(key, r); }
    switch (row.col) {
      case 2: r.band = label(RADIO_BANDS, value); break;
      case 3: r.channel = toInt(value); break;
      // Unsigned magnitude of the dBm noise floor — negate for display.
      case 4: { const n = toInt(value); if (n !== null) r.noiseFloorDbm = -n; } break;
      case 6: r.modemLoadPct = toInt(value); break;
      case 7: r.txPowerDbm = toInt(value); break;
      case 9: r.stations = toInt(value); break;
      case 14: r.mode = label(RADIO_MODES, value) || stripE(value); break;
      case 19: r.bandwidth = label(BANDWIDTHS, value); break;
      // cols 22/23 (rx/tx bytes Counter64) are fast-path only — skipped here.
      case 50: r.temperatureC = toInt(value); break;
      case 51: r.dfsBlocked = value === '1'; break;
    }
  }

  // --- SSIDs (index: [networkName text, band number]) --------------------
  const ssids = new Map<string, Partial<LcosSsid>>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, WLAN_IF.base);
    if (!row) continue;
    const key = decodeTextNumber(row.idx);
    if (!key) continue;
    let s = ssids.get(key.text);
    if (!s) { s = {}; ssids.set(key.text, s); }
    // Band is part of the INDEX (second component), not a column — set on
    // every row so it survives even when only one column is present.
    s.band = label(RADIO_BANDS, String(key.num));
    switch (row.col) {
      case 2: s.ssid = value; break;
      case 4: s.pskSuccess = Number(value) || 0; break;
      case 5: s.pskFailures = Number(value) || 0; break;
      case 6: s.pskWrongPassphrase = Number(value) || 0; break;
      case 10: s.bssid = normalizeMac(value); break;
    }
  }

  // --- Network profiles (index: profileName text) — join by name ---------
  for (const [oid, value] of out) {
    const row = splitRow(oid, NET_PROFILE.base);
    if (!row) continue;
    const key = decodeSingleText(row.idx);
    if (!key) continue;
    let s = ssids.get(key);
    if (!s) { s = {}; ssids.set(key, s); }
    switch (row.col) {
      case 6: s.encryption = label(ENCRYPTIONS, value); break;
      case 18: s.maxStations = toInt(value); break;
      case 21: if (!s.ssid) s.ssid = value; break;
      case 34: s.vlanId = toInt(value); break;
    }
  }

  // --- Stations (index: raw six-octet MAC) -------------------------------
  const clients: LcosClient[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, STATION.base);
    if (!row) continue;
    const mac = decodeStationIndex(row.idx);
    if (!mac) continue; // not MAC-shaped — skip defensively
    let c = clients.find((x) => x.mac === mac);
    if (!c) {
      c = {
        mac, ifc: '', hostname: '', username: '', ip4: '', ip6: '', ssid: '', band: '',
        signalDbm: null, txRateMbps: null, rxRateMbps: null, vlanId: null,
        wpa: '', mode: '', sessionSeconds: null,
      };
      clients.push(c);
    }
    switch (row.col) {
      case 2: c.band = label(RADIO_BANDS, value); break;
      case 3: c.ifc = value; // plain text value ("WLAN-1")
      // Verified live: connectTime is in CENTISECONDS (delta 75s → +750).
      case 18: { const n = toInt(value); if (n !== null) c.sessionSeconds = Math.round(n / 100); } break;
      case 27: c.ip4 = value; break;
      case 28: c.ip6 = value === '::' ? '' : value; break; // link-local/none → absent
      case 33: { const w = label(WPA_VERSIONS, value); if (w) c.wpa = w; } break;
      case 38: c.vlanId = toInt(value); break;
      case 39: c.username = value; break;
      // Pairwise cipher ("CCMP"…) — append to the WPA version.
      case 40: if (value) c.wpa = c.wpa ? `${c.wpa}/${stripE(value)}` : stripE(value); break;
      case 50: c.txRateMbps = toInt(value); break;
      case 51: c.rxRateMbps = toInt(value); break;
      case 71: c.mode = label(OP_MODES, value) || stripE(value); break;
      case 80: c.hostname = value; break;
      // Unsigned magnitude of the dBm signal — negate for display.
      case 97: { const n = toInt(value); if (n !== null) c.signalDbm = -n; } break;
      case 98: if (!c.ssid) c.ssid = value; break; // networkName fallback
      case 99: c.ssid = value || c.ssid; break;
    }
  }
  clients.sort((a, b) => a.mac.localeCompare(b.mac));

  // --- LAN ports (index: port name text "ETH1") ---------------------------
  const ports: LcosPort[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, LAN_PORTS.base);
    if (!row) continue;
    const key = decodeSingleText(row.idx);
    if (!key) continue;
    let p = ports.find((x) => x.name === key);
    if (!p) { p = { name: key, linkUp: null, speedLabel: '', mac: '' }; ports.push(p); }
    switch (row.col) {
      case 2: p.linkUp = value === '1'; break; // eNo(0)/eYes(1)
      case 3: p.speedLabel = label(PORT_SPEEDS, value); break;
      case 4: p.mac = normalizeMac(value); break;
    }
  }

  // --- IP addresses (index: [ifnameText, version, source, addrLiteral…]) --
  const ipRows = new Map<string, LcosIp>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, IP_ADDR.base);
    if (!row || row.col !== 5) continue; // only the gateway column carries data
    const dec = decodeIpAddrIndex(row.idx);
    if (!dec) continue;
    const key = `${dec.ifname}|${dec.version}|${dec.address}`;
    let ip = ipRows.get(key);
    if (!ip) { ip = { ifname: dec.ifname, version: dec.version, address: dec.address, gateway: '' }; ipRows.set(key, ip); }
    // "::" / empty mean no default route on that interface.
    if (value && value !== '::') ip.gateway = value;
  }
  const ips = [...ipRows.values()];

  // --- VLAN membership (index: [vlanId number, ifname text]) --------------
  const vlans: Array<{ ifname: string; vlanId: number; flags: string }> = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, BRIDGE_VLAN.base);
    if (!row || row.col !== 3) continue; // col 3 = flags ("PVID Egress Untagged"…)
    const dec = decodeNumberText(row.idx);
    if (!dec) continue;
    vlans.push({ ifname: dec.text, vlanId: dec.num, flags: value });
  }

  // --- WDS links (index: [linkName text, colon-MAC text]) -----------------
  const wdsLinks: LcosWdsLink[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, WDS.base);
    if (!row) continue;
    const dec = decodeTextMac(row.idx);
    if (!dec) continue;
    let l = wdsLinks.find((x) => x.remoteMac === dec.mac && x.name === dec.text);
    if (!l) { l = { name: dec.text, remoteMac: dec.mac, connected: null, signalDbm: null }; wdsLinks.push(l); }
    switch (row.col) {
      case 3: l.connected = value === '1'; break; // eYes(1)/eNo(0)
      // Unsigned magnitude of the dBm receive signal — negate for display.
      case 5: { const n = toInt(value); if (n !== null) l.signalDbm = -n; } break;
    }
  }

  // --- Environment scan neighbors (index: colon-MAC text BSSID) -----------
  const neighbors: LcosNeighbor[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, ENV_SCAN.base);
    if (!row) continue;
    const bssid = decodeBssidIndex(row.idx);
    if (!bssid) continue;
    let n = neighbors.find((x) => x.bssid === bssid);
    if (!n) { n = { bssid, ssid: '', channel: null, band: '', signalDbm: null }; neighbors.push(n); }
    switch (row.col) {
      case 2: n.ssid = value; break;
      case 8: n.channel = toInt(value); break;
      case 16: n.band = label(RADIO_BANDS, value); break;
      // Unsigned magnitude of the dBm signal — negate for display.
      case 26: { const num = toInt(value); if (num !== null) n.signalDbm = -num; } break;
    }
  }

  // --- Channel utilization (index: plain channel number) ------------------
  const channelUtilization: Array<{ channel: number; utilizationPct: number | null; overload: boolean }> = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, CHANNEL_UTIL.base);
    if (!row || row.idx.length !== 1) continue;
    const ch = Number(row.idx[0]);
    let e = channelUtilization.find((x) => x.channel === ch);
    if (!e) { e = { channel: ch, utilizationPct: null, overload: false }; channelUtilization.push(e); }
    if (row.col === 2) e.utilizationPct = toInt(value);
    else if (row.col === 3) e.overload = value !== '0';
  }

  // --- CAPWAP / LMC management state ------------------------------------
  const mgmtStateRaw = get(MGMT_STATE);
  let controller = '';
  for (const [oid] of out) {
    if (!suffixOf(oid, AP_CONN.base)) continue;
    const row = splitRow(oid, AP_CONN.base);
    if (!row || row.col !== 5) continue; // col 5 = connection name
    const idxText = decodeApConnIndex(row.idx);
    // Prefer an IP-literal index over a hostname for the controller address.
    if (idxText && /^\d+\.\d+\.\d+\.\d+$/.test(idxText)) controller = idxText;
  }

  return {
    collectedAt: Date.now(),
    isLancom: true,
    system: {
      name: get(SYS.setupName),
      swVersion: get(HW.swVersion),
      serialNumber: get(HW.serialNumber),
      uptimeSeconds: Number.isFinite(uptime) && uptime > 0 ? uptime : null,
      // Verified live: the value is already a percentage (5 → 5%).
      cpuLoadPct: Number.isFinite(cpuRaw) ? Math.min(100, Math.round(cpuRaw)) : null,
      memoryTotalKb: Number.isFinite(memTotal) && memTotal > 0 ? memTotal : null,
      memoryFreeKb: Number.isFinite(memFree) && memFree > 0 ? memFree : null,
      bootcount: toInt(get(SYS.bootcount)),
    },
    radios: [...radios.entries()].map(([ifc, r]) => ({
      ifc,
      band: r.band ?? '',
      channel: r.channel ?? null,
      bandwidth: r.bandwidth ?? '',
      mode: r.mode ?? '',
      txPowerDbm: r.txPowerDbm ?? null,
      noiseFloorDbm: r.noiseFloorDbm ?? null,
      modemLoadPct: r.modemLoadPct ?? null,
      stations: r.stations ?? null,
      temperatureC: r.temperatureC ?? null,
      dfsBlocked: r.dfsBlocked ?? false,
    })),
    ssids: [...ssids.entries()].map(([name, s]) => ({
      name,
      ssid: s.ssid || name,
      bssid: s.bssid || '',
      band: s.band || '',
      vlanId: s.vlanId ?? null,
      encryption: s.encryption || '',
      maxStations: s.maxStations ?? null,
      pskSuccess: s.pskSuccess ?? 0,
      pskFailures: s.pskFailures ?? 0,
      pskWrongPassphrase: s.pskWrongPassphrase ?? 0,
    })),
    clients: clients.slice(0, opts.maxClientRows),
    ports,
    ips,
    vlans,
    wdsLinks,
    neighbors: neighbors.slice(0, opts.maxClientRows),
    channelUtilization,
    management: {
      capwapState: label(CAPWAP_STATES, mgmtStateRaw) || stripE(mgmtStateRaw),
      controller,
      lmcStatus: summarizeLmc(get(LMC.managementStatus), get(LMC.controlStatus), get(LMC.monitorStatus)),
    },
  };
}

/** Radio mode enum (gapped numbering — from the MIB value block). */
const RADIO_MODES: Record<number, string> = {
  0: '11b/g', 1: '11g', 2: '11b', 5: '11b/g/n', 7: '11g/n', 8: '11n', 9: '11b/g/n/ax',
  10: '11g/n/ax', 11: '11b/g/n/ax/be', 12: '11g/n/ax/be', 255: 'off', 256: '11a',
  259: '11a/n', 263: '11a/n/ac', 264: '11n/ac', 265: '11ac', 266: '11a/n/ac/ax',
  267: '11a/n/ac/ax/be', 268: '11ax', 269: '11ax/be',
};

/** Strips the vendor "e" prefix from enum text values ("eRun" → "Run"). */
function stripE(v: string): string {
  return (v ?? '').replace(/^e/, '');
}

/** Combines the three LMC cloud status scalars into one readable summary. */
function summarizeLmc(mgmtRaw: string, ctrlRaw: string, monRaw: string): string {
  const parts = [
    `mgmt ${label(LMC_STATUS, mgmtRaw) || stripE(mgmtRaw)}`,
    `control ${label(LMC_STATUS, ctrlRaw) || stripE(ctrlRaw)}`,
    `monitor ${label(LMC_STATUS, monRaw) || stripE(monRaw)}`,
  ].filter((p) => p.split(' ')[1] !== '');
  return parts.join(', ');
}

/** Integer or null when absent/non-numeric. */
function toInt(v: string | undefined): number | null {
  if (v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/* ------------------------------------------------------------------ *
 * Fast path — counter-only walks for rates + station event deltas
 * ------------------------------------------------------------------ */

interface Baseline { value: number; at: number; }
const baselines = new Map<string, Baseline>();

/**
 * Walks the fast-path counters (radio bytes, LAN port bytes/CRC, SNMP-event
 * trap counters) and computes rates/deltas. Returns null on walk failure —
 * callers keep serving slow-path data without fresh rates.
 */
export async function walkLcosCounters(
  host: string,
  creds: SnmpCredentials,
  opts: LcosOptions
): Promise<{
  radioRates: Record<string, { rx: number | null; tx: number | null }>; // keyed by ifc
  portRates: Record<string, { rx: number | null; tx: number | null; crcPerSec: number | null }>; // keyed by port
  wifiEvents: Record<string, number>; // trap name → events since last poll
} | null> {
  try {
    const [radioOut, lanOut, eventOut] = await Promise.all([
      snmpWalk(host, creds, [RADIOS.base], opts),
      snmpWalk(host, creds, [LAN_BYTES.base], opts),
      snmpWalk(host, creds, [SNMP_EVENT.base], opts),
    ]);

    const now = Date.now();
    // Radio byte counters — column-first rows: <base>.1.<col>.<ifcText…>,
    // col 22 = TxBytes, col 23 = RxBytes (verified against {COLUMN} annotations).
    const radioRates: Record<string, { rx: number | null; tx: number | null }> = {};
    for (const [oid, value] of radioOut) {
      const row = splitRow(oid, RADIOS.base);
      if (!row || (row.col !== 22 && row.col !== 23)) continue;
      const key = decodeSingleText(row.idx);
      if (!key) continue;
      radioRates[key] ??= { rx: null, tx: null };
      const isTx = row.col === 22;
      const rate = sampleRate(`${host}:radio:${key}:${isTx ? 'tx' : 'rx'}`, Number(value), now);
      if (rate !== null) {
        if (isTx) radioRates[key].tx = rate;
        else radioRates[key].rx = rate;
      }
    }

    // LAN port byte/CRC counters — col 2 = TxBytes, col 3 = RxBytes, col 4 = CRC.
    const portRates: Record<string, { rx: number | null; tx: number | null; crcPerSec: number | null }> = {};
    for (const [oid, value] of lanOut) {
      const row = splitRow(oid, LAN_BYTES.base);
      if (!row || (row.col !== 2 && row.col !== 3 && row.col !== 4)) continue;
      const key = decodeSingleText(row.idx);
      if (!key) continue;
      portRates[key] ??= { rx: null, tx: null, crcPerSec: null };
      const rate = sampleRate(`${host}:port:${key}:${row.col}`, Number(value), now);
      if (rate === null) continue;
      if (row.col === 2) portRates[key].tx = rate;
      else if (row.col === 3) portRates[key].rx = rate;
      else portRates[key].crcPerSec = rate; // errors/s — usually 0, spikes on bad cabling
    }

    // Station lifecycle events: delta of the per-trap counter table. The trap
    // index is an OBJECT IDENTIFIER whose sub-identifier encoding the agent
    // shortens (verified live: [3,0,0,N] for trap N) — so instead of
    // reconstructing OIDs we join count rows to their NAME column (col 3),
    // which carries plain text ("AuthStation"…).
    const trapNames = new Map<string, string>();
    for (const [oid, value] of eventOut) {
      const row = splitRow(oid, SNMP_EVENT.base);
      if (!row || row.col !== 3) continue; // col 3 = name
      trapNames.set(row.idx.join('.'), value);
    }
    const wifiEvents: Record<string, number> = {};
    for (const [oid, value] of eventOut) {
      const row = splitRow(oid, SNMP_EVENT.base);
      if (!row || row.col !== 4) continue; // col 4 = count
      const name = TRAP_NAMES[trapNames.get(row.idx.join('.')) ?? ''];
      if (!name) continue;
      const delta = sampleDelta(`${host}:trap:${row.idx.join('.')}`, Number(value), now);
      if (delta !== null && delta > 0) wifiEvents[name] = (wifiEvents[name] ?? 0) + delta;
    }

    return { radioRates, portRates, wifiEvents };
  } catch {
    return null; // counter walk failed — slow-path data still served by caller
  }
}

/** Trap name (col-3 text from the event table) → short event key. */
const TRAP_NAMES: Record<string, string> = {
  AuthStation: 'auth',
  DeAuthStation: 'deauth',
  AssStation: 'assoc',
  ReAssStation: 'roam',
  DisAssStation: 'disassoc',
  AssRej: 'assocRejected',
  Connected: 'connected',
};

/** Counter → bits/s rate with reset/wrap skip (same pattern as the SNMP plugin). */
function sampleRate(key: string, current: number, now: number): number | null {
  const prev = baselines.get(key);
  baselines.set(key, { value: current, at: now });
  if (!prev || now <= prev.at) return null; // first sample — no delta yet
  if (current < prev.value) return null; // counter reset/wrap — skip this sample
  const seconds = (now - prev.at) / 1000;
  return ((current - prev.value) * 8) / seconds; // octets/s → bits/s
}

/** Counter → events-per-poll delta with reset skip. */
function sampleDelta(key: string, current: number, now: number): number | null {
  const prev = baselines.get(key);
  baselines.set(key, { value: current, at: now });
  if (!prev || now <= prev.at) return null;
  if (current < prev.value) return null; // counter reset — skip
  return current - prev.value;
}
