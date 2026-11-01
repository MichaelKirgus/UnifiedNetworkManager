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

import { SnmpCredentials, SnmpValue, TransportOptions, snmpGet, snmpWalkMulti, suffixOf, normalizeMac } from '@unm/snmp-client';
import { CounterTracker } from '@unm/plugin-sdk';
import {
  splitRow, decodeSingleText, decodeTextNumber, decodeNumberText, decodeTextMac, decodeBssidIndex,
  decodeChannelIfcBand, decodeStationIndex, decodeIpAddrIndex, decodeApConnIndex, label, toInt,
  createSnapshotCaches, runSlowPath, accumulateRate, LcosLogSink, ProbeOutcome,
} from '@unm/lancom-shared';
import {
  LCOS_BASE, SYS, HW, STATION, RADIOS, WLAN_IF, CHANNEL_UTIL, ENV_SCAN, WDS,
  LAN_PORTS, LAN_BYTES, BRIDGE_VLAN, IP_ADDR, SNMP_EVENT,
  MGMT_STATE, AP_CONN, NET_PROFILE, LMC, TIME, SETUP_TIME, lxTimezoneToIana,
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
  ifc: string; // radio interface it is broadcast on (e.g. "WLAN-1"), '' when unknown
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
const OP_MODES: Record<number, string> = { 1: '11b', 2: '11g', 3: '11a', 4: '11n', 5: '11ac', 6: '11ax', 7: '11be' };
const WPA_VERSIONS: Record<number, string> = { 0: '', 1: 'WPA1', 2: 'WPA2', 3: 'WPA3' };
/** LMC cloud status enums (shared by management/control/monitor scalars). */
const LMC_STATUS: Record<number, string> = {
  0: 'no LMC', 1: 'auth (inactive)', 2: 'disabled', 3: 'disabled by WLC', 4: 'operating',
  8: 'memory error', 9: 'waiting', 10: 'redirect', 11: 'auth error', 12: 'error',
  13: 'cert storage failed', 14: 'active', 15: 'cert gen aborted', 16: 'no activation code',
};

/* ------------------------------------------------------------------ *
 * OID row decoding (column-first + length-prefixed OCTET STRING / IP / MAC
 * indices) and enum/integer pickers now live in @unm/lancom-shared — imported
 * above. The decoders are pure functions of (oid, base); every table's index
 * shape is verified against the MIB / live hardware.
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ *
 * Slow path — one broad walk of the whole runtime-status subtree
 * ------------------------------------------------------------------ */

// Fresh-snapshot cache (TTL-gated) + a last-known map so a failed refresh can
// still fall back to the most recent data even after TTL expiry. Shared trio —
// see @unm/lancom-shared snapshotCache.ts.
const caches = createSnapshotCaches<LcosSnapshot>();

/**
 * The exact subtrees the slow path needs — nothing else. Deliberately NOT a
 * single `13.1` walk: that subtree contains large tables we never read
 * (bridge-VLAN membership ~2600 lines, an internal 13.1.100 table ~1400 lines)
 * and takes ~30s RTT-bound on a real AP, while this set finishes in ~2s.
 * All entries are walked together in one combined GetBulk stream (snmpWalkMulti).
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
 * Returns the cached LCOS-LX snapshot for a host, re-walking only when the
 * cache is empty or older than `inventoryTtlMs`. Never throws — degrades to
 * stale/empty data with an explanatory error. Partial walk failures (some
 * subtrees missing) still yield a usable snapshot; total failure does not.
 *
 * The orchestration (cache → probe gate → combined walk → quality gate → stale
 * fallback) is the shared @unm/lancom-shared slow-path runner; only the probe
 * step and parser are LX-specific. All inventory subtrees go out in ONE
 * strictly-sequential combined GetBulk stream (~2s on a real AP), which never
 * stresses the embedded agents' tiny concurrent-request queues.
 */
export async function getLcosInventory(
  host: string,
  creds: SnmpCredentials,
  opts: LcosOptions,
  log?: LcosLogSink,
  force = false
): Promise<{ snapshot: LcosSnapshot | null; fromCache: boolean; error?: string }> {
  // Probe gate: one cheap snmpget against a scalar every LX-Series AP exposes
  // (hardware-info sw version). Non-LANCOM devices answer "No Such Object" in
  // ~100ms and are rejected here instead of burning ~17 walks × timeout
  // budget; unreachable hosts fail fast on the single PDU.
  const probe = async (): Promise<ProbeOutcome> => {
    let m: Map<string, SnmpValue>;
    try {
      m = await snmpGet(host, creds, [HW.swVersion], opts);
    } catch {
      return { kind: 'transport-error', error: 'SNMP query failed — device unreachable or credentials rejected.' };
    }
    if (m.size === 0) return { kind: 'not-device' }; // agent answered but has no LCOS-LX tree
    return { kind: 'ok', seed: m };
  };

  return runSlowPath(caches, {
    host,
    creds,
    opts,
    log,
    probe,
    walks: () => INVENTORY_WALKS,
    force,
    parse: (out) => parseLcosStatus(out, opts),
    // Quality gate: the serial number comes from the hardware-info WALK
    // (13.1.47), not the probe scalar — only cache when that walk succeeded.
    isComplete: (s) => s.system.serialNumber !== '',
    errors: {
      walkFailed: 'SNMP walk of the LCOS status tree failed.',
      notDevice: 'No LCOS-LX MIB data on this device.',
      partial: 'Partial LCOS data — some SNMP walks failed; retrying next cycle.',
    },
  });
}

/** Parses the targeted LCOS walk output into a typed snapshot. */
function parseLcosStatus(out: Map<string, SnmpValue>, opts: LcosOptions): LcosSnapshot {
  const get = (oid: string): SnmpValue => out.get(oid) ?? '';

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
      // Signed dBm — the shared parser preserves the sign (no negation needed).
      case 4: r.noiseFloorDbm = toInt(value); break;
      case 6: r.modemLoadPct = toInt(value); break;
      case 7: r.txPowerDbm = toInt(value); break;
      case 9: r.stations = toInt(value); break;
      case 14: r.mode = label(RADIO_MODES, value) || stripE(value); break;
      case 19: r.bandwidth = label(BANDWIDTHS, value); break;
      // cols 22/23 (rx/tx bytes Counter64) are fast-path only — skipped here.
      case 50: r.temperatureC = toInt(value); break;
      case 51: r.dfsBlocked = Number(value) === 1; break;
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
      case 2: s.ssid = String(value); break;
      case 4: s.pskSuccess = Number(value) || 0; break;
      case 5: s.pskFailures = Number(value) || 0; break;
      case 6: s.pskWrongPassphrase = Number(value) || 0; break;
      // Radio interface ("WLAN-1") — joins the SSID row to its radio/channel.
      case 7: if (!s.ifc) s.ifc = String(value); break;
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
      case 21: if (!s.ssid) s.ssid = String(value); break;
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
      case 3: c.ifc = String(value); // plain text value ("WLAN-1")
      // Verified live: connectTime is in CENTISECONDS (delta 75s → +750).
      case 18: { const n = toInt(value); if (n !== null) c.sessionSeconds = Math.round(n / 100); } break;
      // LCOS reports "0.0.0.0" for stations without an IPv4 address — treat as absent,
      // otherwise it masks the station's real IPv6 in the merged host view.
      case 27: c.ip4 = value === '0.0.0.0' ? '' : String(value); break;
      case 28: c.ip6 = value === '::' ? '' : String(value); break; // link-local/none → absent
      case 33: { const w = label(WPA_VERSIONS, value); if (w) c.wpa = w; } break;
      case 38: c.vlanId = toInt(value); break;
      case 39: c.username = String(value); break;
      // Pairwise cipher ("CCMP"…) — append to the WPA version.
      case 40: if (value) c.wpa = c.wpa ? `${c.wpa}/${stripE(value)}` : stripE(value); break;
      case 50: c.txRateMbps = toInt(value); break;
      case 51: c.rxRateMbps = toInt(value); break;
      case 71: c.mode = label(OP_MODES, value) || stripE(value); break;
      case 80: c.hostname = String(value); break;
      // Unsigned magnitude of the dBm signal — negate for display.
      // Signed dBm — the shared parser preserves the sign.
      case 97: c.signalDbm = toInt(value); break;
      case 98: if (!c.ssid) c.ssid = String(value); break; // networkName fallback
      case 99: c.ssid = String(value) || c.ssid; break;
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
      case 2: p.linkUp = Number(value) === 1; break; // eNo(0)/eYes(1)
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
    if (value && value !== '::') ip.gateway = String(value);
  }
  const ips = [...ipRows.values()];

  // --- VLAN membership (index: [vlanId number, ifname text]) --------------
  const vlans: Array<{ ifname: string; vlanId: number; flags: string }> = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, BRIDGE_VLAN.base);
    if (!row || row.col !== 3) continue; // col 3 = flags ("PVID Egress Untagged"…)
    const dec = decodeNumberText(row.idx);
    if (!dec) continue;
    vlans.push({ ifname: dec.text, vlanId: dec.num, flags: String(value) });
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
      case 3: l.connected = Number(value) === 1; break; // eYes(1)/eNo(0)
      // Unsigned magnitude of the dBm receive signal — negate for display.
      // Gauge32 magnitude (verified live) — negate for display.
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
      case 2: n.ssid = String(value); break;
      case 8: n.channel = toInt(value); break;
      case 16: n.band = label(RADIO_BANDS, value); break;
      // Signed dBm — the shared parser preserves the sign.
      case 26: n.signalDbm = toInt(value); break;
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
    else if (row.col === 3) e.overload = Number(value) !== 0;
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
      name: String(get(SYS.setupName)),
      swVersion: String(get(HW.swVersion)),
      serialNumber: String(get(HW.serialNumber)),
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
      ifc: s.ifc || '',
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

/** Strips the vendor "e" prefix from enum text values ("eRun" → "Run"). Non-text values pass through as-is. */
function stripE(v: SnmpValue | undefined): string {
  if (typeof v !== 'string') return '';
  return v.replace(/^e/, '');
}

/** Combines the three LMC cloud status scalars into one readable summary. */
function summarizeLmc(mgmtRaw: SnmpValue, ctrlRaw: SnmpValue, monRaw: SnmpValue): string {
  const parts = [
    `mgmt ${label(LMC_STATUS, mgmtRaw) || stripE(mgmtRaw)}`,
    `control ${label(LMC_STATUS, ctrlRaw) || stripE(ctrlRaw)}`,
    `monitor ${label(LMC_STATUS, monRaw) || stripE(monRaw)}`,
  ].filter((p) => p.split(' ')[1] !== '');
  return parts.join(', ');
}

/* ------------------------------------------------------------------ *
 * Fast path — counter-only walks for rates + station event deltas
 * ------------------------------------------------------------------ */

// Shared counter-delta trackers (@unm/plugin-sdk): first sample → null,
// reset/wrap skipped, baseline always refreshed, stale hosts evicted.
const rateTracker = new CounterTracker(); // octets/s → bits/s
const deltaTracker = new CounterTracker({ toBitsPerSec: false }); // raw per-second deltas (trap counters)

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
    // All three counter tables in ONE combined walk (shared session). The
    // parsing loops below filter by their own base OID via splitRow(), so the
    // merged map is safe to reuse for each.
    const counters = await snmpWalkMulti(host, creds, [RADIOS.base, LAN_BYTES.base, SNMP_EVENT.base], opts);

    const now = Date.now();
    rateTracker.evictStale(now);
    deltaTracker.evictStale(now);
    // Radio byte counters — column-first rows: <base>.1.<col>.<ifcText…>,
    // col 22 = TxBytes, col 23 = RxBytes (verified against {COLUMN} annotations).
    const radioRates: Record<string, { rx: number | null; tx: number | null }> = {};
    for (const [oid, value] of counters) {
      const row = splitRow(oid, RADIOS.base);
      if (!row || (row.col !== 22 && row.col !== 23)) continue;
      const key = decodeSingleText(row.idx);
      if (!key) continue;
      const isTx = row.col === 22;
      radioRates[key] ??= { rx: null, tx: null }; // key exists even on the first (null) sample
      accumulateRate(radioRates, key, isTx ? 'tx' : 'rx', rateTracker.sample(`${host}:radio:${key}:${isTx ? 'tx' : 'rx'}`, Number(value), now), false);
    }

    // LAN port byte/CRC counters — col 2 = TxBytes, col 3 = RxBytes, col 4 = CRC.
    const portRates: Record<string, { rx: number | null; tx: number | null; crcPerSec: number | null }> = {};
    for (const [oid, value] of counters) {
      const row = splitRow(oid, LAN_BYTES.base);
      if (!row || (row.col !== 2 && row.col !== 3 && row.col !== 4)) continue;
      const key = decodeSingleText(row.idx);
      if (!key) continue;
      portRates[key] ??= { rx: null, tx: null, crcPerSec: null }; // carries the extra CRC field — manual assignment
      const rate = row.col === 4 ? deltaTracker.sample(`${host}:port:${key}:${row.col}`, Number(value), now) : rateTracker.sample(`${host}:port:${key}:${row.col}`, Number(value), now);
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
    const trapNames = new Map<string, SnmpValue>();
    for (const [oid, value] of counters) {
      const row = splitRow(oid, SNMP_EVENT.base);
      if (!row || row.col !== 3) continue; // col 3 = name
      trapNames.set(row.idx.join('.'), value);
    }
    const wifiEvents: Record<string, number> = {};
    for (const [oid, value] of counters) {
      const row = splitRow(oid, SNMP_EVENT.base);
      if (!row || row.col !== 4) continue; // col 4 = count
      const name = TRAP_NAMES[String(trapNames.get(row.idx.join('.')) ?? '')];
      if (!name) continue;
      const delta = deltaTracker.sample(`${host}:trap:${row.idx.join('.')}`, Number(value), now);
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

/* ------------------------------------------------------------------ *
 * Device clock (Time page) — fresh per-poll read, NOT from the TTL-cached
 * snapshot: drift is measured against the reading's own timestamp, so a
 * 15-minute-old cached wall clock would surface as fake drift.
 * ------------------------------------------------------------------ */

/** One device-clock reading for `system.deviceTime`. */
export interface LcosClock {
  /** Device-local wall clock, naive ISO ("2026-09-02T16:49:52"). */
  localIso: string;
  /** IANA zone from the setup-timezone enum (display only), null when unknown. */
  timezone: string | null;
  /** Current UTC offset in minutes (from lcosLXStatusCurrentTimeOffset, seconds). */
  utcOffsetMinutes: number | null;
  /** Absolute instant in epoch ms — pre-computed from the device's own UTC-epoch scalar. */
  epochMs: number;
}

/**
 * Reads the AP's clock with ONE cheap snmpGet of four scalars:
 *   - lcosLXStatusCurrentTimeEpoch (UTC seconds) → absolute instant, GROUND TRUTH for drift;
 *   - lcosLXStatusCurrentTime ("MM/DD/YYYY HH:mm:ss" local string — US date order, verified
 *     live against the epoch scalar) → display wall clock;
 *   - lcosLXStatusCurrentTimeOffset (signed UTC offset in seconds) → cross-validation + fixed-offset display;
 *   - lcosLXSetupTimeTimezone (IANA-ish enum) → zone name for display.
 * The string is cross-checked against epoch+offset: on any mismatch (e.g. a firmware
 * variant that reports DD/MM) the mathematically exact synthesized value wins.
 * Returns null when no usable instant comes back — the caller omits system.deviceTime.
 */
export async function readLcosClock(
  host: string,
  creds: SnmpCredentials,
  opts: LcosOptions
): Promise<LcosClock | null> {
  try {
    const m = await snmpGet(host, creds, [TIME.currentTime, TIME.epoch, TIME.offset, SETUP_TIME.timezone], opts);

    // Ground truth first — without a usable epoch there is no drift to report.
    const epochSec = toInt(m.get(TIME.epoch));
    if (epochSec === null || !Number.isFinite(epochSec) || epochSec <= 0) return null;
    const epochMs = Math.round(epochSec * 1000); // Unsigned32 — the 2106 wrap is irrelevant for drift

    const offsetSec = toInt(m.get(TIME.offset));
    const utcOffsetMinutes = offsetSec !== null && Number.isFinite(offsetSec) ? Math.round(offsetSec / 60) : null;

    // Display wall clock: parse the device's own string ("MM/DD/YYYY HH:mm:ss").
    let localIso: string | null = null;
    const raw = m.get(TIME.currentTime);
    if (typeof raw === 'string') {
      const mm = raw.trim().match(/^(\d{2})\/(\d{2})\/(\d{4}) (\d{2}):(\d{2})(?::(\d{2}))?$/);
      if (mm) localIso = `${mm[3]}-${mm[1]}-${mm[2]}T${mm[4]}:${mm[5]}:${mm[6] ?? '00'}`;
    }

    // Cross-validate / synthesize from epoch+offset (exact by construction).
    if (offsetSec !== null && Number.isFinite(offsetSec)) {
      const synth = new Date((epochSec + offsetSec) * 1000).toISOString().slice(0, 19);
      if (!localIso || localIso !== synth) localIso = synth; // missing or mismatched → trust the math
    } else if (!localIso) {
      return null; // no string AND no offset to synthesize from — nothing usable
    }

    const timezone = lxTimezoneToIana(toInt(m.get(SETUP_TIME.timezone)));
    return { localIso, timezone, utcOffsetMinutes, epochMs };
  } catch {
    return null; // clock read failed — the rest of the poll proceeds without it
  }
}
