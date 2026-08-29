// SNMP transport (snmpwalk, v1/v2c + v3 USM args, output parsing, MAC
// normalization) lives in the shared @unm/snmp-client package so every
// SNMP-based plugin uses one implementation.
import { SnmpCredentials, SnmpValue, TransportOptions, snmpWalk, suffixOf, normalizeMac } from '@unm/snmp-client';
import { CounterTracker, TtlCache } from '@unm/plugin-sdk';

// Re-exported so existing imports (index.ts) keep working unchanged.
export type { SnmpCredentials } from '@unm/snmp-client';

/** Plugin-level walk options on top of the shared transport knobs. */
export interface WalkOptions extends TransportOptions {
  /** How long the slow-path inventory snapshot stays fresh. */
  inventoryTtlMs: number;
  /** Collect 802.11 WLAN data (IEEE 802.11 MIBs). Default true — opt-out per device. */
  collectWifi?: boolean;
}

export interface SystemInfo {
  description: string;
  objectId: string;
  name: string;
  location: string;
  contact: string;
  uptimeSeconds: number | null;
}

export interface InterfaceInfo {
  ifIndex: string;
  name: string; // '' when the device exposes no name for this index
  type: string; // human-readable (e.g. 'ethernetCsmacd') or numeric fallback
  speedBps: number | null;
  mac: string; // '' when unavailable
  status: string; // 'up' | 'down' | 'testing' | 'unknown'
}

/** Octet counters per ifIndex (64-bit preferred, 32-bit fallback). */
export interface Counters {
  [ifIndex: string]: { inOctets: number; outOctets: number };
}

/** One access point / BSS as seen via the IEEE 802.11 MIBs. */
export interface WifiAccessPoint {
  ssid: string; // '' when the device doesn't expose one
  bssid: string; // normalized aa:bb:cc:dd:ee:ff, '' when unavailable
  channel: number | null;
  security: string; // 'open' | 'wep' | 'tkip' | 'ccmp' | numeric fallback, '' when unknown
}

/** One associated client (station) as seen via the IEEE 802.11 MIBs. */
export interface WifiClient {
  mac: string; // normalized aa:bb:cc:dd:ee:ff
  ssid: string; // '' when unavailable
  rateMbps: number | null; // best-effort — many devices don't expose per-station rates
}

/** WiFi facts for a host. `source` says which MIB revision supplied the data. */
export interface WifiInfo {
  accessPoints: WifiAccessPoint[];
  clients: WifiClient[];
  source: 'ieee802dot11-2' | 'legacy';
}

export interface InventorySnapshot {
  collectedAt: number;
  system: SystemInfo | null;
  interfaces: InterfaceInfo[];
  counters: Counters;
  /** True when the device exposes ifHC* (64-bit) counters. */
  useHc: boolean;
  /**
   * WiFi facts (IEEE 802.11 MIBs). `undefined` = collection was disabled for
   * this snapshot (collectWifi off); `null` = collected but the device exposes
   * no 802.11 data (normal on non-AP devices).
   */
  wifi?: WifiInfo | null;
}

export interface InventoryResult {
  snapshot: InventorySnapshot | null;
  /** True when the data came from the TTL cache (not re-walked this call). */
  fromCache: boolean;
  /** Set when the refresh attempt failed but a cached fallback was returned. */
  error?: string;
}

/* ------------------------------------------------------------------ *
 * OID map — numeric OIDs so we never depend on MIB name resolution.
 * Standard MIBs (SNMPv2-MIB, IF-MIB) ship with net-snmp itself; the
 * mounted volume is for vendor-specific MIBs that users may add later.
 * ------------------------------------------------------------------ */

// SNMPv2-MIB system group — scalar instances are addressed with a trailing ".0".
const SYS_BASE = '.1.3.6.1.2.1.1';
const SYSTEM_OIDS = {
  description: `${SYS_BASE}.1`, // sysDescr
  objectId: `${SYS_BASE}.2`, // sysObjectID
  uptime: `${SYS_BASE}.3`, // sysUpTime (Timeticks, 1/100 s)
  contact: `${SYS_BASE}.4`, // sysContact
  name: `${SYS_BASE}.5`, // sysName
  location: `${SYS_BASE}.6`, // sysLocation
} as const;

const IF_TABLE = '.1.3.6.1.2.1.2.2.1'; // ifTable (IF-MIB)
const IF_XTABLE = '.1.3.6.1.2.1.31.1.1.1'; // ifXTable (IF-MIB)

const COUNTERS_32 = { in: `${IF_TABLE}.10`, out: `${IF_TABLE}.16` };
const COUNTERS_HC = { in: '.1.3.6.1.2.1.31.1.1.1.6', out: '.1.3.6.1.2.1.31.1.1.1.10' };

const IF_TYPE_NAMES: Record<number, string> = {
  1: 'other',
  6: 'ethernetCsmacd',
  7: 'ieee8023MacBridge',
  14: 'propWireless',
  24: 'softwareLoopback',
  53: 'propVirtual',
  136: 'atm',
};

const OPER_STATUS_NAMES: Record<number, string> = { 1: 'up', 2: 'down', 3: 'testing' };

/* ------------------------------------------------------------------ *
 * IEEE 802.11 WLAN OIDs — two revisions, both numeric so we never depend
 * on MIB name resolution (see the OID map note above).
 *
 * Primary: newer AP-oriented revision under .1.3.6.1.2.1.105. The station
 * table base is confirmed; the BSS table base and column numbers below are
 * ASSUMED — verify against a live AP walk (`snmpwalk -O n <ap> 1.3.6.1.2.1.105`)
 * and adjust if a device disagrees (parsing degrades to '' per missing col).
 *
 * Fallback: legacy IEEE802dot11-MIB under .1.2.840.10036 (verified on LANCOM
 * LCOS APs): SSID + BSSID per wireless ifIndex and DSSS channel — but no
 * association table, so client enumeration is not possible from this revision.
 * ------------------------------------------------------------------ */

const WLAN_BASE = '.1.3.6.1.2.1.105'; // newer AP-oriented revision
const BSS_TABLE = `${WLAN_BASE}.1.2`; // ASSUMED base for the BSS table — verify on device
const STATION_TABLE = `${WLAN_BASE}.1.3`; // dot11StationTable (confirmed)

// Assumed column layout under each table row: <table>.<rowIndex>.<column>
const BSS_COLS = { bssid: 1, ssid: 2, channel: 3, security: 4 } as const;
const STATION_COLS = { mac: 1, ssid: 2, status: 3, rateMbps: 4 } as const;

// Legacy IEEE802dot11-MIB (.1.2.840.10036). Layouts verified by full walk on
// LANCOM LCOS APs (LX-6500), which address the station-config table as
// <table>.<column>.<ifIndex> — column before index, unlike usual SNMP tables:
const LEGACY_BASE = '.1.2.840.10036';
const LEGACY_STATION_CFG_LANCOM = `${LEGACY_BASE}.1.1.1`; // col 1 = BSSID (MAC), col 9 = dot11DesiredSSID
const LEGACY_STATION_CFG_STD = `${LEGACY_BASE}.1.1`; // standard layout <ifIndex>.<column> — best-effort fallback
const LEGACY_PHY_DSSS = `${LEGACY_BASE}.4.5`; // dot11CurrentChannel: 4.5.1.1.<ifIdx> (LANCOM) / 4.5.<ifIdx>.<col> (standard)

/** IEEE 802.11 security algorithm enum → short label (best-effort map). */
const WIFI_SECURITY_NAMES: Record<number, string> = {
  1: 'open',
  2: 'wep',
  3: 'tkip',
  4: 'ccmp',
};

/* ------------------------------------------------------------------ *
 * snmpwalk wrapper + output parsing
 * ------------------------------------------------------------------ */


/* ------------------------------------------------------------------ *
 * System group (SNMPv2-MIB) — slow path
 * ------------------------------------------------------------------ */

async function walkSystem(host: string, creds: SnmpCredentials, opts: WalkOptions): Promise<SystemInfo | null> {
  try {
    // One walk of the whole system subtree — snmpwalk only processes the FIRST
    // OID when given several, so a single broad subtree is both correct and faster.
    const out = await snmpWalk(host, creds, [SYS_BASE], opts);
    // Scalar instances are addressed with a trailing ".0".
    const get = (oid: string): SnmpValue => out.get(`${oid}.0`) ?? '';

    const uptimeTicks = Number(get(SYSTEM_OIDS.uptime));
    return {
      description: String(get(SYSTEM_OIDS.description)),
      objectId: String(get(SYSTEM_OIDS.objectId)),
      name: String(get(SYSTEM_OIDS.name)),
      location: String(get(SYSTEM_OIDS.location)),
      contact: String(get(SYSTEM_OIDS.contact)),
      uptimeSeconds: Number.isFinite(uptimeTicks) && uptimeTicks > 0 ? Math.round(uptimeTicks / 100) : null,
    };
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * Interface table (IF-MIB ifTable + ifXTable) — slow path
 * ------------------------------------------------------------------ */

interface TableResult {
  interfaces: InterfaceInfo[];
  counters: Counters;
  useHc: boolean;
}

async function walkTables(host: string, creds: SnmpCredentials, opts: WalkOptions): Promise<TableResult | null> {
  try {
    const [ifOut, xOut] = await Promise.all([
      snmpWalk(host, creds, [IF_TABLE], opts),
      snmpWalk(host, creds, [IF_XTABLE], opts).catch(() => new Map<string, SnmpValue>()),
    ]);

    // Accumulate per-ifIndex attributes from both tables.
    const byIndex = new Map<
      string,
      { name: string; type: number | null; speedBps: number | null; mac: string; operStatus: number | null }
    >();
    const counters: Counters = {};
    let useHc = false;

    const row = (idx: string) => {
      let r = byIndex.get(idx);
      if (!r) {
        r = { name: '', type: null, speedBps: null, mac: '', operStatus: null };
        byIndex.set(idx, r);
      }
      return r;
    };

    for (const [oid, value] of ifOut) {
      const suffix = suffixOf(oid, IF_TABLE); // e.g. "2.3" → field 2, index 3
      const dot = suffix.indexOf('.');
      if (dot < 0) continue;
      const field = Number(suffix.slice(0, dot));
      const idx = suffix.slice(dot + 1);

      switch (field) {
        case 2: // ifDescr — fallback name
          row(idx).name ||= String(value);
          break;
        case 3: {
          const n = Number(value);
          if (Number.isFinite(n)) row(idx).type = n;
          break;
        }
        case 5: {
          const n = Number(value); // ifSpeed (bits/s, saturates at 2^32)
          if (Number.isFinite(n)) row(idx).speedBps = n;
          break;
        }
        case 6:
          row(idx).mac = normalizeMac(value);
          break;
        case 8: {
          const n = Number(value); // ifOperStatus
          if (Number.isFinite(n)) row(idx).operStatus = n;
          break;
        }
        case 10: {
          const n = Number(value); // ifInOctets (32-bit)
          if (Number.isFinite(n)) {
            counters[idx] ??= { inOctets: 0, outOctets: 0 };
            counters[idx].inOctets = n;
          }
          break;
        }
        case 16: {
          const n = Number(value); // ifOutOctets (32-bit)
          if (Number.isFinite(n)) {
            counters[idx] ??= { inOctets: 0, outOctets: 0 };
            counters[idx].outOctets = n;
          }
          break;
        }
      }
    }

    for (const [oid, value] of xOut) {
      const suffix = suffixOf(oid, IF_XTABLE);
      const dot = suffix.indexOf('.');
      if (dot < 0) continue;
      const field = Number(suffix.slice(0, dot));
      const idx = suffix.slice(dot + 1);

      switch (field) {
        case 6: // ifHCInOctets (64-bit — preferred)
          useHc = true;
          counters[idx] ??= { inOctets: 0, outOctets: 0 };
          counters[idx].inOctets = Number(value);
          break;
        case 8: {
          const n = Number(value); // ifHighSpeed (bits/s — preferred over ifSpeed)
          if (Number.isFinite(n)) row(idx).speedBps = n;
          break;
        }
        case 10: // ifHCOutOctets (64-bit — preferred)
          useHc = true;
          counters[idx] ??= { inOctets: 0, outOctets: 0 };
          counters[idx].outOctets = Number(value);
          break;
        case 18: // ifName — preferred display name
          row(idx).name ||= String(value);
          break;
      }
    }

    const interfaces: InterfaceInfo[] = Array.from(byIndex.entries())
      .sort((a, b) => Number(a[0]) - Number(b[0]))
      .map(([ifIndex, r]) => ({
        ifIndex,
        name: r.name,
        type: r.type !== null ? IF_TYPE_NAMES[r.type] ?? String(r.type) : 'unknown',
        speedBps: r.speedBps,
        mac: r.mac,
        status: r.operStatus !== null ? OPER_STATUS_NAMES[r.operStatus] ?? 'unknown' : 'unknown',
      }));

    return { interfaces, counters, useHc };
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * WiFi / WLAN tables (IEEE 802.11 MIBs) — slow path, TTL-cached
 * ------------------------------------------------------------------ */

/**
 * Walks the IEEE 802.11 MIB trees for access-point + client facts. Tries the
 * newer AP-oriented revision first (.1.3.6.1.2.1.105); when it yields nothing,
 * falls back to the legacy IEEE802dot11-MIB (.1.2.840.10036) which provides
 * SSID/BSSID/channel per wireless ifIndex but no client (association) table.
 * Returns null when neither tree yields rows — normal for non-AP devices,
 * never an error. One broad subtree walk per revision: snmpwalk only processes
 * the FIRST OID given several.
 */
export async function walkWifi(
  host: string,
  creds: SnmpCredentials,
  opts: WalkOptions
): Promise<WifiInfo | null> {
  try {
    const out = await snmpWalk(host, creds, [WLAN_BASE], opts);
    if (out.size > 0) {
      const info = parseNewerWlan(out);
      if (info.accessPoints.length > 0 || info.clients.length > 0) return info;
    }
  } catch {
    // Newer tree absent or walk failed — try the legacy revision below.
  }

  try {
    const out = await snmpWalk(host, creds, [LEGACY_BASE], opts);
    if (out.size > 0) {
      const info = parseLegacyWlan(out);
      if (info.accessPoints.length > 0 || info.clients.length > 0) return info;
    }
  } catch {
    // No 802.11 MIB data at all — this device is not an AP (or hides it).
  }

  return null;
}

/** Parses the newer revision's BSS + station tables from one broad walk. */
function parseNewerWlan(out: Map<string, SnmpValue>): WifiInfo {
  const bssRows = new Map<string, Record<number, SnmpValue>>();
  const stationRows = new Map<string, Record<number, SnmpValue>>();

  for (const [oid, value] of out) {
    let tableBase = '';
    if (suffixOf(oid, BSS_TABLE)) tableBase = BSS_TABLE;
    else if (suffixOf(oid, STATION_TABLE)) tableBase = STATION_TABLE;
    else continue;

    const suffix = suffixOf(oid, tableBase); // "<rowIndex>.<column>"
    const dot = suffix.indexOf('.');
    if (dot < 0) continue;
    const idx = suffix.slice(0, dot);
    const col = Number(suffix.slice(dot + 1));
    if (!Number.isInteger(col)) continue;

    const rows = tableBase === BSS_TABLE ? bssRows : stationRows;
    let row = rows.get(idx);
    if (!row) {
      row = {};
      rows.set(idx, row);
    }
    row[col] = value;
  }

  const accessPoints: WifiAccessPoint[] = [...bssRows.entries()]
    .sort((a, b) => Number(a[0]) - Number(b[0]))
    .map(([, cols]) => ({
      ssid: String(cols[BSS_COLS.ssid] ?? ''),
      bssid: normalizeMac(cols[BSS_COLS.bssid] ?? ''), // '' when not MAC-shaped (layout differs)
      channel: toIntOrNull(cols[BSS_COLS.channel]),
      security: wifiSecurityLabel(cols[BSS_COLS.security]),
    }));

  const clients: WifiClient[] = [...stationRows.entries()]
    .sort((a, b) => Number(a[0]) - Number(b[0]))
    .map(([, cols]) => {
      // MAC is assumed at STATION_COLS.mac; when that value isn't MAC-shaped
      // (column layout differs on this device), scan the row for one.
      let mac = normalizeMac(cols[STATION_COLS.mac] ?? '');
      if (!mac) {
        for (const v of Object.values(cols)) {
          mac = normalizeMac(v);
          if (mac) break;
        }
      }
      return { mac, ssid: String(cols[STATION_COLS.ssid] ?? ''), rateMbps: toIntOrNull(cols[STATION_COLS.rateMbps]) };
    })
    .filter((c) => c.mac !== ''); // a station row without a MAC is useless for display

  return { accessPoints, clients, source: 'ieee802dot11-2' };
}

/**
 * Parses the legacy IEEE802dot11-MIB (.1.2.840.10036): AP rows per wireless
 * ifIndex with SSID + BSSID from the station-config table and channel from
 * the DSSS PHY table. Verified layout (LANCOM LCOS, full walk on LX-6500s):
 *   .1.2.840.10036.1.1.1.<column>.<ifIdx>  col 1 = BSSID, col 9 = SSID
 *   .1.2.840.10036.4.5.1.1.<ifIdx>         dot11CurrentChannel
 * A standard-layout config table (<table>.<ifIdx>.<column> under ...1.1) is
 * also accepted best-effort for other vendors. This revision has no
 * association/station table, so clients are always empty here — per-client
 * data needs the newer .1.3.6.1.2.1.105 tree or a vendor MIB. (Subtree 2.x on
 * LANCOM holds the AP's own radio MACs, not client stations.)
 */
function parseLegacyWlan(out: Map<string, SnmpValue>): WifiInfo {
  const aps = new Map<string, { ssid: string; bssid: string }>();
  const channels = new Map<string, number>();

  const apRow = (ifIndex: string) => {
    let r = aps.get(ifIndex);
    if (!r) {
      r = { ssid: '', bssid: '' };
      aps.set(ifIndex, r);
    }
    return r;
  };

  for (const [oid, value] of out) {
    // Station-config table — LANCOM layout <column>.<ifIndex> under ...1.1.1.
    let suffix = suffixOf(oid, LEGACY_STATION_CFG_LANCOM);
    if (suffix) {
      const dot = suffix.indexOf('.');
      const idxPart = suffix.slice(dot + 1);
      if (dot > 0 && !idxPart.includes('.')) {
        const col = Number(suffix.slice(0, dot));
        if (col === 1) apRow(idxPart).bssid ||= normalizeMac(value); // BSSID
        else if (col === 9 && value) apRow(idxPart).ssid = String(value); // dot11DesiredSSID
      }
      continue;
    }

    // Station-config table — standard layout <ifIndex>.<column> under ...1.1
    // (only rows that don't extend the LANCOM base reach here with 2 parts).
    suffix = suffixOf(oid, LEGACY_STATION_CFG_STD);
    const dot = suffix.indexOf('.');
    if (dot > 0 && !suffix.slice(dot + 1).includes('.')) {
      const col = Number(suffix.slice(dot + 1));
      if (col === 1) apRow(suffix.slice(0, dot)).bssid ||= normalizeMac(value);
      else if (col === 2 && value) apRow(suffix.slice(0, dot)).ssid = String(value); // best-effort column guess
    }

    // DSSS PHY table — current channel per ifIndex.
    suffix = suffixOf(oid, LEGACY_PHY_DSSS);
    const parts = suffix.split('.');
    let chIdx: string | null = null;
    if (parts.length === 3 && parts[0] === '1' && parts[1] === '1') chIdx = parts[2]; // LANCOM: 4.5.1.1.<ifIdx>
    else if (parts.length === 2) chIdx = parts[0]; // standard: 4.5.<ifIdx>.<col>
    if (chIdx !== null) {
      const n = Number(value);
      if (Number.isFinite(n) && n > 0) channels.set(chIdx, n);
    }
  }

  const accessPoints: WifiAccessPoint[] = [...aps.entries()]
    .sort((a, b) => Number(a[0]) - Number(b[0]))
    .filter(([ifIndex, r]) => r.ssid !== '' || r.bssid !== '' || channels.has(ifIndex))
    .map(([ifIndex, r]) => ({
      ssid: r.ssid,
      bssid: r.bssid,
      channel: channels.get(ifIndex) ?? null,
      security: '', // not exposed by this MIB revision
    }));

  return { accessPoints, clients: [], source: 'legacy' };
}

/** Integer or null when absent/non-numeric. */
function toIntOrNull(v: SnmpValue | undefined): number | null {
  if (v === undefined) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/** Security enum → label, numeric fallback for unknown values, '' when absent. */
function wifiSecurityLabel(raw: SnmpValue | undefined): string {
  if (raw === undefined || raw === '') return '';
  const n = Number(raw);
  if (!Number.isFinite(n)) return String(raw); // already a text value — keep as-is
  return WIFI_SECURITY_NAMES[n] ?? String(n);
}

/* ------------------------------------------------------------------ *
 * Inventory cache (slow path, TTL-based — opnsense LIVE/INVENTORY split)
 * ------------------------------------------------------------------ */

// Fresh-snapshot cache (TTL-gated) + a last-known map so a failed refresh can
// still fall back to the most recent data even after TTL expiry.
const inventoryCache = new TtlCache<InventorySnapshot>();
const lastKnown = new Map<string, InventorySnapshot>();
function rememberLastKnown(host: string, snapshot: InventorySnapshot): void {
  lastKnown.set(host, snapshot);
  if (lastKnown.size > 512) {
    const oldest = lastKnown.keys().next().value; // Map iteration = insertion order
    if (oldest !== undefined) lastKnown.delete(oldest);
  }
}

/**
 * Returns the cached inventory snapshot for a host, performing the slow
 * walks only when the cache is empty or older than `inventoryTtlMs`.
 * Never throws — degrades to stale/empty data with an explanatory error.
 */
export async function getInventory(
  host: string,
  creds: SnmpCredentials,
  opts: WalkOptions
): Promise<InventoryResult> {
  // WiFi collection is ON by default — only an explicit false disables it.
  const collectWifi = opts.collectWifi !== false;

  const cached = inventoryCache.get(host, opts.inventoryTtlMs);
  if (cached) {
    // A cache hit is only fresh enough when the WiFi state matches: toggling
    // collectWifi on must not wait for TTL expiry to get first data.
    const wifiStale = collectWifi && cached.wifi === undefined;
    if (!wifiStale) return { snapshot: cached, fromCache: true };
  }
  const stale = lastKnown.get(host); // expired-but-usable fallback

  // System group, interface tables and (optionally) WLAN tables are independent — walk in parallel.
  const [system, tables, wifi] = await Promise.all([
    walkSystem(host, creds, opts).catch(() => null),
    walkTables(host, creds, opts).catch(() => null),
    collectWifi ? walkWifi(host, creds, opts).catch(() => null) : Promise.resolve(undefined as WifiInfo | undefined),
  ]);

  if (!system && !tables) {
    return {
      snapshot: stale ?? null,
      fromCache: stale !== undefined,
      error: 'SNMP walks failed — no system or interface data could be collected.',
    };
  }

  const fallback = cached ?? stale; // merge base for partial refreshes
  const snapshot: InventorySnapshot = {
    collectedAt: Date.now(),
    system: system ?? fallback?.system ?? null,
    interfaces: tables && tables.interfaces.length > 0 ? tables.interfaces : (fallback?.interfaces ?? []),
    counters: tables?.counters ?? {},
    useHc: tables?.useHc ?? false,
    // undefined = collection disabled; null = collected but no 802.11 data.
    wifi: collectWifi ? (wifi ?? fallback?.wifi ?? null) : undefined,
  };
  inventoryCache.set(host, snapshot);
  rememberLastKnown(host, snapshot);

  // Partial failure is worth surfacing even though we have usable data.
  const error = !system && fallback?.system ? undefined : !system ? 'System group walk failed.' : undefined;
  return { snapshot, fromCache: false, ...(error ? { error } : {}) };
}

/* ------------------------------------------------------------------ *
 * Fast path — counter-only walk for per-cycle rate computation
 * ------------------------------------------------------------------ */

/**
 * Walks just the traffic counters (64-bit when the device has them).
 * Two parallel single-OID walks — snmpwalk only processes the FIRST OID when
 * given several, so in/out must be separate calls.
 */
export async function walkCounters(
  host: string,
  creds: SnmpCredentials,
  opts: WalkOptions,
  useHc: boolean
): Promise<Counters | null> {
  const inBase = useHc ? COUNTERS_HC.in : COUNTERS_32.in;
  const outBase = useHc ? COUNTERS_HC.out : COUNTERS_32.out;

  try {
    const [inOut, outOut] = await Promise.all([
      snmpWalk(host, creds, [inBase], opts),
      snmpWalk(host, creds, [outBase], opts),
    ]);

    const counters: Counters = {};
    for (const [oid, value] of inOut) {
      const n = Number(value);
      if (!Number.isFinite(n)) continue;
      const idx = suffixOf(oid, inBase);
      if (!idx) continue;
      counters[idx] ??= { inOctets: 0, outOctets: 0 };
      counters[idx].inOctets = n;
    }
    for (const [oid, value] of outOut) {
      const n = Number(value);
      if (!Number.isFinite(n)) continue;
      const idx = suffixOf(oid, outBase);
      if (!idx) continue;
      counters[idx] ??= { inOctets: 0, outOctets: 0 };
      counters[idx].outOctets = n;
    }
    return counters;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * Rate computation (counter deltas → bits/s) with baseline cache
 * ------------------------------------------------------------------ */

// Shared counter-delta tracker (@unm/plugin-sdk): first sample → null,
// reset/wrap skipped, baseline always refreshed, stale hosts evicted.
const rateTracker = new CounterTracker();

/**
 * Computes per-interface rx/tx rates in bits/s from the current counters and
 * updates the baseline cache. Returns null for a direction when there is no
 * previous sample yet or the counter reset/wrapped (new < old).
 */
export function computeRates(
  host: string,
  counters: Counters
): Record<string, { rx: number | null; tx: number | null }> {
  const now = Date.now();
  rateTracker.evictStale(now);
  const rates: Record<string, { rx: number | null; tx: number | null }> = {};

  for (const [ifIndex, c] of Object.entries(counters)) {
    rates[ifIndex] = {
      rx: rateTracker.sample(`${host}:${ifIndex}:in`, c.inOctets, now),
      tx: rateTracker.sample(`${host}:${ifIndex}:out`, c.outOctets, now),
    };
  }
  return rates;
}
