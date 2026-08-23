/**
 * Monitoring snapshot collection for SwOS / SwOS Lite switches.
 *
 * The API polls /monitoring every 30 s with a HARD 10 s timeout, so the full
 * switch state (system + link + poe + lag + vlans + snmp + mac table) is
 * TTL-cached per host: fresh polls reuse the last good snapshot; only stale or
 * missing snapshots trigger a re-collection. A failed re-collection still
 * serves the stale data with health 'warning' rather than dropping to critical
 * (the switch is reachable — one endpoint just misbehaved).
 */

import { createHash } from 'crypto';
import { SwosClient, SwosData, decodeHexString, decodeMac, decodeIpLe, decodePortMask } from './swosClient';
import { SwosPlatform, createPlatform, getField, hasField } from './platform';

export interface SwosOptions {
  /** How long a collected snapshot stays fresh (ms). */
  cacheTtlMs: number;
  /** Per-request timeout for individual .b fetches (ms). */
  requestTimeoutMs: number;
}

export const DEFAULT_OPTIONS: SwosOptions = {
  cacheTtlMs: 60_000,
  requestTimeoutMs: 4_000,
};

// --- Snapshot types -----------------------------------------------------------------

export interface PortInfo {
  port: number; // 1-based
  name: string;
  enabled: boolean;
  linkUp: boolean;
  speedLabel: string;
  duplex: 'full' | 'half' | 'unknown';
  autoNegotiation: boolean;
}

export interface PoePort {
  port: number;
  mode: string; // off | on | auto
  status: string;
  powerW: number | null;
  voltageV: number | null;
  currentMa: number | null;
  lldpEnabled: boolean;
}

export interface LagPort {
  port: number;
  mode: string; // passive | active | static
  group: number;
  partnerMac: string;
}

export interface VlanRow {
  id: number;
  name: string | null; // SwOS only — null on Lite
  members: number[]; // 1-based port numbers
  igmpSnooping: boolean;
}

export interface PortVlanRow {
  port: number;
  mode: string;
  receive: string;
  defaultVlanId: number | null;
  forceVlanId: boolean;
}

export interface MacEntry {
  mac: string;
  intf: string; // 'port N'
}

export interface SwosSnapshot {
  platformType: 'swos' | 'swos-lite';
  platformName: string;
  identity: string;
  model: string;
  firmwareVersion: string;
  macAddress: string;
  serialNumber: string;
  uptimeSeconds: number | null;
  currentIp: string;
  addressAcquisition: string;
  allowFrom: string;
  ports: PortInfo[];
  poe: PoePort[] | null; // null = no PoE hardware
  lag: LagPort[] | null; // null = no LAG/LACP support
  vlans: VlanRow[];
  portVlans: PortVlanRow[];
  snmp: { enabled: boolean; community: string; contact: string; location: string } | null;
  macs: MacEntry[];
  sfpRows: Record<string, string>[]; // best-effort raw SFP diagnostics
  /** Per-port throughput from stats.b (null when the endpoint is unsupported). */
  portStats: PortStat[] | null;
  totalRxBitsPerSec: number | null;
  totalTxBitsPerSec: number | null;
}

/** One row of per-port traffic statistics. Rates are null until a second sample exists. */
export interface PortStat {
  port: number; // 1-based
  name: string;
  rxBytesTotal: number;
  txBytesTotal: number;
  rxBitsPerSec: number | null;
  txBitsPerSec: number | null;
}

// --- Value maps (from the reference project's confirmed device observations) --------

const SPEED_LABELS: Record<number, string> = {
  0: 'down',
  1: '10M',
  2: '100M',
  3: '1G',
  4: '5G', // estimated by the reference (between 2.5G and 10G)
  5: '2.5G',
  6: '10G',
  7: '10G',
  8: '25G',
  9: '40G',
  10: '50G',
  11: '100G',
};

const POE_MODES = ['off', 'on', 'auto'];
const POE_STATUS: Record<number, string> = { 0: 'disabled', 2: 'waiting for load', 3: 'powered on', 5: 'short circuit', 6: 'overload' };
const LACP_MODES = ['passive', 'active', 'static'];
const ADDR_ACQ = ['DHCP with fallback', 'static', 'DHCP only'];
const VLAN_RECEIVE = ['Any', 'Only Tagged', 'Only Untagged'];

function num(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) ? Math.floor(v) : 0;
}

// --- Collection ---------------------------------------------------------------------

/** Parses the !dhost.b MAC table.
 *  - SwOS Lite: `{i01:'<mac hex>', i02:<port index>}` (index is 0-based).
 *  - SwOS:      `{adr:'<mac hex>', vid:<vlan>, prt:<port bitmask>}` — verified on a
 *    CSS309/CRS309 (SwOS 2.18): `prt` is a BITMASK of physical ports, so an entry
 *    can span several ports (e.g. 0x82 = ports 1+8). Entries with no port bit set
 *    are CPU-side/internal MACs and are skipped.
 */
function parseMacTable(data: SwosData): MacEntry[] {
  if (!Array.isArray(data)) return [];
  const out: MacEntry[] = [];
  for (const entry of data) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const e = entry as Record<string, unknown>;

    // SwOS format (verified on real hardware).
    if (typeof e['adr'] === 'string') {
      const mac = decodeMac(e['adr']);
      if (!mac) continue;
      const mask = num(e['prt']);
      const portNums: number[] = [];
      for (let i = 0; i < 64; i++) if (Math.floor(mask / 2 ** i) % 2 === 1) portNums.push(i + 1);
      if (portNums.length === 0) continue; // no physical port — internal/CPU entry
      out.push({ mac, intf: `port ${portNums.join('+')}` });
      continue;
    }

    // SwOS Lite format.
    const mac = decodeMac(e['i01']);
    if (!mac) continue;
    const idx = num(e['i02']);
    out.push({ mac, intf: `port ${idx + 1}` });
  }
  return out;
}

/** Collects one full snapshot from the switch. Throws on transport/auth failure. */
export async function collectSnapshot(client: SwosClient): Promise<SwosSnapshot> {
  const platform = await createPlatform(client);
  const map = platform.map;
  // Reuse the sys.b body that identified the platform (no second fetch).
  const sys = platform.systemData ?? ((await client.get('sys.b')) as Record<string, unknown>);

  // --- system ------------------------------------------------------------------
  const identity = decodeHexString(getField(sys, map, 'systemIdentity'));
  const model = decodeHexString(getField(sys, map, 'systemModel'));
  const firmwareVersion = decodeHexString(getField(sys, map, 'systemVersion'));
  const macAddress = decodeMac(getField(sys, map, 'systemMac'));
  const serialNumber = decodeHexString(getField(sys, map, 'systemSerial'));
// Verified on a CRS309 (SwOS 2.18): upt increments at exactly 100/s → CENTIseconds.
    // The reference project's "uptime in seconds" assumption is wrong for SwOS.
    const uptimeRaw = getField(sys, map, 'systemUptime');
  const currentIp = decodeIpLe(getField(sys, map, 'systemCurrentIp'));

  const acqMode = num(getField(sys, map, 'systemAddressAcquisition'));
  const allowFromIp = num(getField(sys, map, 'systemAllowFromIp'));
  const allowFromBits = num(getField(sys, map, 'systemAllowFromBits'));
  let allowFrom = '';
  if (allowFromIp > 0) {
    allowFrom = decodeIpLe(allowFromIp);
    if (allowFromBits > 0) allowFrom += `/${allowFromBits}`;
  }

  // --- parallel endpoint fetches (best-effort each) ------------------------------
  const [hasPoe, hasLacp, hasSnmp] = await Promise.all([platform.hasPoe(), platform.hasLacp(), platform.hasSnmp()]);
  const [linkRes, poeRes, lagRes, vlanTableRes, vlanPortRes, snmpRes, sfpRes, dhostRes, statsRes] = await Promise.allSettled([
    client.get('link.b'),
    hasPoe ? client.get('poe.b') : Promise.resolve(null),
    hasLacp ? client.get('lacp.b') : Promise.resolve(null),
    client.get('vlan.b'),
    client.get('fwd.b'),
    hasSnmp ? client.get('snmp.b') : Promise.resolve(null),
    client.get('sfp.b').catch(() => null), // read-only diagnostics; absent on many models
    client.get('!dhost.b').catch(() => null),
    client.get('stats.b').catch(() => null), // cumulative per-port counters (Web UI's stats table)
  ]);

  const portCount = await platform.portCount();

  // --- ports ---------------------------------------------------------------------
  let ports: PortInfo[] = [];
  let portNames: string[] = []; // hoisted — also labels the stats.b rows
  if (linkRes.status === 'fulfilled' && linkRes.value) {
    const link = linkRes.value as Record<string, unknown>;
    const namesRaw = getField(link, map, 'portNames');
    const names: string[] = Array.isArray(namesRaw) ? namesRaw.map((n) => decodeHexString(n)) : [];
    portNames = names;
    const enabledMask = num(getField(link, map, 'portEnabled'));
    const autoNegMask = num(getField(link, map, 'portAutoNeg'));
    const linkUpMask = num(getField(link, map, 'portLinkUp'));
    const duplexStatusRaw = getField(link, map, 'portDuplexStatus');
    const speedRaw = getField(link, map, 'portSpeed');
    const statusArr: unknown[] | null = hasField(map, 'portLinkStatus') && Array.isArray(getField(link, map, 'portLinkStatus')) ? (getField(link, map, 'portLinkStatus') as unknown[]) : null;

    for (let i = 0; i < names.length; i++) {
      const speedCode = Array.isArray(speedRaw) ? num((speedRaw as unknown[])[i]) : -1;
      let linkUp: boolean;
      if (statusArr && statusArr[i] !== undefined) {
        // SwOS Lite reports per-port status codes (0x02 = up, 0x07 = no link).
        const code = num(statusArr[i]);
        linkUp = code === 0x02;
      } else {
        linkUp = !!(linkUpMask & (1 << i)); // SwOS 'lnk' bitmask
      }
      let duplex: PortInfo['duplex'] = 'unknown';
      if (Array.isArray(duplexStatusRaw)) {
        // SwOS Lite reports a per-port status array.
        const d = num((duplexStatusRaw as unknown[])[i]);
        if (d === 1) duplex = 'full';
        else if (d === 0 && linkUp) duplex = 'half';
      } else if (typeof duplexStatusRaw === 'number') {
        // SwOS reports a full-duplex BITMASK (verified on CRS309: dpx=511, all up).
        if ((duplexStatusRaw & (1 << i)) !== 0) duplex = linkUp ? 'full' : 'unknown';
      }
      ports.push({
        port: i + 1,
        name: names[i] || `Port ${i + 1}`,
        enabled: !!(enabledMask & (1 << i)),
        linkUp,
        speedLabel: SPEED_LABELS[speedCode] ?? (speedCode >= 0 ? String(speedCode) : 'unknown'),
        duplex,
        autoNegotiation: !!(autoNegMask & (1 << i)),
      });
    }
  }

  // --- PoE -----------------------------------------------------------------------
  let poe: PoePort[] | null = null;
  if (poeRes.status === 'fulfilled' && poeRes.value) {
    const d = poeRes.value as Record<string, unknown>;
    const modesRaw = getField(d, map, 'poeMode');
    if (Array.isArray(modesRaw)) {
      const prioRaw = getField(d, map, 'poePriority') as unknown[] | undefined;
      const voltRaw = getField(d, map, 'poeVoltage') as unknown[] | undefined;
      const statusRaw = getField(d, map, 'poeStatus') as unknown[] | undefined;
      const curRaw = getField(d, map, 'poeCurrent') as unknown[] | undefined;
      const voltActRaw = getField(d, map, 'poeVoltageActual') as unknown[] | undefined;
      const pwrRaw = getField(d, map, 'poePower') as unknown[] | undefined;
      const lldpMask = num(getField(d, map, 'poeLldp'));
      poe = (modesRaw as unknown[]).map((m, i) => {
        const modeCode = num(m);
        const powerW = pwrRaw && typeof pwrRaw[i] === 'number' && (pwrRaw[i] as number) > 0 ? Math.round(((pwrRaw[i] as number) / 10) * 10) / 10 : null; // wire unit: 0.1 W
        const voltageV = voltActRaw && typeof voltActRaw[i] === 'number' && (voltActRaw[i] as number) > 0 ? Math.round(((voltActRaw[i] as number) / 10) * 10) / 10 : null; // wire unit: 0.1 V
        const currentMa = curRaw && typeof curRaw[i] === 'number' && (curRaw[i] as number) > 0 ? (curRaw[i] as number) : null;
        return {
          port: i + 1,
          mode: POE_MODES[modeCode] ?? `Unknown(0x${modeCode.toString(16)})`,
          status: POE_STATUS[num(statusRaw?.[i])] ?? 'unknown',
          powerW,
          voltageV,
          currentMa,
          lldpEnabled: !!(lldpMask & (1 << i)),
        };
      });
    } else {
      poe = [];
    }
  }

  // --- LAG/LACP --------------------------------------------------------------------
  let lag: LagPort[] | null = null;
  if (lagRes.status === 'fulfilled' && lagRes.value) {
    const d = lagRes.value as Record<string, unknown>;
    const modesRaw = getField(d, map, 'lagMode');
    if (Array.isArray(modesRaw)) {
      const groupsRaw = getField(d, map, 'lagGroup') as unknown[] | undefined;
      const partnersRaw = getField(d, map, 'lagPartner') as unknown[] | undefined;
      lag = (modesRaw as unknown[]).map((m, i) => ({
        port: i + 1,
        mode: LACP_MODES[num(m)] ?? `Unknown(0x${num(m).toString(16)})`,
        group: groupsRaw && typeof groupsRaw[i] === 'number' ? (groupsRaw[i] as number) : 0,
        partnerMac: partnersRaw && typeof partnersRaw[i] === 'string' ? decodeMac(partnersRaw[i]) : '',
      }));
    } else {
      lag = [];
    }
  }

  // --- VLAN table -------------------------------------------------------------------
  const vlans: VlanRow[] = [];
  if (vlanTableRes.status === 'fulfilled' && Array.isArray(vlanTableRes.value)) {
    for (const entry of vlanTableRes.value) {
      if (!entry || typeof entry !== 'object') continue;
      const e = entry as Record<string, unknown>;
      const id = num(getField(e, map, 'vlanId'));
      if (id <= 0) continue;
      const membersMask = num(getField(e, map, 'vlanMembers'));
      const nameRaw = hasField(map, 'vlanName') ? getField(e, map, 'vlanName') : undefined;
      vlans.push({
        id,
        name: typeof nameRaw === 'string' && nameRaw ? decodeHexString(nameRaw) : null,
        members: decodePortMask(membersMask, Math.max(portCount, 64)),
        igmpSnooping: !!num(getField(e, map, 'vlanIgmp')),
      });
    }
  }

  // --- per-port VLANs -----------------------------------------------------------------
  const portVlans: PortVlanRow[] = [];
  if (vlanPortRes.status === 'fulfilled' && vlanPortRes.value) {
    const d = vlanPortRes.value as Record<string, unknown>;
    const modesRaw = getField(d, map, 'vlanPortMode');
    if (Array.isArray(modesRaw)) {
      const recvRaw = getField(d, map, 'vlanPortReceive') as unknown[] | undefined;
      const defRaw = getField(d, map, 'vlanPortDefaultId') as unknown[] | undefined;
      const forceMask = num(getField(d, map, 'vlanPortForceId'));
      for (let i = 0; i < (modesRaw as unknown[]).length; i++) {
        portVlans.push({
          port: i + 1,
          mode: map.vlanPortModes[num((modesRaw as unknown[])[i])] ?? `Unknown(${num((modesRaw as unknown[])[i])})`,
          receive: recvRaw ? (VLAN_RECEIVE[num(recvRaw[i])] ?? 'unknown') : 'Any',
          defaultVlanId: defRaw && typeof defRaw[i] === 'number' ? (defRaw[i] as number) : null,
          forceVlanId: !!(forceMask & (1 << i)),
        });
      }
    }
  }

  // --- SNMP ---------------------------------------------------------------------------
  let snmp: SwosSnapshot['snmp'] = null;
  if (snmpRes.status === 'fulfilled' && snmpRes.value) {
    const d = snmpRes.value as Record<string, unknown>;
    snmp = {
      enabled: !!num(getField(d, map, 'snmpEnabled')),
      community: decodeHexString(getField(d, map, 'snmpCommunity')),
      contact: decodeHexString(getField(d, map, 'snmpContact')),
      location: decodeHexString(getField(d, map, 'snmpLocation')),
    };
  }

  // --- SFP (per-slot rows, best-effort) ----------------------------------------------------
  // SwOS sfp.b is an object of PER-SLOT arrays: {vnd:[…8], pnr:[…8], tmp:[…8], …}
  // (verified on a CRS309). Zip them into one row per slot; text fields are
  // hex-encoded ASCII, temperature is in °C with 4294967168 as the "no data" sentinel.
  // Physical port labels come from link.b: sfpo = index of the first SFP slot,
  // sfp = slot count (e.g. CRS309-1G-8S+: sfpo=0, sfp=8 → ports 1–8 are SFP+).
  const sfpRows: Record<string, string>[] = [];
  if (sfpRes.status === 'fulfilled' && sfpRes.value) {
    let sfpOffset = 0;
    if (linkRes.status === 'fulfilled' && linkRes.value && !Array.isArray(linkRes.value)) {
      const offRaw = getField(linkRes.value as Record<string, unknown>, map, 'portSfpOffset');
      if (typeof offRaw === 'number') sfpOffset = Math.max(0, Math.floor(offRaw));
    }
    const d = sfpRes.value;
    const entries = Array.isArray(d) ? d : [d];
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object') continue;
      const obj = entry as Record<string, unknown>;
      const arrKeys = Object.keys(obj).filter((k) => Array.isArray(obj[k]));
      if (arrKeys.length > 0) {
        const slotCount = Math.max(...arrKeys.map((k) => (obj[k] as unknown[]).length));
        for (let i = 0; i < slotCount; i++) {
          const row: Record<string, string> = {};
          let anyData = false;
          for (const k of arrKeys) {
            const v = (obj[k] as unknown[])[i];
            if (v === undefined || v === null) continue;
            if (typeof v === 'string') {
              row[k] = decodeHexString(v);
              anyData = true;
            } else if (k === 'tmp') {
              const t = num(v);
              row[k] = t > 2 ** 31 || t < -50 ? '—' : `${t}°C`; // sentinel / out-of-range → no data
              anyData = true;
            } else if (typeof v === 'number') {
              row[k] = String(v);
              anyData = true;
            }
          }
          row['port'] = String(sfpOffset + i + 1); // physical port of this slot
          if (anyData) sfpRows.push(row);
        }
      } else {
        // Single-slot object fallback.
        const row: Record<string, string> = {};
        for (const [k, v] of Object.entries(obj)) {
          row[k] = typeof v === 'string' ? decodeHexString(v) : String(v);
        }
        sfpRows.push(row);
      }
    }
  }

  // --- MAC table ------------------------------------------------------------------------------
  const macs = dhostRes.status === 'fulfilled' && dhostRes.value ? parseMacTable(dhostRes.value) : [];

  // --- Port throughput (stats.b: cumulative byte counters → rates via previous sample) -----
  let portStats: PortStat[] | null = null;
  let totalRxBitsPerSec: number | null = null;
  let totalTxBitsPerSec: number | null = null;
  if (statsRes.status === 'fulfilled' && statsRes.value && !Array.isArray(statsRes.value)) {
    const st = statsRes.value as Record<string, unknown>;
    // Field ids are map-driven: verified on SwOS ('rb'/'tb'); absent from the Lite
    // map until confirmed on CSS hardware (the Web UI polls stats.b there too).
    const rxRaw = hasField(map, 'statsRxBytes') && Array.isArray(st[map.statsRxBytes!]) ? (st[map.statsRxBytes!] as number[]) : [];
    const txRaw = hasField(map, 'statsTxBytes') && Array.isArray(st[map.statsTxBytes!]) ? (st[map.statsTxBytes!] as number[]) : [];
    if (rxRaw.length > 0 || txRaw.length > 0) {
      const nowMs = Date.now();
      const prev = statsHistory.get(client.base);
      // Per-port rates may be null (counter reset on that port) even when others are valid.
      let rxRate: (number | null)[] | null = null;
      let txRate: (number | null)[] | null = null;
      if (prev && nowMs > prev.atMs) {
        const dtSec = (nowMs - prev.atMs) / 1000;
        // Counter reset (reboot/config restore) or clock skew → negative delta; drop the rates.
        rxRate = rxRaw.map((v, i) => ((v - (prev.rxBytes[i] ?? v)) < 0 ? null : Math.round(((v - (prev.rxBytes[i] ?? v)) / dtSec) * 8)));
        txRate = txRaw.map((v, i) => ((v - (prev.txBytes[i] ?? v)) < 0 ? null : Math.round(((v - (prev.txBytes[i] ?? v)) / dtSec) * 8)));
      }
      statsHistory.set(client.base, { atMs: nowMs, rxBytes: rxRaw, txBytes: txRaw });

      const count = Math.max(rxRaw.length, txRaw.length);
      portStats = [];
      for (let i = 0; i < count; i++) {
        portStats.push({
          port: i + 1,
          name: portNames[i] || `Port ${i + 1}`,
          rxBytesTotal: rxRaw[i] ?? 0,
          txBytesTotal: txRaw[i] ?? 0,
          rxBitsPerSec: rxRate ? (rxRate[i] ?? null) : null,
          txBitsPerSec: txRate ? (txRate[i] ?? null) : null,
        });
      }
      const sum = (r: (number | null)[] | null) => (r === null ? null : r.reduce<number>((acc, v) => acc + (v ?? 0), 0));
      totalRxBitsPerSec = sum(rxRate);
      totalTxBitsPerSec = sum(txRate);
    }
  }

  // createPlatform() throws for 'unknown', so the type is narrowed here.
  const platformType = platform.type === 'swos' ? ('swos' as const) : ('swos-lite' as const);

  return {
    platformType,
    platformName: platform.name,
    identity,
    model,
    firmwareVersion,
    macAddress,
    serialNumber,
    // SwOS reports centiseconds (verified: Δ=1503 over 15.0s); SwOS Lite is documented
    // as seconds — dividing by 100 keeps both sane only if the wire unit matches, so we
    // normalize per platform.
    uptimeSeconds:
      typeof uptimeRaw === 'number' && Number.isFinite(uptimeRaw)
        ? Math.floor(platform.type === 'swos' ? uptimeRaw / 100 : uptimeRaw)
        : null,
    currentIp,
    addressAcquisition: ADDR_ACQ[acqMode] ?? `Unknown(${acqMode})`,
    allowFrom,
    ports,
    poe,
    lag,
    vlans,
    portVlans,
    snmp,
    macs,
    sfpRows,
    portStats,
    totalRxBitsPerSec,
    totalTxBitsPerSec,
  };
}

// --- Throughput rate state (per host) ---------------------------------------------------------
// stats.b only exposes CUMULATIVE byte counters; the Web UI polls it every second and
// derives rates client-side. We do the same across API poll intervals: keep the last
// sample per management address and compute Δbytes/Δt between collections.
interface StatsSample {
  atMs: number;
  rxBytes: number[];
  txBytes: number[];
}
const statsHistory = new Map<string, StatsSample>();

/** Humanizes a bits/s rate for table cells (the webapp renders table values verbatim). */
function formatBitsPerSec(v: number | null): string {
  if (v === null || !Number.isFinite(v) || v < 0) return '—';
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
  let x = v;
  let i = 0;
  while (x >= 1000 && i < units.length - 1) {
    x /= 1000;
    i++;
  }
  return `${x >= 100 ? Math.round(x) : x.toFixed(2)} ${units[i]}`;
}

// --- TTL cache ------------------------------------------------------------------------------

interface CacheEntry {
  at: number;
  snapshot: SwosSnapshot;
}

const cache = new Map<string, CacheEntry>();

export interface MonitoringResult {
  snapshot: SwosSnapshot;
  /** True when the served snapshot is stale (re-collection failed). */
  stale: boolean;
  error?: string;
}

/**
 * Returns a fresh-or-cached snapshot for one host. Never throws — transport and
 * auth failures surface as `error` so /monitoring can map them to health.
 */
export async function getMonitoring(
  address: string,
  credentials: { username: string; password: string },
  opts: SwosOptions
): Promise<MonitoringResult> {
  // The password is part of the key (hashed) — a cached snapshot collected with
  // one credential set must never be served for another.
  const pwHash = createHash('md5').update(credentials.password, 'utf8').digest('hex');
  const key = `${address}|${credentials.username}:${pwHash}`;
  const now = Date.now();
  const cached = cache.get(key);

  if (cached && now - cached.at < opts.cacheTtlMs) {
    return { snapshot: cached.snapshot, stale: false };
  }

  try {
    const client = new SwosClient(address, credentials, opts.requestTimeoutMs);
    const snapshot = await collectSnapshot(client);
    cache.set(key, { at: now, snapshot });
    // Opportunistic eviction so the map can't grow unbounded across devices.
    if (cache.size > 512) {
      for (const [k, v] of cache) if (now - v.at > opts.cacheTtlMs * 4) cache.delete(k);
    }
    return { snapshot, stale: false };
  } catch (err) {
    const message = (err as Error).message;
    if (cached) {
      // Serve the last good data rather than flapping to critical on a blip.
      return { snapshot: cached.snapshot, stale: true, error: `Snapshot is stale — refresh failed: ${message}` };
    }
    throw err;
  }
}

/** Test hook: clears the per-host cache. */
export function clearMonitoringCache(): void {
  cache.clear();
}

// --- Metric descriptors ---------------------------------------------------------------------------

export interface MetricDescriptor {
  key: string;
  label: string;
  unit?: string;
  format?: 'bytes' | 'bits' | 'duration' | 'number' | 'text';
  type: 'number' | 'string' | 'boolean' | 'enum';
  visualization: 'gauge' | 'plot' | 'text' | 'table';
  group?: string;
  min?: number;
  max?: number;
  color?: string;
  rows?: string[];
  columns?: string[];
  summary?: boolean;
}

/** Builds the descriptor set for one snapshot (groups appear only when present). */
export function buildDescriptors(s: SwosSnapshot): MetricDescriptor[] {
  const d: MetricDescriptor[] = [
    // --- System ---------------------------------------------------------------
    { key: 'system.identity', label: 'Identity', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.platform', label: 'Platform', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.detectedModel', label: 'Detected model', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.detectedFirmwareVersion', label: 'Detected firmware', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.macAddress', label: 'MAC address', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.serialNumber', label: 'Serial number', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.uptime', label: 'Uptime', unit: 's', format: 'duration', type: 'number', visualization: 'text', group: 'System' },
    { key: 'system.currentIp', label: 'Management IP', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.addressAcquisition', label: 'Address mode', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.allowFrom', label: 'Management allow-from', type: 'string', visualization: 'text', group: 'System' },

    // --- Summary (device overview table) ----------------------------------------
    { key: 'switch.portsUp', label: 'Ports up', type: 'string', visualization: 'text', group: 'Summary', summary: true },
  ];

  if (s.poe && s.poe.length > 0) {
    d.push(
      {
        key: 'poe.ports',
        label: 'PoE ports',
        type: 'string',
        visualization: 'table',
        group: 'PoE',
        columns: ['port', 'mode', 'status', 'powerW', 'voltageV', 'currentMa', 'lldp'],
      },
      { key: 'poe.totalPowerW', label: 'Total PoE draw', unit: 'W', type: 'number', visualization: 'gauge', group: 'PoE', color: '#f59e0b', summary: true }
    );
  }

  if (s.lag && s.lag.length > 0) {
    d.push({ key: 'lag.ports', label: 'LAG / LACP', type: 'string', visualization: 'table', group: 'LAG', columns: ['port', 'mode', 'group', 'partnerMac'] });
  }

  if (s.vlans.length > 0) {
    d.push({ key: 'vlans.table', label: 'VLAN table', type: 'string', visualization: 'table', group: 'VLANs', columns: ['id', 'name', 'members', 'igmpSnooping'] });
  }

  if (s.portVlans.length > 0) {
    d.push({ key: 'vlans.perPort', label: 'Per-port VLAN mode', type: 'string', visualization: 'table', group: 'VLANs', columns: ['port', 'mode', 'receive', 'defaultVlanId', 'forceVlanId'] });
  }

  if (s.snmp) {
    d.push(
      { key: 'snmp.enabled', label: 'SNMP enabled', type: 'boolean', visualization: 'text', group: 'SNMP' },
      { key: 'snmp.community', label: 'Community', type: 'string', visualization: 'text', group: 'SNMP' },
      { key: 'snmp.contact', label: 'Contact', type: 'string', visualization: 'text', group: 'SNMP' },
      { key: 'snmp.location', label: 'Location', type: 'string', visualization: 'text', group: 'SNMP' }
    );
  }

  if (s.sfpRows.length > 0) {
    d.push({ key: 'sfp.info', label: 'SFP modules', type: 'string', visualization: 'table', group: 'SFP', columns: ['port', 'vnd', 'pnr', 'typ', 'ser', 'dat', 'wln', 'tmp'] });
  }

  if (s.portStats && s.portStats.length > 0) {
    d.push(
      { key: 'switch.rxThroughput', label: 'Total RX throughput', unit: 'bps', format: 'bits', type: 'number', visualization: 'gauge', group: 'Traffic', color: '#3b82f6', summary: true },
      { key: 'switch.txThroughput', label: 'Total TX throughput', unit: 'bps', format: 'bits', type: 'number', visualization: 'gauge', group: 'Traffic', color: '#10b981', summary: true },
      { key: 'switch.portStats', label: 'Port traffic (current rate)', type: 'string', visualization: 'table', group: 'Traffic', columns: ['port', 'name', 'rxRate', 'txRate'] }
    );
  }

  if (s.macs.length > 0) {
    d.push({ key: 'switch.macTable', label: 'Learned MAC addresses', type: 'string', visualization: 'table', group: 'Hosts', columns: ['mac', 'intf'] });
  }

  return d;
}

/** Builds the metrics map for one snapshot (consumed by /monitoring). */
export function buildMetrics(s: SwosSnapshot, selectedModel?: string | null, selectedFirmware?: string | null): Record<string, unknown> {
  const m: Record<string, unknown> = {};
  m['system.identity'] = s.identity || null;
  m['system.platform'] = s.platformName;
  m['system.detectedModel'] = s.model || null;
  m['system.detectedFirmwareVersion'] = s.firmwareVersion || null;
  m['system.macAddress'] = s.macAddress || null;
  m['system.serialNumber'] = s.serialNumber || null;
  m['system.uptime'] = s.uptimeSeconds;
  m['system.currentIp'] = s.currentIp || null;
  m['system.addressAcquisition'] = s.addressAcquisition || null;
  m['system.allowFrom'] = s.allowFrom || null;

  // User-selected model/firmware (device form) — echoed like the other plugins.
  if (selectedModel) m['system.model'] = selectedModel;
  if (selectedFirmware) m['system.firmwareVersion'] = selectedFirmware;

  const upCount = s.ports.filter((p) => p.linkUp).length;
  m['switch.portsUp'] = `${upCount}/${s.ports.length}`;

  if (s.poe && s.poe.length > 0) {
    m['poe.ports'] = s.poe.map((p) => ({
      port: String(p.port),
      mode: p.mode,
      status: p.status,
      powerW: p.powerW !== null ? `${p.powerW} W` : '—',
      voltageV: p.voltageV !== null ? `${p.voltageV} V` : '—',
      currentMa: p.currentMa !== null ? `${p.currentMa} mA` : '—',
      lldp: p.lldpEnabled ? 'on' : 'off',
    }));
    const total = s.poe.reduce((sum, p) => sum + (p.powerW ?? 0), 0);
    m['poe.totalPowerW'] = Math.round(total * 10) / 10;
  }

  if (s.lag && s.lag.length > 0) {
    m['lag.ports'] = s.lag.map((l) => ({ port: String(l.port), mode: l.mode, group: String(l.group), partnerMac: l.partnerMac || '—' }));
  }

  if (s.vlans.length > 0) {
    m['vlans.table'] = s.vlans.map((v) => ({
      id: String(v.id),
      name: v.name ?? '—',
      members: v.members.length > 0 ? v.members.join(', ') : '—',
      igmpSnooping: v.igmpSnooping ? 'on' : 'off',
    }));
  }

  if (s.portVlans.length > 0) {
    m['vlans.perPort'] = s.portVlans.map((v) => ({
      port: String(v.port),
      mode: v.mode,
      receive: v.receive,
      defaultVlanId: v.defaultVlanId !== null ? String(v.defaultVlanId) : '—',
      forceVlanId: v.forceVlanId ? 'yes' : 'no',
    }));
  }

  if (s.snmp) {
    m['snmp.enabled'] = s.snmp.enabled;
    m['snmp.community'] = s.snmp.community || null;
    m['snmp.contact'] = s.snmp.contact || null;
    m['snmp.location'] = s.snmp.location || null;
  }

  if (s.sfpRows.length > 0) m['sfp.info'] = s.sfpRows;

  // Port throughput — rates are pre-formatted strings because the webapp renders table
  // cells verbatim; the aggregate gauges carry raw bits/s + format:'bits'.
  if (s.portStats && s.portStats.length > 0) {
    m['switch.rxThroughput'] = s.totalRxBitsPerSec ?? 0;
    m['switch.txThroughput'] = s.totalTxBitsPerSec ?? 0;
    m['switch.portStats'] = s.portStats.map((p) => ({
      port: String(p.port),
      name: p.name,
      rxRate: formatBitsPerSec(p.rxBitsPerSec),
      txRate: formatBitsPerSec(p.txBitsPerSec),
    }));
  }

  if (s.macs.length > 0) {
    m['switch.macTable'] = s.macs.map((x) => ({ mac: x.mac, intf: x.intf || '—' }));
  }

  // --- Inventory propagation (consumed by the API's ingestInventory) --------------
  // networks[]: one row per VLAN — logical L2 segments without IPs. The name is
  // the VLAN name on SwOS, "VLAN <id>" elsewhere; vlanId drives the Networks page
  // grouping. Dedup guard for the (name, ip) upsert key below.
  const netSeen = new Set<string>();
  const networks: Record<string, unknown>[] = [];
  for (const v of s.vlans) {
    const name = v.name || `VLAN ${v.id}`;
    if (netSeen.has(`${name}|`)) continue;
    netSeen.add(`${name}|`);
    networks.push({ name, ip: '', vlanId: v.id, status: 'up' });
  }
  if (networks.length > 0) m['networks'] = networks;

  // macTable[] → hosts table with source 'mac' (API-side ingestion; IP-less rows).
  if (s.macs.length > 0) {
    m['macTable'] = s.macs.map((x) => ({ mac: x.mac, intf: x.intf || null }));
  }

  return m;
}
