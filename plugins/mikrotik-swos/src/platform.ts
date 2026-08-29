/**
 * SwOS vs SwOS Lite platform handling: endpoint names, per-platform field-ID
 * maps, and runtime detection.
 *
 * Both platforms speak the same `.b`-file protocol but use DIFFERENT field IDs:
 *  - SwOS Lite (CSS series): hex-style ids — i01, i0a, …
 *  - SwOS (CRS/RB series):   short descriptive names — id, ver, brd, en, nm…
 * The maps below are transcribed from the python-mikrotik-swos reference
 * project (swos_lite_map.py / swos_map.py), which documents them as tested on
 * CSS610-8G/8P-2S+ (SwOS Lite 2.20) and CRS305/CRS310 (SwOS 2.17). SwOS PoE
 * field names in that reference are marked "likely" — the client tolerates
 * missing fields at runtime, so unverified maps degrade gracefully instead of
 * breaking monitoring.
 */

import { SwosClient, SwosData, decodeHexString } from './swosClient';

export type PlatformType = 'swos' | 'swos-lite' | 'unknown';

/** Logical endpoint names → wire file names (identical on both platforms). */
const ENDPOINTS: Record<string, string> = {
  system: 'sys.b',
  link: 'link.b',
  poe: 'poe.b',
  lag: 'lacp.b',
  vlanPort: 'fwd.b',
  vlanTable: 'vlan.b',
  snmp: 'snmp.b',
  sfp: 'sfp.b', // read-only diagnostics (not in the reference maps — probed best-effort)
  dhost: '!dhost.b', // learned MAC table (read-only)
};

/** Logical field name → platform-specific wire id ('' = not present). */
export interface FieldMap {
  platformType: PlatformType;
  platformName: string;

  // sys.b
  systemUptime: string;
  systemCurrentIp: string;
  systemMac: string;
  systemSerial: string;
  systemIdentity: string;
  systemVersion: string;
  systemModel: string;
  systemBuildDate: string;
  systemStaticIp: string;
  systemAddressAcquisition: string;
  systemAllowFromIp: string;
  systemAllowFromBits: string;
  systemAllowFromPorts: string;
  systemAllowFromVlan: string;
  // SwOS-only extras (None on Lite)
  systemTemperature?: string;
  systemFan1?: string;
  systemFan2?: string;
  systemPoeAvailable?: string;

  // link.b
  portEnabled: string;
  portNames: string;
  portAutoNeg: string;
  portDuplexConfig: string;
  portDuplexStatus: string;
  /** SwOS Lite: array of status codes. SwOS: absent (link state = 'lnk' bitmask). */
  portLinkStatus?: string;
  portLinkUp: string;
  portSpeed: string;
  portSpeedConfig?: string; // SwOS only
  portFlowTx: string;
  portFlowRx: string;
  portUptime?: string; // SwOS Lite only
  portCount?: string; // SwOS only (explicit field)
  portSfpCount?: string; // SwOS only
  /** SwOS only: 0-based index of the first SFP slot in physical port order. */
  portSfpOffset?: string;

  // stats.b (cumulative per-port counters — verified on CRS309, SwOS 2.18)
  statsRxBytes?: string; // 'rb' on SwOS; Lite field ids unverified → hidden there
  statsTxBytes?: string; // 'tb' on SwOS

  // poe.b
  poeMode: string;
  poePriority: string;
  poeVoltage: string;
  poeStatus: string;
  poeCurrent: string;
  poeVoltageActual: string;
  poePower: string;
  poeLldp: string;
  poeLldpPower: string;

  // lacp.b
  lagMode: string;
  lagTrunk: string;
  lagGroup: string;
  lagPartner: string;

  // vlan.b (array of objects)
  vlanId: string;
  vlanMembers: string;
  vlanIgmp: string;
  vlanName?: string; // SwOS only
  vlanIsolation?: string; // SwOS only
  vlanLearning?: string; // SwOS only
  vlanMirror?: string; // SwOS only

  // fwd.b (per-port VLAN)
  vlanPortMode: string;
  vlanPortReceive: string;
  vlanPortDefaultId: string;
  vlanPortForceId: string;
  /** Mode names indexed by the wire value. */
  vlanPortModes: readonly string[];

  // snmp.b
  snmpEnabled: string;
  snmpCommunity: string;
  snmpContact: string;
  snmpLocation: string;
}

export const SWOS_LITE_MAP: FieldMap = {
  platformType: 'swos-lite',
  platformName: 'SwOS Lite',
  systemUptime: 'i01',
  systemCurrentIp: 'i02',
  systemMac: 'i03',
  systemSerial: 'i04',
  systemIdentity: 'i05',
  systemVersion: 'i06',
  systemModel: 'i07',
  systemBuildDate: 'i0b',
  systemStaticIp: 'i09',
  systemAddressAcquisition: 'i0a',
  systemAllowFromIp: 'i19',
  systemAllowFromBits: 'i1a',
  systemAllowFromPorts: 'i12',
  systemAllowFromVlan: 'i1b',
  portEnabled: 'i01',
  portNames: 'i0a',
  portAutoNeg: 'i02',
  portDuplexConfig: 'i03',
  portDuplexStatus: 'i07',
  portLinkStatus: 'i08',
  portLinkUp: 'i06',
  portSpeed: 'i05',
  portFlowTx: 'i16',
  portFlowRx: 'i12',
  portUptime: 'i09',
  poeMode: 'i01',
  poePriority: 'i02',
  poeVoltage: 'i03',
  poeStatus: 'i04',
  poeCurrent: 'i05',
  poeVoltageActual: 'i06',
  poePower: 'i07',
  poeLldp: 'i0a',
  poeLldpPower: 'i0b',
  lagMode: 'i01',
  lagTrunk: 'i02',
  lagGroup: 'i03',
  lagPartner: 'i04',
  vlanId: 'i01',
  vlanMembers: 'i02',
  vlanIgmp: 'i03',
  vlanPortMode: 'i15',
  vlanPortReceive: 'i17',
  vlanPortDefaultId: 'i18',
  vlanPortForceId: 'i19',
  vlanPortModes: ['Disabled', 'Optional', 'Strict'],
  snmpEnabled: 'i01',
  snmpCommunity: 'i02',
  snmpContact: 'i03',
  snmpLocation: 'i04',
};

export const SWOS_MAP: FieldMap = {
  platformType: 'swos',
  platformName: 'SwOS',
  systemUptime: 'upt',
  systemCurrentIp: 'cip',
  systemMac: 'mac',
  systemSerial: 'sid',
  systemIdentity: 'id',
  systemVersion: 'ver',
  systemModel: 'brd',
  systemBuildDate: 'bld',
  systemStaticIp: 'ip',
  systemAddressAcquisition: 'iptp',
  systemAllowFromIp: 'alla',
  systemAllowFromBits: 'allm',
  systemAllowFromPorts: 'allp',
  systemAllowFromVlan: 'avln',
  systemTemperature: 'temp',
  systemFan1: 'fan1',
  systemFan2: 'fan2',
  systemPoeAvailable: 'poe',
  portEnabled: 'en',
  portNames: 'nm',
  portAutoNeg: 'an',
  portDuplexConfig: 'dpxc',
  portDuplexStatus: 'dpx',
  portLinkUp: 'lnk',
  portSpeed: 'spd',
  portSpeedConfig: 'spdc',
  portFlowTx: 'fctc',
  portFlowRx: 'fctr',
  portCount: 'prt',
  portSfpCount: 'sfp',
  portSfpOffset: 'sfpo',
  statsRxBytes: 'rb',
  statsTxBytes: 'tb',
  poeMode: 'mode', // "likely" in the reference — unverified on CRS PoE hardware
  poePriority: 'prio',
  poeVoltage: 'volt',
  poeStatus: 'stat',
  poeCurrent: 'cur',
  poeVoltageActual: 'volr',
  poePower: 'pwr',
  poeLldp: 'lldp',
  poeLldpPower: 'lldpp',
  lagMode: 'mode',
  lagTrunk: 'sgrp',
  lagGroup: 'grp',
  lagPartner: 'mac',
  vlanId: 'vid',
  vlanMembers: 'mbr',
  vlanIgmp: 'igmp',
  vlanName: 'nm',
  vlanIsolation: 'piso',
  vlanLearning: 'lrn',
  vlanMirror: 'mrr',
  vlanPortMode: 'vlan',
  vlanPortReceive: 'vlni',
  vlanPortDefaultId: 'dvid',
  vlanPortForceId: 'fvid',
  vlanPortModes: ['Disabled', 'Optional', 'Enabled', 'Strict'],
  snmpEnabled: 'en',
  snmpCommunity: 'com',
  snmpContact: 'ci',
  snmpLocation: 'loc',
};

/** Read a logical field from parsed data (undefined when the platform lacks it). */
export function getField(data: SwosData, map: FieldMap, name: keyof FieldMap): unknown {
  const id = map[name];
  if (typeof id !== 'string' || id === '') return undefined;
  if (!data || Array.isArray(data)) return undefined;
  return (data as Record<string, unknown>)[id];
}

/** True when the platform's map defines this logical field. */
export function hasField(map: FieldMap, name: keyof FieldMap): boolean {
  const id = map[name];
  return typeof id === 'string' && id !== '';
}

// --- Runtime adapter -----------------------------------------------------------------

export interface SwosPlatform {
  type: PlatformType;
  /** Human-readable platform label (e.g. "SwOS Lite"). */
  name: string;
  map: FieldMap;
  client: SwosClient;
  /** The parsed sys.b body that identified this platform (avoids re-fetching). */
  systemData?: Record<string, unknown>;
  /** Total physical ports (from link.b). */
  portCount(): Promise<number>;
  /** Feature probes — cached, best-effort (false on any error/empty response). */
  hasPoe(): Promise<boolean>;
  hasLacp(): Promise<boolean>;
  hasSnmp(): Promise<boolean>;
}

/**
 * Detects the platform from a parsed sys.b body: SwOS Lite uses hex-style ids
 * (i01…), SwOS uses descriptive names (id/ver/brd). Falls back to model prefix
 * (CSS → Lite, CRS/RB → SwOS) and version string ("…lite…").
 */
export function detectPlatformFromData(data: SwosData): PlatformType {
  if (!data || Array.isArray(data)) return 'unknown';
  const keys = Object.keys(data as Record<string, unknown>);
  const hasHexFields = keys.some((k) => /^i[0-9a-f]{2}$/.test(k));
  const hasDescriptive = ['id', 'ver', 'brd'].some((k) => k in (data as Record<string, unknown>));

  if (hasHexFields && !hasDescriptive) return 'swos-lite';
  if (hasDescriptive && !hasHexFields) return 'swos';

  // Fallbacks: model prefix / version string.
  const d = data as Record<string, unknown>;
  const modelRaw = (d['i07'] ?? d['brd']) as unknown;
  if (typeof modelRaw === 'string' && modelRaw) {
    const model = decodeHexString(modelRaw);
    if (/^CSS/i.test(model)) return 'swos-lite';
    if (/^(CRS|RB)/i.test(model)) return 'swos';
  }
  const verRaw = (d['i06'] ?? d['ver']) as unknown;
  if (typeof verRaw === 'string' && /lite/i.test(decodeHexString(verRaw))) return 'swos-lite';

  return 'unknown';
}

/**
 * Creates a platform adapter for one switch. `sys.b` is fetched once and the
 * response parsed to decide SwOS vs SwOS Lite; both platforms use sys.b (the
 * reference project confirms identical endpoint names).
 */
export async function createPlatform(client: SwosClient): Promise<SwosPlatform> {
  const data = await client.get('sys.b');
  const type = detectPlatformFromData(data);
  if (type === 'unknown') {
    throw new Error('Not a recognized SwOS/SwOS Lite device — sys.b did not match either platform format');
  }
  const map = type === 'swos' ? SWOS_MAP : SWOS_LITE_MAP;

  let portCountCache: number | null = null;
  const featureCache = new Map<string, boolean>();

  async function probeFeature(endpoint: string): Promise<boolean> {
    if (featureCache.has(endpoint)) return featureCache.get(endpoint)!;
    let ok = false;
    try {
      const d = await client.get(endpoint);
      ok = !!d && (!Array.isArray(d) ? Object.keys(d).length > 0 : d.length > 0);
    } catch {
      ok = false; // 404 / redirect to index.html / parse failure → unsupported
    }
    featureCache.set(endpoint, ok);
    return ok;
  }

  const platform: SwosPlatform = {
    type,
    name: map.platformName,
    map,
    client,
    systemData: data as Record<string, unknown>,
    async portCount() {
      if (portCountCache !== null) return portCountCache;
      try {
        const link = await client.get('link.b');
        if (!Array.isArray(link)) {
          // SwOS exposes an explicit port-count field.
          const prt = getField(link, map, 'portCount');
          if (typeof prt === 'number' && prt > 0) {
            portCountCache = Math.floor(prt);
            return portCountCache;
          }
        }
        const names = getField(link, map, 'portNames');
        portCountCache = Array.isArray(names) ? names.length : 0;
      } catch {
        portCountCache = 0;
      }
      return portCountCache;
    },
    hasPoe: () => probeFeature('poe.b'),
    hasLacp: () => probeFeature('lacp.b'),
    hasSnmp: () => probeFeature('snmp.b'),
  };

  // Warm the feature cache in the background — callers await it lazily anyway.
  void Promise.allSettled([platform.hasPoe(), platform.hasLacp(), platform.hasSnmp()]);

  return platform;
}

/** Endpoint name helper (logical → wire file). */
export function endpointFile(logical: string): string {
  const f = ENDPOINTS[logical];
  if (!f) throw new Error(`Unknown SwOS endpoint: ${logical}`);
  return f;
}
