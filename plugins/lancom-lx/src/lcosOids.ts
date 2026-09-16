/**
 * LCOS-LX-MIB numeric OID map for LANCOM LX-Series access points.
 *
 * Every constant is taken from the vendor MIB's explicit `{TABLE}` / `{SCALAR}`
 * / `{COLUMN}` annotations (LC-LX-6500-7.14.0036-RU1.mib), NOT inferred from
 * SEQUENCE order — LANCOM uses gapped, non-sequential column numbering, so a
 * column's position in the MIB text is meaningless. The full dotted prefix for
 * every entry is `.1.3.6.1.4.1.2356.` + the suffix shown (lcosLX = 13).
 *
 * Scope note: this map targets the LX-6500 (top of series) as a superset. Lower
 * LX models expose fewer tables/columns — parsers must treat any missing OID as
 * absent, never an error. All objects in this MIB are read-only; there is no
 * SET surface here (actions require a separate transport, see plugin README).
 */

/** lcosLX module root: enterprises.lancom-systems(2356).13 */
export const LCOS_BASE = '.1.3.6.1.4.1.2356.13';

/* ------------------------------------------------------------------ *
 * System / hardware (read-only scalars) — 13.1, 13.3
 * ------------------------------------------------------------------ */
// NOTE: every scalar instance carries a trailing ".0" sub-identifier
// (verified live: .13.1.47.9.0 = sw version). Table rows are addressed
// COLUMN-FIRST — <table>.1.<column>.<index…> — see lcosClient.ts.
export const SYS = {
  /** lcosLXStatusOperatingTime — uptime in seconds (Unsigned32). */
  operatingTime: `${LCOS_BASE}.1.2.0`,
  /** lcosLXSetupName — configured device name (config mirror, RO). */
  setupName: `${LCOS_BASE}.2.1.0`,
  /** lcosLXFirmwareBootcount — total firmware boot count. */
  bootcount: `${LCOS_BASE}.3.10.0`,
} as const;

/** lcosLXStatus time scalars (13.1.18–20) — the AP's wall clock + UTC epoch + offset. */
export const TIME = {
  /**
   * lcosLXStatusCurrentTime — device-local wall clock, OCTET STRING (SIZE(0..20)),
   * format "MM/DD/YYYY HH:mm:ss" (US order — verified live against the epoch scalar).
   */
  currentTime: `${LCOS_BASE}.1.18.0`,
  /** lcosLXStatusCurrentTimeEpoch — UTC seconds since epoch (Unsigned32; wraps 2106). */
  epoch: `${LCOS_BASE}.1.19.0`,
  /** lcosLXStatusCurrentTimeOffset — current UTC offset in SECONDS, signed (Integer32). */
  offset: `${LCOS_BASE}.1.20.0`,
} as const;

/** lcosLXSetupTime group (13.2.14) — time config mirror (read-only). */
export const SETUP_TIME = {
  /** lcosLXSetupTimeTimezone — INTEGER enum of IANA-ish zones (see lxTimezoneToIana). */
  timezone: `${LCOS_BASE}.2.14.20.0`,
} as const;

/** Maps the lcosLXSetupTimeTimezone enum to an IANA zone name (null when unknown). */
export function lxTimezoneToIana(v: number | null): string | null {
  if (v === null || !Number.isFinite(v)) return null;
  const ZONES: Record<number, string> = {
    0: 'UTC',
    1: 'Europe/Berlin', 2: 'Europe/Vienna', 3: 'Europe/Zurich', 4: 'Europe/London',
    5: 'Europe/Prague', 6: 'Europe/Warsaw', 7: 'Europe/Zagreb', 8: 'Europe/Copenhagen',
    9: 'Europe/Paris', 10: 'Europe/Helsinki', 11: 'Europe/Tallinn', 12: 'Europe/Athens',
    13: 'Europe/Budapest', 14: 'Europe/Dublin', 15: 'Europe/Rome', 16: 'Europe/Riga',
    17: 'Europe/Vilnius', 18: 'Europe/Luxembourg', 19: 'Europe/Malta', 20: 'Europe/Amsterdam',
    21: 'Europe/Nicosia', 22: 'Europe/Lisbon', 23: 'Europe/Bucharest', 24: 'Europe/Bratislava',
    25: 'Europe/Ljubljana', 26: 'Europe/Madrid', 27: 'Europe/Stockholm', 28: 'Europe/Brussels',
    29: 'Europe/Sofia', 30: 'America/Anchorage', 31: 'America/Los_Angeles',
    32: 'America/Denver', 33: 'America/Chicago', 34: 'America/New_York',
    35: 'Pacific/Auckland', 36: 'Pacific/Honolulu', 37: 'Australia/Brisbane',
    38: 'Australia/Sydney', 39: 'Australia/Perth', 40: 'Australia/Darwin', 41: 'Australia/Adelaide',
  };
  return ZONES[v] ?? null;
}

/** lcosLXStatusHardwareInfo group (13.1.47). */
export const HW = {
  base: `${LCOS_BASE}.1.47`,
  totalMemoryKbytes: `${LCOS_BASE}.1.47.4.0`,
  freeMemoryKbytes: `${LCOS_BASE}.1.47.5.0`,
  serialNumber: `${LCOS_BASE}.1.47.7.0`,
  boardRevision: `${LCOS_BASE}.1.47.8.0`,
  swVersion: `${LCOS_BASE}.1.47.9.0`,
  /** lcosLXStatusHardwareInfoCPULoad60sPercent — U32; scaling verified live (×100). */
  cpuLoad60sPercent: `${LCOS_BASE}.1.47.14.0`,
} as const;

/* ------------------------------------------------------------------ *
 * WLAN runtime status — 13.1.3
 * ------------------------------------------------------------------ */

/** lcosLXStatusWLANStationTable (13.1.3.32) — per-client, indexed by MAC (col .4). */
export const STATION = {
  base: `${LCOS_BASE}.1.3.32`,
  radioBand: `${LCOS_BASE}.1.3.32.1.2`, // e2GHz(1)/e5GHz(2)/e6GHz(3)
  ifc: `${LCOS_BASE}.1.3.32.1.3`,
  macAddress: `${LCOS_BASE}.1.3.32.1.4`, // index column (MacAddress)
  txBytes: `${LCOS_BASE}.1.3.32.1.6`, // Counter64
  rxBytes: `${LCOS_BASE}.1.3.32.1.7`, // Counter64
  identification: `${LCOS_BASE}.1.3.32.1.9`,
  state: `${LCOS_BASE}.1.3.32.1.10`,
  interface: `${LCOS_BASE}.1.3.32.1.15`,
  connectTime: `${LCOS_BASE}.1.3.32.1.18`, // Counter64 (session duration, ticks)
  throughput: `${LCOS_BASE}.1.3.32.1.20`,
  phySignal: `${LCOS_BASE}.1.3.32.1.26`, // legacy 0-255 scale
  ipv4Address: `${LCOS_BASE}.1.3.32.1.27`,
  ipv6Address: `${LCOS_BASE}.1.3.32.1.28`,
  wpaVersion: `${LCOS_BASE}.1.3.32.1.33`,
  vlanId: `${LCOS_BASE}.1.3.32.1.38`,
  userName: `${LCOS_BASE}.1.3.32.1.39`, // 802.1X identity when present
  pairwiseCipher: `${LCOS_BASE}.1.3.32.1.40`,
  networkId: `${LCOS_BASE}.1.3.32.1.41`,
  idleTimeout: `${LCOS_BASE}.1.3.32.1.43`,
  effTxRate: `${LCOS_BASE}.1.3.32.1.50`, // Mbit/s (U32)
  effRxRate: `${LCOS_BASE}.1.3.32.1.51`, // Mbit/s (U32)
  fastRoaming: `${LCOS_BASE}.1.3.32.1.63`,
  wpa2KeyManagement: `${LCOS_BASE}.1.3.32.1.64`,
  channelBandwidths: `${LCOS_BASE}.1.3.32.1.66`,
  operationMode: `${LCOS_BASE}.1.3.32.1.71`, // e11b…e11be
  dhcpHostname: `${LCOS_BASE}.1.3.32.1.80`,
  maxSpatialStreams: `${LCOS_BASE}.1.3.32.1.83`,
  phySignalDbm: `${LCOS_BASE}.1.3.32.1.97`, // Int32 dBm — preferred signal value
  networkName: `${LCOS_BASE}.1.3.32.1.98`,
  ssid: `${LCOS_BASE}.1.3.32.1.99`,
} as const;

/** lcosLXStatusWLANRadios (13.1.3.57) — per-radio, indexed by ifc name. */
export const RADIOS = {
  base: `${LCOS_BASE}.1.3.57`,
  ifc: `${LCOS_BASE}.1.3.57.1.1`, // index column (OCTET STRING)
  radioBand: `${LCOS_BASE}.1.3.57.1.2`,
  channel: `${LCOS_BASE}.1.3.57.1.3`,
  noiseFloor: `${LCOS_BASE}.1.3.57.1.4`, // Int32 dBm
  noiseLevel: `${LCOS_BASE}.1.3.57.1.5`,
  modemLoad: `${LCOS_BASE}.1.3.57.1.6`, // U32 %
  transmitPower: `${LCOS_BASE}.1.3.57.1.7`, // Int32 dBm
  eirp: `${LCOS_BASE}.1.3.57.1.8`, // Int32 dBm
  numStations: `${LCOS_BASE}.1.3.57.1.9`,
  mode: `${LCOS_BASE}.1.3.57.1.14`, // e11b…e11be mixes, off=255
  channelBandwidth: `${LCOS_BASE}.1.3.57.1.19`,
  rxErrorRatio: `${LCOS_BASE}.1.3.57.1.20`, // U32 (0-65535)
  txErrorRatio: `${LCOS_BASE}.1.3.57.1.21`,
  rxBytes: `${LCOS_BASE}.1.3.57.1.22`, // Counter64 — fast path
  txBytes: `${LCOS_BASE}.1.3.57.1.23`, // Counter64 — fast path
  modemLoadMin: `${LCOS_BASE}.1.3.57.1.40`,
  modemLoadMax: `${LCOS_BASE}.1.3.57.1.41`,
  modemLoadAverage: `${LCOS_BASE}.1.3.57.1.42`,
  temperatureDegrees: `${LCOS_BASE}.1.3.57.1.50`,
  allChannelsBlocked: `${LCOS_BASE}.1.3.57.1.51`, // DFS — enum
} as const;

/** lcosLXStatusWLANInterfaces (13.1.3.51) — per-SSID, indexed by networkName+band. */
export const WLAN_IF = {
  base: `${LCOS_BASE}.1.3.51`,
  networkName: `${LCOS_BASE}.1.3.51.1.1`, // index part 1
  ssid: `${LCOS_BASE}.1.3.51.1.2`,
  radioBand: `${LCOS_BASE}.1.3.51.1.3`,
  pskNumSuccess: `${LCOS_BASE}.1.3.51.1.4`, // U32 counter — brute-force signal
  pskNumFailures: `${LCOS_BASE}.1.3.51.1.5`,
  pskNumWrongPassphrase: `${LCOS_BASE}.1.3.51.1.6`,
  ifc: `${LCOS_BASE}.1.3.51.1.7`,
  bssid: `${LCOS_BASE}.1.3.51.1.10`, // MacAddress
  networkId: `${LCOS_BASE}.1.3.51.1.41`,
} as const;

/** lcosLXStatusWLANClientManagementChannelTable (13.1.3.4.2) — airtime per channel. */
export const CHANNEL_UTIL = {
  base: `${LCOS_BASE}.1.3.4.2`,
  channel: `${LCOS_BASE}.1.3.4.2.1.1`, // index column
  utilization: `${LCOS_BASE}.1.3.4.2.1.2`, // U32 %
  overload: `${LCOS_BASE}.1.3.4.2.1.3`, // enum
} as const;

/** lcosLXStatusWLANEnvironmentScanResults (13.1.3.69) — neighbor APs seen by scan. */
export const ENV_SCAN = {
  base: `${LCOS_BASE}.1.3.69`,
  bssid: `${LCOS_BASE}.1.3.69.1.1`, // index column (MacAddress)
  ssid: `${LCOS_BASE}.1.3.69.1.2`,
  ifc: `${LCOS_BASE}.1.3.69.1.3`,
  channel: `${LCOS_BASE}.1.3.69.1.8`,
  band: `${LCOS_BASE}.1.3.69.1.16`,
  signalLevel: `${LCOS_BASE}.1.3.69.1.26`, // Int32 dBm
  signalPercent: `${LCOS_BASE}.1.3.69.1.27`,
  bandwidth: `${LCOS_BASE}.1.3.69.1.45`,
} as const;

/** lcosLXStatusWLANCompetingNetworks (13.1.3.70) — same shape as ENV_SCAN. */
export const COMPETING = {
  base: `${LCOS_BASE}.1.3.70`,
  bssid: `${LCOS_BASE}.1.3.70.1.1`,
  ssid: `${LCOS_BASE}.1.3.70.1.2`,
  ifc: `${LCOS_BASE}.1.3.70.1.3`,
  channel: `${LCOS_BASE}.1.3.70.1.8`,
  band: `${LCOS_BASE}.1.3.70.1.16`,
  signalLevel: `${LCOS_BASE}.1.3.70.1.26`,
  signalPercent: `${LCOS_BASE}.1.3.70.1.27`,
} as const;

/** lcosLXStatusWLANChannelScanResults (13.1.3.42) — DFS state per channel. */
export const DFS = {
  base: `${LCOS_BASE}.1.3.42`,
  channel: `${LCOS_BASE}.1.3.42.1.1`, // index part 1
  interface: `${LCOS_BASE}.1.3.42.1.2`, // index part 2
  band: `${LCOS_BASE}.1.3.42.1.9`,
  dfsState: `${LCOS_BASE}.1.3.42.1.12`, // eClear/eBlocked…
  scanAge: `${LCOS_BASE}.1.3.42.1.13`,
} as const;

/** lcosLXStatusWLANWDSLinks (13.1.3.101.1) — WDS/mesh links, indexed by name+MAC. */
export const WDS = {
  base: `${LCOS_BASE}.1.3.101.1`,
  linkName: `${LCOS_BASE}.1.3.101.1.1.1`, // index part 1
  macAddress: `${LCOS_BASE}.1.3.101.1.1.2`, // index part 2 (MacAddress)
  connected: `${LCOS_BASE}.1.3.101.1.1.3`, // enum
  radio: `${LCOS_BASE}.1.3.101.1.1.4`,
  rxPhySignal: `${LCOS_BASE}.1.3.101.1.1.5`,
  remoteMode: `${LCOS_BASE}.1.3.101.1.1.6`, // eAP/eStation…
  effTxRate: `${LCOS_BASE}.1.3.101.1.1.7`,
  effRxRate: `${LCOS_BASE}.1.3.101.1.1.8`,
  txPackets: `${LCOS_BASE}.1.3.101.1.1.9`, // Counter64 — fast path
  txBytes: `${LCOS_BASE}.1.3.101.1.1.10`, // Counter64 — fast path
  rxPackets: `${LCOS_BASE}.1.3.101.1.1.11`,
  rxBytes: `${LCOS_BASE}.1.3.101.1.1.12`, // Counter64 — fast path
} as const;

/* ------------------------------------------------------------------ *
 * LAN / bridge — 13.1.5, 13.1.45
 * ------------------------------------------------------------------ */

/** lcosLXStatusLANPorts (13.1.5.99) — per-port link state, indexed by port name. */
export const LAN_PORTS = {
  base: `${LCOS_BASE}.1.5.99`,
  port: `${LCOS_BASE}.1.5.99.1.1`, // index column (OCTET STRING)
  linkActive: `${LCOS_BASE}.1.5.99.1.2`, // enum
  connector: `${LCOS_BASE}.1.5.99.1.3`, // speed/connector enum
  macAddress: `${LCOS_BASE}.1.5.99.1.4`, // MacAddress
} as const;

/** lcosLXStatusLANByteTransport (13.1.5.52) — per-port byte/CRC counters, fast path. */
export const LAN_BYTES = {
  base: `${LCOS_BASE}.1.5.52`,
  port: `${LCOS_BASE}.1.5.52.1.1`, // index column
  txBytes: `${LCOS_BASE}.1.5.52.1.2`, // Counter64
  rxBytes: `${LCOS_BASE}.1.5.52.1.3`, // Counter64
  rxCRCErrors: `${LCOS_BASE}.1.5.52.1.4`, // Counter64
} as const;

/** lcosLXStatusLANLACP (13.1.5.44) — bond state, indexed by bond name. */
export const LACP = {
  base: `${LCOS_BASE}.1.5.44`,
  bondName: `${LCOS_BASE}.1.5.44.1.1`, // index column
  status: `${LCOS_BASE}.1.5.44.1.2`,
  localPorts: `${LCOS_BASE}.1.5.44.1.10`,
  bundleState: `${LCOS_BASE}.1.5.44.1.11`,
} as const;

/** lcosLXStatusLANSpanningTreePortTable (13.1.5.1.8) — STP per port, indexed by name. */
export const STP = {
  base: `${LCOS_BASE}.1.5.1.8`,
  port: `${LCOS_BASE}.1.5.1.8.1.1`, // index column
  state: `${LCOS_BASE}.1.5.1.8.1.3`,
  role: `${LCOS_BASE}.1.5.1.8.1.7`,
} as const;

/** lcosLXStatusBridgeVLANTable (13.1.45.3) — VLAN membership per interface+VLAN. */
export const BRIDGE_VLAN = {
  base: `${LCOS_BASE}.1.45.3`,
  ifname: `${LCOS_BASE}.1.45.3.1.1`, // index part 1
  vlanId: `${LCOS_BASE}.1.45.3.1.2`, // index part 2
  flags: `${LCOS_BASE}.1.45.3.1.3`, // untagged/tagged…
} as const;

/* ------------------------------------------------------------------ *
 * IP configuration — 13.1.70
 * ------------------------------------------------------------------ */

/** lcosLXStatusIPConfigurationAddresses (13.1.70.1) — per ifname+version+source+addr. */
export const IP_ADDR = {
  base: `${LCOS_BASE}.1.70.1`,
  interfaceName: `${LCOS_BASE}.1.70.1.1.1`, // index part 1
  ipVersion: `${LCOS_BASE}.1.70.1.1.2`, // index part 2 (eIPv4/eIPv6)
  addressSource: `${LCOS_BASE}.1.70.1.1.3`, // index part 3
  address: `${LCOS_BASE}.1.70.1.1.4`, // index part 4 (IpAddress)
  gateway: `${LCOS_BASE}.1.70.1.1.5`,
} as const;

/* ------------------------------------------------------------------ *
 * SNMP event counters — 13.1.35 (trap-rate monitoring without trap subscription)
 * ------------------------------------------------------------------ */

/** lcosLXStatusSNMPEvent (13.1.35.1) — per-trap-OID counter, indexed by trap OID. */
export const SNMP_EVENT = {
  base: `${LCOS_BASE}.1.35.1`,
  trapId: `${LCOS_BASE}.1.35.1.1.1`, // index column (OBJECT IDENTIFIER)
  group: `${LCOS_BASE}.1.35.1.1.2`,
  name: `${LCOS_BASE}.1.35.1.1.3`,
  count: `${LCOS_BASE}.1.35.1.1.4`, // U32 — fast path (delta per poll)
} as const;

/** The seven station-lifecycle trap OIDs (lcosLXWifiTraps = 13.0.0). */
export const TRAP_OIDS = {
  authStation: `${LCOS_BASE}.0.0.1`,
  deAuthStation: `${LCOS_BASE}.0.0.2`,
  assStation: `${LCOS_BASE}.0.0.3`,
  reAssStation: `${LCOS_BASE}.0.0.4`, // roaming
  disAssStation: `${LCOS_BASE}.0.0.5`,
  assRej: `${LCOS_BASE}.0.0.6`,
  connected: `${LCOS_BASE}.0.0.7`,
} as const;

/* ------------------------------------------------------------------ *
 * WLAN management / cloud — 13.1.59, 13.1.98 (CAPWAP + LMC state)
 * ------------------------------------------------------------------ */

/** lcosLXStatusWLANManagementState (13.1.59.2) — CAPWAP mode scalar. */
export const MGMT_STATE = `${LCOS_BASE}.1.59.2.0`;

/** lcosLXStatusWLANManagementAPConnections (13.1.59.1) — WTP→AC connections, by IP. */
export const AP_CONN = {
  base: `${LCOS_BASE}.1.59.1`,
  ipAddress: `${LCOS_BASE}.1.59.1.1.2`, // index column (IpAddress)
  port: `${LCOS_BASE}.1.59.1.1.3`,
  name: `${LCOS_BASE}.1.59.1.1.5`,
  state: `${LCOS_BASE}.1.59.1.1.6`, // eIdle…eRun/eOff
  result: `${LCOS_BASE}.1.59.1.1.7`, // ~28 failure codes
  firmwareVersion: `${LCOS_BASE}.1.59.1.1.10`,
} as const;

/** lcosLXStatusWLANManagementNetworkprofiles (13.1.59.103) — active SSID config, by name. */
export const NET_PROFILE = {
  base: `${LCOS_BASE}.1.59.103`,
  profileName: `${LCOS_BASE}.1.59.103.1.1`, // index column
  operating: `${LCOS_BASE}.1.59.103.1.4`,
  encryption: `${LCOS_BASE}.1.59.103.1.6`, // ePSK/e8021X…
  maxStations: `${LCOS_BASE}.1.59.103.1.18`,
  ssid: `${LCOS_BASE}.1.59.103.1.21`,
  vlanMode: `${LCOS_BASE}.1.59.103.1.30`, // eUntagged/eTagged…
  vlanId: `${LCOS_BASE}.1.59.103.1.34`,
} as const;

/** LMC cloud scalars (13.1.98). */
export const LMC = {
  customerDeviceId: `${LCOS_BASE}.1.98.5.0`,
  roundTripTime: `${LCOS_BASE}.1.98.6.0`, // U32 ms
  managementStatus: `${LCOS_BASE}.1.98.7.0`,
  controlStatus: `${LCOS_BASE}.1.98.9.0`,
  monitorStatus: `${LCOS_BASE}.1.98.10.0`,
  pairingTokenPresent: `${LCOS_BASE}.1.98.13.0`,
  configModified: `${LCOS_BASE}.1.98.15.0`,
  domain: `${LCOS_BASE}.1.98.16.0`,
} as const;
