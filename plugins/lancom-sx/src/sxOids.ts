/**
 * Numeric OID map for Lancom SX-Series switches (GS / IGS / XS).
 *
 * Every constant is taken from the vendor MIBs' explicit `{TABLE}` /
 * `{COLUMN}` annotations — NOT inferred from SEQUENCE order. Two firmware
 * lines are supported, each with its OWN tree under enterprise 2356:
 *
 *   SX4 (unified LCOS-SX MIB, module `lcosSX`):
 *     .1.3.6.1.4.1.2356.14 — all modern GS/IGS/XS models on firmware 4.x
 *     (source: mibs/LC-GS-3510XP-4.30.0439-RU9.mib)
 *   SX3 (legacy per-model MIB, module `lancom-systems`):
 *     .1.3.6.1.4.1.2356.800.3.2313 — GS-2310 line on firmware 3.x
 *     (source: mibs/LC-GS-2310-3.34.0371-RU11.mib)
 *
 * The port configuration + traffic tables use IDENTICAL column numbering in
 * both trees; the SX3 tree simply lacks PoE / LACP / VLAN / SVI / neighbor
 * tables (those are 4.x-only features). sxClient.ts auto-detects which tree a
 * device answers and degrades gracefully — any missing OID is "absent", never
 * an error. The writable objects at the bottom of each map are used by the
 * config actions (SNMP SET); everything else is read-only status.
 *
 * Row addressing: like every LANCOM MIB, tables address rows COLUMN-FIRST —
 *   <tableBase>.1.<column>.<index…>
 * where `<tableBase>` is the SEQUENCE OF (TABLE) node and the leading "1" is
 * the not-accessible entry object. All SX table indices are plain Integer32
 * port numbers / ifIndex values (no length-prefixed text indices — that
 * quirk belongs to the LCOS router MIB).
 */

/** Unified 4.x tree root: enterprises.lancom-systems(2356).14 (module lcosSX). */
export const SX4_BASE = '.1.3.6.1.4.1.2356.14';

/** Legacy 3.x GS-2310 tree root: …2356.switchingSystems(800).gigabitEthernetSwitches(3).lancomGS2310(2313). */
export const SX3_BASE = '.1.3.6.1.4.1.2356.800.3.2313';

/** Probe OIDs for firmware-line auto-detection (one snmpget each).
 *  Scalar OBJECT-TYPEs are only queryable at their `.0` instance — verified
 *  live on a GS-3510XP: without the suffix the agent answers "No Such Instance". */
export const DETECT = {
  /** lcsSystemInfoModelName — present on every unified 4.x switch. */
  sx4Model: `${SX4_BASE}.1.1.1.2.0`,
  /** gs2310ModelName — present on the legacy GS-2310 line. */
  sx3Model: `${SX3_BASE}.1.1.1.0`,
} as const;

/* ================================================================== *
 * SX4 — unified LCOS-SX tree (firmware 4.x)
 * ================================================================== */

/** lcsSystemInfo scalars (…14.1.1.1.N). Every scalar OBJECT-TYPE is
 *  addressed at its `.0` instance — that suffix is MANDATORY for snmpget and
 *  appears in walk output too, so lookups must use the same suffixed OIDs. */
export const SX4_SYS = {
  base: `${SX4_BASE}.1.1.1`,
  model: `${SX4_BASE}.1.1.1.2.0`, // DisplayString "GS-3510XP" etc.
  systemDescription: `${SX4_BASE}.1.1.1.3.0`,
  location: `${SX4_BASE}.1.1.1.4.0`, // read-write
  contact: `${SX4_BASE}.1.1.1.5.0`, // read-write
  name: `${SX4_BASE}.1.1.1.6.0`, // configured device name (read-write)
  systemDate: `${SX4_BASE}.1.1.1.7.0`,
  uptime: `${SX4_BASE}.1.1.1.8.0`, // DisplayString as reported
  bootloaderVersion: `${SX4_BASE}.1.1.1.9.0`,
  firmwareVersion: `${SX4_BASE}.1.1.1.10.0`,
  hardwareVersion: `${SX4_BASE}.1.1.1.11.0`,
  mechanicalVersion: `${SX4_BASE}.1.1.1.12.0`,
  serialNumber: `${SX4_BASE}.1.1.1.13.0`,
  hostMacAddress: `${SX4_BASE}.1.1.1.14.0`, // DisplayString MAC
  memoryTotalMb: `${SX4_BASE}.1.1.1.15.0`, // "Total memory in RAM(MB)"
  fanSpeed: `${SX4_BASE}.1.1.1.17.0`, // DisplayString
  temperature1: `${SX4_BASE}.1.1.1.22.0`,
  temperature2: `${SX4_BASE}.1.1.1.23.0`,
  cpuLoad: `${SX4_BASE}.1.1.1.24.0`, // "CPU Utilization." DisplayString
  productionDate: `${SX4_BASE}.1.1.1.33.0`,
  temperature3: `${SX4_BASE}.1.1.1.34.0`,
  memoryFreeMb: `${SX4_BASE}.1.1.1.204.0`, // Integer32 "Free memory in RAM(MB)"
} as const;

/** lcsPowerInformation scalars (…14.1.1.2.N) — dual-PSU status. */
export const SX4_PSU = {
  base: `${SX4_BASE}.1.1.2`,
  psuADetected: `${SX4_BASE}.1.1.2.2`, // DisplayString present/absent
  psuBDetected: `${SX4_BASE}.1.1.2.3`,
  psuAStatus: `${SX4_BASE}.1.1.2.4.0`,
  psuBStatus: `${SX4_BASE}.1.1.2.5.0`,
  fanSpeedA: `${SX4_BASE}.1.1.2.6.0`, // Integer32 rpm
  fanSpeedB: `${SX4_BASE}.1.1.2.7.0`,
  temperatureA: `${SX4_BASE}.1.1.2.8.0`, // Integer32 °C
  temperatureB: `${SX4_BASE}.1.1.2.9.0`,
  /** Operating mode (read-write): 0=Boost, 1=Redundant. */
  operatingMode: `${SX4_BASE}.1.1.2.10.0`,
} as const;

/** lcsPortConfigurationTable (TABLE node …14.2.1.1) — index: port int. */
export const SX4_PORT_CONF = {
  base: `${SX4_BASE}.2.1.1`, // rows: <base>.1.<col>.<port>
  COL_DESCRIPTION: 2, // DisplayString (read-write), ≤16 chars
  COL_LINK: 3, // DisplayString "Up"/"Down"
  COL_SPEED_STATUS: 4, // DisplayString current link speed
  /** Speed/duplex mode (read-write): disable(0)/auto(1)/…/25G modes up to 24 — see MIB. */
  COL_SPEED_MODE: 5,
  COL_FLOW_CTRL_RX: 6, // Integer32 0/1/2(ro)
  COL_FLOW_CTRL_TX: 7, // Integer32 0/1/2(ro)
  COL_FLOW_CONTROL_MODE: 8, // Integer32 (read-write)
  COL_MAX_FRAME_SIZE: 9, // Integer32 1518..10240 (read-write)
  /** FEC mode (read-write): none(0)/rfec(1)/rsfec(2)/auto(3). */
  COL_FEC_MODE: 150,
} as const;

/** lcsPortTrafficStatisticsTable (TABLE node …14.2.1.2) — index: port int.
 *  FAST-PATH byte counters for rate computation. */
export const SX4_PORT_TRAFFIC = {
  base: `${SX4_BASE}.2.1.2`, // rows: <base>.1.<col>.<port>
  COL_CLEAR: 2, // Integer32 (read-write) — counter reset trigger
  COL_RX_PACKETS: 3, // Counter64
  COL_RX_OCTETS: 4, // Counter64
  COL_RX_UNICAST: 5, // Counter64
  COL_RX_MULTICAST: 6, // Counter64
  COL_RX_BROADCAST: 7, // Counter64
  COL_RX_DROPS: 24, // Counter64
  COL_RX_CRC_OR_ALIGNMENT: 25, // Counter64
  COL_TX_PACKETS: 31, // Counter64
  COL_TX_OCTETS: 32, // Counter64
  COL_TX_UNICAST: 33, // Counter64
  COL_TX_MULTICAST: 34, // Counter64
  COL_TX_BROADCAST: 35, // Counter64
  COL_TX_DROPS: 52, // Counter64
  COL_TX_LATE_OR_EXC_COLLISIONS: 53, // Counter64
} as const;

/** lcsVlanTable (TABLE node …14.1.10.2.3) — index: ifIndex (= panel port). */
export const SX4_VLAN = {
  base: `${SX4_BASE}.1.10.2.3`, // rows: <base>.1.<col>.<ifIndex>
  /** Port mode (read-write): access(0)/trunk(1)/hybrid(2). */
  COL_MODE: 2,
  /** PVID — the port's VLAN ID (read-write), 1..4094. */
  COL_PVID: 3,
  /** Port type (read-write): unaware(0)/cPort(1)/sPort(2)/sCustomPort(3). */
  COL_PORT_TYPE: 4,
  COL_INGRESS_FILTERING: 5, // AdminMode (read-write)
  COL_INGRESS_ACCEPTANCE: 7, // taggedAndUntagged(0)/taggedOnly(1)/untaggedOnly(2)
  COL_EGRESS_TAGGING: 8, // untagPortVlan(0)/tagAll(1)/untagAll(2)
  /** Allowed VLAN list (read-write), DisplayString "1,10-13" or "-" when empty. */
  COL_ALLOWED_VLANS: 9,
  COL_FORBIDDEN_VLANS: 10, // DisplayString
} as const;

/** lcsIPInterfacesTable (TABLE node …14.1.4.3.1) — index: int 1..128.
 *  One row per configured IP interface (VLAN SVI / management). */
export const SX4_SVI = {
  base: `${SX4_BASE}.1.4.3.1`, // rows: <base>.1.<col>.<index>
  COL_VLAN: 2, // Integer32 1..4094 (read-write)
  COL_IPV4_DHCP_LEASE: 5, // IpAddress (ro) — current DHCP lease
  COL_IPV4_ADDRESS: 6, // IpAddress (read-write)
  COL_IPV4_MASK_LEN: 7, // Integer32 0..32 (read-write)
  COL_IPV6_RAPID_COMMIT: 9, // Integer32 0/1
  COL_IPV6_CURRENT_LEASE: 10, // DisplayString (ro)
  COL_IPV6_ADDRESS: 11, // DisplayString (read-write), SIZE(0..30)
  COL_IPV6_MASK_LEN: 12, // Integer32 0..128 (read-write)
} as const;

/** lcsIPRoutesTable (TABLE node …14.1.4.4.1) — index: int 1..32.
 *  Configured STATIC routes (read-write; we only read). */
export const SX4_IP_ROUTES = {
  base: `${SX4_BASE}.1.4.4.1`, // rows: <base>.1.<col>.<index>
  COL_INDEX: 2, // Integer32 1..32 (not-accessible)
  COL_NETWORK: 3, // DisplayString IPv4/IPv6 network address
  COL_MASK_LENGTH: 4, // Integer32 0..128
  COL_GATEWAY: 5, // DisplayString IPv4/IPv6 gateway
  COL_NEXT_HOP_VLAN: 6, // Integer32 0..4094 (v6 link-local gateways)
  COL_ROW_STATUS: 7, // RowStatus — skip when parsing (not a data column)
  COL_DISTANCE: 50, // Integer32 1..255 admin distance (DEFVAL 1)
} as const;

/** lcsIPStatusRouteTable (TABLE node …14.1.4.9.1) — index: int 1..2048.
 *  LIVE routing table ("show all routing entries") → routes inventory. */
export const SX4_IP_STATUS_ROUTES = {
  base: `${SX4_BASE}.1.4.9.1`, // rows: <base>.1.<col>.<index>
  COL_INDEX: 1, // Integer32 1..2048 (not-accessible)
  COL_NETWORK: 2, // DisplayString destination network or host address
  COL_GATEWAY: 3, // DisplayString gateway address of this route
  COL_ADDRESS: 4, // DisplayString "the route address"
} as const;

/** lcsIPStatusNeighborCacheTable (TABLE node …14.1.4.10.1) — index: int 1..1024.
 *  The switch's ARP/NDP neighbor cache → hosts inventory. */
export const SX4_NEIGHBOR = {
  base: `${SX4_BASE}.1.4.10.1`, // rows: <base>.1.<col>.<index>
  COL_IP_ADDRESS: 2, // DisplayString (v4 dotted-quad or v6 literal)
  COL_LINK_ADDRESS: 3, // MAC address
} as const;

/** lcsPoeStatusTable (TABLE node …14.2.13.1.1) — index: local port int (1..10). */
export const SX4_POE_STATUS = {
  base: `${SX4_BASE}.2.13.1.1`, // rows: <base>.1.<col>.<port>
  COL_PD_CLASS: 2, // DisplayString ("Class 4" / "Max. power 30 W")
  COL_POWER_REQUESTED: 3, // DisplayString watts
  COL_POWER_ALLOCATED: 4, // DisplayString watts
  COL_POWER_USED: 5, // DisplayString watts
  COL_CURRENT_USED: 6, // DisplayString amps
  COL_PRIORITY: 7, // DisplayString low/high/critical
  COL_PORT_STATUS: 8, // DisplayString on/off/fault…
} as const;

/** lcsPoeStatusTotalTable (TABLE node …14.2.13.1.2) — index: switch int (1..16). */
export const SX4_POE_TOTALS = {
  base: `${SX4_BASE}.2.13.1.2`, // rows: <base>.1.<col>.<switch>
  COL_TOTAL_REQUESTED: 2, // DisplayString watts
  COL_TOTAL_ALLOCATED: 3, // DisplayString watts
  COL_TOTAL_USED: 4, // DisplayString watts
  COL_TOTAL_CURRENT: 5, // DisplayString amps
} as const;

/** lcsPoeConfigurationPortTable (TABLE node …14.2.13.5.5) — index: port int. */
export const SX4_POE_CONF = {
  base: `${SX4_BASE}.2.13.5.5`, // rows: <base>.1.<col>.<port>
  /** PoE mode (read-write): disable(0)/poe(1)/4pair60W(2)/4pair90W(3)/8023bt(4)/8023bt30w(10)/8023bt60w(11). */
  COL_POE_MODE: 2,
  /** Priority (read-write): low(0)/high(1)/critical(2). */
  COL_PRIORITY: 3,
  COL_MAX_POWER_WATTS: 4, // DisplayString watts (read-write)
  COL_DETECTION: 5, // Integer32 1..5 (read-write)
  COL_SCHEDULE_PROFILE_NAME: 7, // DisplayString (read-write)
  COL_DELAY_MODE: 8, // Integer32 0/1 (read-write)
  COL_DELAY_TIME: 9, // Integer32 0..300 s (read-write)
  /** Simple enable/disable mode (read-write): disable(0)/enable(1). */
  COL_MODE: 12,
  /** Max power class limit (read-write): see SX4_POE_MAX_POWER in sxClient.ts. */
  COL_MAX_POWER_ENUM: 13,
} as const;

/** lcsLACPPortConfigTable (TABLE node …14.2.36.2.1) — index: port int. */
export const SX4_LACP_CONF = {
  base: `${SX4_BASE}.2.36.2.1`, // rows: <base>.1.<col>.<port>
  COL_ENABLED: 2, // Integer32 0/1 (read-write)
  COL_KEY: 3, // Integer32 aggregation key (read-write)
  /** Role (read-write): passive(0)/active(1). */
  COL_ROLE: 4,
  /** Timeout (read-write): slow(0)/fast(1). */
  COL_TIMEOUT: 5,
  COL_PRIORITY: 6, // Integer32 1..65535 (read-write)
} as const;

/** lcsLACPStatusTable (TABLE node …14.2.36.6.1) — index: port int. */
export const SX4_LACP_STATUS = {
  base: `${SX4_BASE}.2.36.6.1`, // rows: <base>.1.<col>.<port>
  /** "Yes" (up+enabled), "No", or "Backup". */
  COL_LACP: 2, // DisplayString
  COL_KEY: 3, // DisplayString
  COL_AGGR_ID: 4, // DisplayString
  COL_PARTNER_SYSTEM_ID: 5, // DisplayString MAC
  COL_PARTNER_PORT: 6, // DisplayString
  COL_PARTNER_PRIO: 7, // DisplayString
} as const;

/* ================================================================== *
 * SX3 — legacy GS-2310 tree (firmware 3.x)
 * ================================================================== */

/** gs2310SystemInformation scalars (…800.3.2313.1.1.N) — same mandatory
 *  `.0` scalar-instance suffix as the unified tree. */
export const SX3_SYS = {
  base: `${SX3_BASE}.1.1`,
  model: `${SX3_BASE}.1.1.1.0`, // DisplayString "GS-2310"
  biosVersion: `${SX3_BASE}.1.1.2.0`,
  firmwareVersion: `${SX3_BASE}.1.1.3.0`,
  hardwareMechanicalVersion: `${SX3_BASE}.1.1.4.0`,
  serialNumber: `${SX3_BASE}.1.1.5.0`,
  hostMacAddress: `${SX3_BASE}.1.1.6.0`, // MacAddress
  consoleBaudrate: `${SX3_BASE}.1.1.7.0`,
  ramSize: `${SX3_BASE}.1.1.8.0`, // DisplayString KB
  flashSize: `${SX3_BASE}.1.1.9.0`,
  bridgeFdbSize: `${SX3_BASE}.1.1.10.0`,
  transmitQueue: `${SX3_BASE}.1.1.11.0`,
  maximumFrameSize: `${SX3_BASE}.1.1.12.0`,
  cpuLoad: `${SX3_BASE}.1.1.13.0`, // DisplayString
  systemDescription: `${SX3_BASE}.1.1.21.0`,
  location: `${SX3_BASE}.1.1.22.0`,
  contact: `${SX3_BASE}.1.1.23.0`,
  deviceName: `${SX3_BASE}.1.1.24.0`,
  systemDate: `${SX3_BASE}.1.1.25.0`,
  uptime: `${SX3_BASE}.1.1.26.0`, // DisplayString as reported
  /** Management IPv4 config (read-only scalars — the only IP info on 3.x). */
  ipv4Address: `${SX3_BASE}.1.1.27.0`,
  ipv4SubnetMask: `${SX3_BASE}.1.1.28.0`, // dotted-quad mask
  ipv4Gateway: `${SX3_BASE}.1.1.29.0`,
  ipv6LinkLocalAddress: `${SX3_BASE}.1.1.30.0`,
  ipv6Address: `${SX3_BASE}.1.1.31.0`,
  ipv6Prefix: `${SX3_BASE}.1.1.32.0`, // prefix length as DisplayString
  ipv6Gateway: `${SX3_BASE}.1.1.33.0`,
  largestFreeMemBlockKb: `${SX3_BASE}.1.1.1500.0`, // Integer32 KB
  memFreeKb: `${SX3_BASE}.1.1.1501.0`, // Integer32 KB
} as const;

/** gs2310PortConfigurationTable (TABLE node …800.3.2313.2.1.1) — index: port int.
 *  Column numbers MATCH the unified 4.x table for the shared columns. */
export const SX3_PORT_CONF = {
  base: `${SX3_BASE}.2.1.1`, // rows: <base>.1.<col>.<port>
  COL_MEDIA: 2, // DisplayString (ro) — copper/SFP media hint
  COL_LINK: 3, // DisplayString "Up"/"Down"
  COL_CURRENT_SPEED: 4, // DisplayString current link speed
  /** Speed/duplex mode (read-write): disable(0)/auto(1)/…/1000X(11) — see MIB. */
  COL_SPEED: 5,
  COL_FLOW_CTRL_RX: 6, // Integer32 0/1/2(ro)
  COL_FLOW_CTRL_TX: 7, // Integer32 0/1/2(ro)
  COL_FLOW_CONTROL: 8, // Integer32 (read-write)
  COL_MAX_FRAME_SIZE: 9, // Integer32 1518..9600 (read-write)
  COL_EXCESSIVE_COLLISION_MODE: 10, // discard(0)/restart(1)/noSupport(2)
  COL_POWER_CONTROL: 11, // disable(0)/actiphy(1)/dynamic(2)/enable(3)/noSupport(4)
  COL_DESCRIPTION: 12, // DisplayString (read-write), ≤47 chars
} as const;

/** gs2310PortTrafficStatisticsTable (TABLE node …800.3.2313.2.1.2) — index: port int.
 *  Column numbers IDENTICAL to the unified 4.x traffic table. */
export const SX3_PORT_TRAFFIC = {
  base: `${SX3_BASE}.2.1.2`, // rows: <base>.1.<col>.<port>
  COL_CLEAR: 2, // Integer32 (read-write)
  COL_RX_PACKETS: 3, // Counter64
  COL_RX_OCTETS: 4, // Counter64
  COL_RX_UNICAST: 5, // Counter64
  COL_RX_MULTICAST: 6, // Counter64
  COL_RX_BROADCAST: 7, // Counter64
  COL_RX_DROPS: 24, // Counter64
  COL_RX_CRC_OR_ALIGNMENT: 25, // Counter64
  COL_TX_PACKETS: 31, // Counter64
  COL_TX_OCTETS: 32, // Counter64
  COL_TX_UNICAST: 33, // Counter64
  COL_TX_MULTICAST: 34, // Counter64
  COL_TX_BROADCAST: 35, // Counter64
  COL_TX_DROPS: 52, // Counter64
  COL_TX_LATE_OR_EXC_COLLISIONS: 53, // Counter64
} as const;

/* ================================================================== *
 * Standard MIBs (both firmware lines)
 * ================================================================== */

/** Q-BRIDGE-MIB dot1qTpFdbTable — transient FDB used to enrich host rows with
 *  the port a MAC was learned on. Best-effort: absent/empty ⇒ no enrichment.
 *  Entry index is {dot1qFdbAddress, dot1qFdbId}; columns of interest: */
export const QB_FDB = {
  base: '.1.3.6.1.2.1.17.7.1', // rows: <base>.1.<col>.<mac(6 octets)>.<fdbId>
  COL_ADDRESS: 2, // MacAddress (ro)
  COL_PORT: 4, // Integer32 ifIndex the MAC was learned on (ro)
} as const;
