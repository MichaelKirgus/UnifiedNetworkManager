/**
 * LCOS unified MIB numeric OID map for Lancom LCOS routers.
 *
 * Every constant is taken from the vendor MIB's explicit `{TABLE}` / `{SCALAR}`
 * / `{COLUMN}` annotations (LC-UNIFIED-LCOS-10-94-REL-OIDS.mib, module `lcos`),
 * NOT inferred from SEQUENCE order — LANCOM uses gapped, non-sequential column
 * numbering, so a column's position in the MIB text is meaningless. The full
 * dotted prefix for every entry is `.1.3.6.1.4.1.2356.` + the suffix shown
 * (lcos = 11). NOTE: this is a DIFFERENT tree from the LCOS-LX AP MIB used by
 * the lancom-lx plugin (that one lives at 2356.13) — no OID overlap.
 *
 * Scope note: this map targets current LCOS routers as a superset. Lower-end or
 * older models expose fewer tables/columns — parsers must treat any missing OID
 * as absent, never an error. The writable `lcsSetup` objects at the bottom are
 * used by the config actions (SNMP SET); everything above is read-only status.
 */

/** lcos module root: enterprises.lancom-systems(2356).11 */
export const LCOS_BASE = '.1.3.6.1.4.1.2356.11';

/* ------------------------------------------------------------------ *
 * System / hardware (read-only scalars) — 11.1, 11.2, 11.3
 * ------------------------------------------------------------------ */
// NOTE: every scalar instance carries a trailing ".0" sub-identifier. Table
// rows are addressed COLUMN-FIRST — <table>.1.<column>.<index…> — see lcosClient.ts.
export const SYS = {
  /** lcsStatusOperatingTime — uptime as DisplayString (e.g. "3 days, 4 hours"). */
  operatingTime: `${LCOS_BASE}.1.2.0`,
  /** lcsSetupName — configured device name (config mirror; read-write but we only read). */
  setupName: `${LCOS_BASE}.2.1.0`,
} as const;

/** lcsStatusHardwareInfo group (11.1.47) — scalars, all with trailing .0. */
export const HW = {
  base: `${LCOS_BASE}.1.47`,
  cpuType: `${LCOS_BASE}.1.47.1.0`,
  cpuClockMhz: `${LCOS_BASE}.1.47.2.0`,
  totalMemoryKbytes: `${LCOS_BASE}.1.47.4.0`,
  freeMemoryKbytes: `${LCOS_BASE}.1.47.5.0`,
  modelNumber: `${LCOS_BASE}.1.47.6.0`,
  serialNumber: `${LCOS_BASE}.1.47.7.0`,
  swVersion: `${LCOS_BASE}.1.47.9.0`,
  /** eNo(0)/eYes(1) — hardware security engine present? */
  securityEngine: `${LCOS_BASE}.1.47.11.0`,
  /** lcsStatusHardwareInfoCpuLoad60sPercent (Integer32 0..255). */
  cpuLoad60sPercent: `${LCOS_BASE}.1.47.14.0`,
} as const;

/** lcsFirmware group (11.3) — per-module firmware table + scalars. */
export const FIRMWARE = {
  /** lcsFirmwareVersionTable (11.3.1) — index: ifc int (eIfc=1). */
  versionTableBase: `${LCOS_BASE}.3.1`,
  COL_MODULE: 2, // DisplayString
  COL_VERSION: 3, // DisplayString
  COL_SERIAL: 4, // DisplayString
  /** lcsFirmwareBootCause — DisplayString (e.g. "power on", "watchdog"). */
  bootCause: `${LCOS_BASE}.3.9.0`,
  /** lcsFirmwareFeatureWord — feature/license word of the running image. */
  featureWord: `${LCOS_BASE}.3.7.0`,
} as const;

/* ------------------------------------------------------------------ *
 * LAN status — 11.1.5 (per-interface, indexed by ifc text "LAN-1"…)
 * ------------------------------------------------------------------ */

/** lcsStatusLanInterfacesTable (11.1.5.51) — link state + connector per port. */
export const LAN_IF = {
  base: `${LCOS_BASE}.1.5.51`, // index: ifc text (length-prefixed, e.g. "LAN-1")
  COL_LINK_ACTIVE: 3, // eNo(0)/eYes(1)
  COL_CONNECTOR: 4, // enum — see LAN_CONNECTORS in lcosClient.ts
  COL_MAC: 13, // MacAddress
} as const;

/** lcsStatusLanByteTransportTable (11.1.5.52) — FAST-PATH byte counters. */
export const LAN_BYTES = {
  base: `${LCOS_BASE}.1.5.52`, // index: ifc text
  COL_TX: 2, // Counter64
  COL_RX: 3, // Counter64
  COL_THROUGHPUT_LABEL: 4, // DisplayString (agent-side rate label)
} as const;

/* ------------------------------------------------------------------ *
 * WAN status — 11.1.4 (per-WAN-interface, indexed by ifc INTEGER)
 * ------------------------------------------------------------------ */

/** lcsStatusWanByteTransportTable (11.1.4.1) — FAST-PATH byte counters. */
export const WAN_BYTES = {
  base: `${LCOS_BASE}.1.4.1`, // index: ifc int — eCh01(257)…eModem(513), DSL/XDSL/ADSL/VDSL ranges
  COL_CRX: 2, // Counter32 (compressed rx)
  COL_RX: 3, // Counter32
  COL_TX: 4, // Counter32
  COL_CTX: 5, // Counter32 (compressed tx)
  COL_HRX: 6, // Counter64 — preferred high-resolution counters
  COL_HTx: 7, // Counter64
} as const;

/** lcsStatusWanIpAddressesIpv4Table (11.1.4.13.1) — per-WAN-IP config mirror. */
export const WAN_IP = {
  base: `${LCOS_BASE}.1.4.13.1`, // index: peer text (length-prefixed, e.g. "WAN")
  COL_TYPE: 2, // eStatic(1)/eDhcp(2)/ePpp(3)/eAutoconfig(4)
  COL_ADDR: 3, // IpAddress
  COL_NETMASK: 4, // IpAddress
  COL_GATEWAY: 5, // IpAddress
  COL_DNS_DEFAULT: 6, // IpAddress
  COL_DNS_BACKUP: 7, // IpAddress
} as const;

/* ------------------------------------------------------------------ *
 * TCP/IP status — 11.1.9 (networks, ARP, DHCP)
 * ------------------------------------------------------------------ */

/** lcsStatusTcpIpNetworkListTable (TABLE node 11.1.9.20) — configured networks. */
export const NET_LIST = {
  base: `${LCOS_BASE}.1.9.20`, // index: networkName text (length-prefixed, e.g. "LAN")
  COL_IP: 2, // IpAddress
  COL_NETMASK: 3, // IpAddress
  COL_VLAN: 4, // Integer32
  COL_IFC: 5, // enum — eLan1(256)… (see decodeNetIfc in lcosClient.ts)
} as const;

/** lcsStatusTcpIpArpTableArpTable (TABLE node 11.1.9.1.7) — ARP cache, indexed by IP address. */
export const ARP = {
  base: `${LCOS_BASE}.1.9.1.7`, // index: ipAddress — four decimal octets
  COL_MAC: 2, // MacAddress
  COL_LAST_ACCESS: 3, // Integer32 (seconds)
  COL_PORT: 5, // enum — see ARP_PORTS in lcosClient.ts
} as const;

/** lcsStatusTcpIpDhcpDhcpTableTable (TABLE node 11.1.9.6.16) — active DHCP leases. */
export const DHCP = {
  base: `${LCOS_BASE}.1.9.6.16`, // index: [ipAddress(4 octets), networkName text]
  COL_MAC: 2, // DisplayString (SIZE 0..12)
  COL_TIMEOUT: 3, // Integer32 — remaining lease seconds
  COL_HOSTNAME: 4, // DisplayString
  COL_PORT: 7, // enum like ARP_PORTS — col 5 is Type (gapped!)
  COL_VLAN: 8, // Integer32
} as const;

/* ------------------------------------------------------------------ *
 * VPN status — 11.1.26 (per-connection)
 * ------------------------------------------------------------------ */

/** lcsStatusVpnConnectionsTable (TABLE node 11.1.26.17) — active VPN connections. */
export const VPN_CONN = {
  base: `${LCOS_BASE}.1.26.17`, // index: peer text (length-prefixed, e.g. "IPSEC-1")
  COL_PHYS: 2, // DisplayString — physical connection name
  COL_CRYPT_ALG: 4, // DisplayString (e.g. "AES-128")
  COL_STATE: 11, // enum — see VPN_STATES in lcosClient.ts
  COL_MODE: 12, // ePassive(0)/eActive(128)
  COL_CONN_TIME: 19, // Gauge32 — seconds since established
  COL_IKE_TYPE: 22, // DisplayString (e.g. "IKEv2") — col 20 is SslEncaps (gapped!)
} as const;

/* ------------------------------------------------------------------ *
 * WLAN status — 11.1.3 (only on LCOS models with built-in radios)
 * ------------------------------------------------------------------ */

/** lcsStatusWlanNetworksTable (TABLE node 11.1.3.56) — per-radio SSID/network config mirror. */
export const WLAN_NET = {
  base: `${LCOS_BASE}.1.3.56`, // index: ifc text (radio, e.g. "WLAN-1")
  COL_OPERATING: 2, // eNo(0)/eYes(1)
  COL_NAME: 3, // DisplayString — network name
  COL_STATIONS: 4, // Integer32
  COL_BSSID: 6, // MacAddress
  COL_VLAN: 7, // Integer32
} as const;

/** lcsStatusWlanRadiosTable (TABLE node 11.1.3.57) — per-radio RF status. */
export const WLAN_RADIO = {
  base: `${LCOS_BASE}.1.3.57`, // index: ifc text
  COL_BAND: 2, // eUnknown(0)/e24ghz(1)/e5ghz(2)/e24ghz5ghz(3)
  COL_CHANNEL: 3, // Integer32 (0..255)
  COL_NOISE: 5, // Int32 dBm
  COL_MODEM_LOAD: 6, // Integer32 %
  COL_TX_POWER: 7, // DisplayString
  COL_EIRP: 8, // DisplayString
  COL_MODE: 14, // enum — radio mode (e11b…mixes) — col 12 is BackgroundScanUnit (gapped!)
  COL_BANDWIDTH: 19, // enum — channel bandwidth
  COL_UTILIZATION: 28, // Integer32 % (channel utilization) — gapped numbering!
} as const;

/** lcsStatusWlanStationTableTable (TABLE node 11.1.3.32) — per-client stations. */
export const WLAN_STATION = {
  base: `${LCOS_BASE}.1.3.32`, // index: plain Integer32 (0..65535)
  COL_MAC: 4, // MacAddress
  COL_TX_BYTES: 6, // Counter64
  COL_RX_BYTES: 7, // Counter64
  COL_IDENT: 9, // DisplayString — identification string
  COL_STATE: 10, // enum — see STATION_STATES in lcosClient.ts
  COL_IFC: 15, // enum — eWlan1(0)…eWlan4(3) → "WLAN-<n+1>"
  COL_NETWORK: 25, // enum — network id (no reliable join target; shown raw)
  COL_SIGNAL: 26, // Int32 dBm
  COL_IP4: 27, // IpAddress
  COL_VLAN: 38, // Integer32
  COL_USER: 39, // DisplayString — 802.1X identity when present
  COL_EFF_TX: 50, // Integer32 Mbit/s
  COL_EFF_RX: 51, // Integer32 Mbit/s
  COL_IP6: 53, // IpAddress
  COL_HOSTNAME: 80, // DisplayString — DHCP hostname
} as const;

/* ------------------------------------------------------------------ *
 * IP routing status — 11.1.10 (active routing table)
 * ------------------------------------------------------------------ */

/** lcsStatusIpRouterActIpRoutingTabTable (TABLE node 11.1.10.30).
 *  The router's ACTIVE routing table — one row per installed route, with a
 *  per-row Type enum that labels the protocol (static/rip/bgp/ospf/…). A single
 *  walk therefore yields static AND dynamically-learned routes together.
 *  Index: [ipAddress(4 octets), ipNetmask(4 octets), rtgTag int]. IPv4 only —
 *  the MIB has no v6 route table. */
export const IP_ROUTES = {
  base: `${LCOS_BASE}.1.10.30`, // rows: <base>.1.<col>.<ip(4)><netmask(4)><rtgTag>
  COL_IP: 1, // IpAddress — destination network address
  COL_NETMASK: 2, // IpAddress — netmask (dotted-quad)
  COL_RTG_TAG: 3, // Integer32 0..65535 — routing table tag
  COL_GATEWAY: 4, // IpAddress — next hop ('0.0.0.0' = directly connected)
  COL_PEER: 5, // DisplayString (SIZE 0..255) — peer/interface name when set
  COL_DISTANCE: 6, // Integer32 0..255 — admin distance
  COL_MASQUERADE: 7, // enum eNo(0)/eOn(1)/eIntranet(2)/eUnknown(255)
  /** Route origin (see IP_ROUTE_TYPES in lcosClient.ts). */
  COL_TYPE: 8,
} as const;

/** Standard ipCidrRouteTable (IP-FORWARD-MIB, RFC 2993) — MIB-2 base .1.3.6.1.2.1.4.24.
 *  Fallback for firmware that does NOT expose the vendor active-routing table
 *  (lcsStatusIpRouterActIpRoutingTabTable / 11.1.10.30): LCOS agents implement
 *  this standard table on all models, but with a NON-STANDARD row layout
 *  (verified live on LCOS 10.94):
 *    <base>.4.1.<col(1..16)>.<dest(4 octets).mask(4 octets).filler(1).nextHop(4 octets)>
 *  The column number follows standard IP-FORWARD-MIB ordering (1=dest, 2=mask,
 *  3=tos, 4=nextHop, …, 6=type, 7=proto, …, 11=metric1, …, 16=status). The
 *  agent reports several columns with the wrong SNMP type (Gauge32 instead of
 *  INTEGER) and its proto/type enums do not follow RFC semantics — so the
 *  parser derives protocol from next-hop presence and keeps raw values. */
export const IP_CIDR_ROUTES = {
  base: '.1.3.6.1.2.1.4.24', // rows: <base>.4.1.<col>.<dest(4)><mask(4)>0<nextHop(4)>
  COL_DEST: 1, // IpAddress — destination network address
  COL_MASK: 2, // IpAddress — netmask (dotted-quad)
  COL_NEXT_HOP: 4, // IpAddress — '0.0.0.0'/'255.255.255.255' = directly connected
  /** RFC {other(0), invalid(1), direct(2), indirect(3)} — agent values unreliable; only invalid(1) is acted on (row dropped). */
  COL_TYPE: 6,
  /** RFC {other(0), connected(1), static(2)}. */
  COL_PROTO: 7,
  COL_METRIC1: 11, // INTEGER — routing metric/cost (-1/0 = unset)
  COL_STATUS: 16, // INTEGER {active(1), inactive(2), garbage(3), probe(4)}
} as const;

/* ------------------------------------------------------------------ *
 * Temperature monitor — 11.1.70 (min/max extremes per sensor)
 * ------------------------------------------------------------------ */

/** lcsStatusTemperatureMonitorExtremesTable (11.1.70.1). */
export const TEMP_EXTREMES = {
  base: `${LCOS_BASE}.1.70.1`, // index: type int — eMinimum1(1)/eMaximum1(2), +256 per sensor
  COL_VALUE: 2, // Int32 (tenths of a degree)
  COL_TIME: 3, // DisplayString
} as const;

/* ------------------------------------------------------------------ *
 * Writable lcsSetup objects — used by the config actions (SNMP SET).
 * The full setup tree is huge; only these safe, well-understood objects are
 * exposed in phase 1. Each action reads current state → snmpSet → re-reads to
 * verify (see actions/registry.ts).
 * ------------------------------------------------------------------ */

export const SETUP = {
  /** lcsSetupTcpIpDnsDefault — IpAddress, read-write. */
  dnsDefault: `${LCOS_BASE}.2.7.7.0`,
  /** lcsSetupTcpIpDnsBackup — IpAddress, read-write. */
  dnsBackup: `${LCOS_BASE}.2.7.8.0`,
  /** lcsSetupNtpServerOperating — INTEGER eNo(0)/eYes(1), read-write. */
  ntpOperating: `${LCOS_BASE}.2.26.2.0`,
  /**
   * lcsSetupNtpRqAddressTable (11.2.26.11) — NTP server list, indexed by the
   * address text itself; column .1 (RqAddress) is read-write. Adding a row =
   * snmpSet on <base>.1.1.<encoded-address>.
   */
  ntpRqAddressTableBase: `${LCOS_BASE}.2.26.11`,
  NTP_COL_ADDRESS: 1,
  /**
   * lcsSetupInterfacesLanInterfacesTable (11.2.23.21) — per-LAN-port config,
   * indexed by ifc INTEGER eLan1(1)…eLan16(16). Column .7 (Operating) is
   * read-write with INVERTED semantics: eYes(0)/eNo(1) — operating=ON means 0!
   */
  lanIfcTableBase: `${LCOS_BASE}.2.23.21`,
  LAN_COL_OPERATING: 7,
} as const;
