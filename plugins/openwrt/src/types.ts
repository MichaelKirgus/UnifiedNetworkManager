/**
 * OpenWRT plugin — shared row/snapshot types.
 *
 * Row shapes mirror what the API's ingestInventory() consumes (see
 * packages/plugin-sdk/src/types.ts INVENTORY_KEYS) plus the unified
 * firewallRules shape shared with OPNsense/RouterOS on the cross-device
 * Firewall page.
 */

/** How the plugin reaches an appliance: LuCI ubus-over-HTTP, SSH shell, or auto-negotiated. */
export type OpenWrtTransportMode = 'auto' | 'luci' | 'ssh';

/** Configured endpoint ports (defaults 443/80) — explicit address port always wins. */
export interface OpenWrtPorts {
  httpsPort?: number;
  httpPort?: number;
}

/** One configured network/interface row → `metrics['networks']` + device_ports. */
export interface NetworkRow {
  name: string;
  ip?: string | null;
  prefix?: number | null;
  version?: 'v4' | 'v6' | null;
  vlanId?: number | null;
  mac?: string | null;
  status?: string | null;
}

/** One ARP/NDP/DHCP-lease row → `metrics['arp'|'ndp'|'dhcpLeases']` (hosts table). */
export interface HostRow {
  mac: string;
  ip?: string;
  hostname?: string | null;
  manufacturer?: string | null;
  intf?: string | null;
  expiry?: string | null;
}

/** One tunnel row → `metrics['tunnels']` (WireGuard/OpenVPN/PPPoE/GRE). */
export interface TunnelRow {
  name: string;
  type: string;
  peerAddress?: string;
  localAddress?: string;
  subnet?: string | null;
  status?: string;
  uptimeSeconds?: number | null;
  lastHandshakeSeconds?: number | null;
  interfaceName?: string | null;
  rxRate?: number | null;
  txRate?: number | null;
  extra?: Record<string, unknown>;
}

/** One route row → `metrics['routes']`. */
export interface RouteRow {
  destination: string;
  gateway?: string;
  protocol?: string;
  distance?: number | null;
  metric?: number | null;
  mtu?: number | null;
  status?: string;
  extra?: Record<string, unknown>;
}

/** One wireless SSID row → `metrics['wifiNetworks']`. */
export interface WifiSsidRow {
  name: string;
  band: string;
  channel?: number | null;
  bssid?: string | null;
  encryption?: string | null;
  vlanId?: number | null;
  ifc?: string | null;
}

/** One device port row → `metrics['ports']` (device_ports table). */
export interface PortRowLike {
  name: string;
  status?: string | null;
  speed?: string | null;
  duplex?: string | null;
  vlanId?: number | null;
  poe?: string | null;
  extra?: Record<string, unknown>;
}

/** One firewall rule row — the unified cross-device shape (see opnsense/src/firewall.ts). */
export interface FirewallRuleRow {
  ruleType: 'filter' | 'dnat' | 'snat';
  vendorRuleId: string;
  position: number;
  protocol: string;
  sourceIp: string;
  destIp: string;
  sourcePort: string | null;
  destPort: string | null;
  action: 'allow' | 'deny' | 'other';
  enabled: boolean;
  description: string;
  scope: string;
  ipVersion: 'v4' | 'v6' | 'both';
  packets?: number | null;
  bytes?: number | null;
  states?: number | null;
  extra: Record<string, unknown>;
}

/** One running service row (init.d script + live state). */
export interface ServiceRow {
  name: string;
  enabled: boolean;
  running: boolean;
  pid?: number | null;
}

/** One filesystem/disk row for the Storage page. */
export interface FilesystemRow {
  name: string;
  type: string;
  sizeBytes: number | null;
  usedBytes: number | null;
  availBytes: number | null;
  mountpoint?: string | null;
}

/** Board/system identity info. */
export interface BoardInfo {
  hostname: string;
  model: string;
  board: string;
  release: string;
  revision?: string | null;
  uptimeSeconds?: number | null;
}

/** The full per-host inventory snapshot (15-min cadence, cached in memory). */
export interface InventorySnapshot {
  collectedAt: string;
  board: BoardInfo | null;
  networks: NetworkRow[];
  arp: HostRow[];
  ndp: HostRow[];
  dhcpLeases: HostRow[];
  routes: RouteRow[];
  tunnels: TunnelRow[];
  wifiSsids: WifiSsidRow[];
  firewallRules: FirewallRuleRow[] | null; // null = collection failed (keep previous rows)
  services: ServiceRow[];
  filesystems: FilesystemRow[];
  certificates: import('@unm/plugin-sdk').CertificateRow[];
}

/** Per-host transport state resolved for one request. */
export interface TransportState {
  /** The requested mode from settings. */
  mode: OpenWrtTransportMode;
  /** Resolved LuCI base URL (null = unavailable / not used). */
  luciBaseUrl: string | null;
  /** True when the SSH path is usable for this request. */
  sshAvailable: boolean;
  /** Human-readable report of what was negotiated (for /state + logs). */
  report: string[];
}
