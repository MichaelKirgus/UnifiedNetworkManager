const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:3000/v1';

/** API error that may carry per-field validation messages (e.g. plugin settings). */
export class ApiError extends Error {
  status: number;
  /** Machine-readable error code when the API provides one (e.g. 'no_2fa_enrolled'). */
  code?: string;
  fieldErrors?: Record<string, string>;
  constructor(message: string, status: number, fieldErrors?: Record<string, string>, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.fieldErrors = fieldErrors;
    this.code = code;
  }
}

export interface Secret {
  id: string;
  label: string;
  type: string;
  providerId?: string | null;
  createdAt: string;
  expiresAt?: string;
  username: string;
}

export interface SecretField {
  name: string;
  label: string;
  /** textarea = multi-line (PEM keys, cert bundles). */
  input: 'text' | 'password' | 'select' | 'textarea';
  secret?: boolean;
  required?: boolean;
  options?: string[];
}

export interface SecretType {
  type: string;
  label: string;
  /** True when the provider can create/rotate this type's key material itself (POST /secrets/generate). */
  generatable?: boolean;
  fields: SecretField[];
}

export interface SecretProvider {
  id: string;
  name: string;
  version: string;
  endpoint: string;
  online: boolean;
  secretTypes: SecretType[];
}

export interface LoginResponse {
  challengeToken: string;
  twoFactorRequired: boolean;
}

export interface AuthFlow {
  flow: string;
  /** True when the active provider supports passkey (WebAuthn) step-2. */
  supportsPasskey?: boolean;
}

/** WebAuthn assertion options + nonce for a pending login challenge. */
export interface WebauthnAssertionOptions {
  /** PublicKeyCredentialRequestOptionsJSON — pass straight to navigator.credentials.get(). */
  options: Record<string, unknown>;
  /** Echo back with the assertion response (replay protection). */
  nonce: string;
}

/** WebAuthn registration options + nonce for enrolling a new passkey. */
export interface WebauthnRegistrationOptions {
  /** PublicKeyCredentialCreationOptionsJSON — pass to navigator.credentials.create(). */
  options: Record<string, unknown>;
  /** Echo back with the creation response (attestation is verified against it). */
  nonce: string;
}

/** An enrolled passkey (display metadata only — no key material). */
export interface PasskeyCredential {
  id: string;
  credentialId: string;
  label: string | null;
  transports: string[] | null;
  createdAt: string;
}

export interface AuthRedirect {
  redirectUrl: string;
}

export interface VerifyResponse {
  accessToken: string;
  expiresIn: number;
  username: string;
  roles: string[];
  /** Effective permission set (explicit grants + role-derived). */
  permissions: string[];
}

/** POST /auth/revalidate/challenge response — a pending in-session 2FA challenge. */
export interface RevalidateChallenge {
  challengeToken: string;
  twoFactorRequired: boolean;
  /** True when the caller has an enrolled passkey (the UI may offer it). */
  supportsPasskey?: boolean;
  /** The caller's user id — needed to fetch their own passkey assertion options. */
  userId: string;
}

/** Stores a freshly minted access token (login or in-session revalidation). */
export function setAccessToken(token: string): void {
  localStorage.setItem('accessToken', token);
}

/** A long-lived API token for agents/scripts (MCP server, CI). */
export interface ApiToken {
  id: string;
  userId: string;
  username?: string | null;
  label: string | null;
  /** First characters of the raw value, for display. */
  tokenPrefix: string | null;
  permissions: string[];
  /** True when permissions is empty (inherit the owner's full effective set). */
  inheritsAllPermissions?: boolean;
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
}

/** POST /tokens response — carries the raw value exactly once. */
export interface ApiTokenCreated extends ApiToken {
  rawToken: string;
}

/** One named credential slot a plugin declares in /discover (beyond its primary secret). */
export interface CredentialSlotDescriptor {
  name: string;
  /** Legacy single allowed type; `secretTypes` wins when present. */
  secretType?: string;
  /** All allowed secret types for this slot (one or many). */
  secretTypes?: string[];
  required?: boolean;
  description?: string;
}

/** Effective allowed types of a slot — `secretTypes` wins over legacy `secretType`. */
export function allowedSecretTypes(slot: Pick<CredentialSlotDescriptor, 'secretType' | 'secretTypes'>): string[] {
  if (slot.secretTypes && slot.secretTypes.length > 0) return slot.secretTypes;
  return slot.secretType ? [slot.secretType] : [];
}

/** A declared slot with the secret bound to it on an assignment (list views). */
export interface BoundCredentialSlot extends CredentialSlotDescriptor {
  secretId: string | null;
  secretLabel?: string | null;
}

/** One row of the device ↔ plugin join table (a device can have several). */
export interface DevicePluginAssignment {
  id: string;
  deviceId: string;
  pluginId: string;
  /** Credential source for this assignment (null = no credentials). */
  secretId?: string | null;
  /** Bound extra credential slots: slot name → secrets.id. */
  extraCredentials?: Record<string, string>;
  isPrimary: boolean;
  createdAt: string;
  // Enriched fields returned by the list endpoints:
  pluginName?: string;
  pluginVersion?: string;
  pluginEndpoint?: string;
  /** The assigned plugin's advertised capabilities (e.g. 'deviceState'). */
  pluginCapabilities?: string[];
  pluginOnline?: boolean;
  secretLabel?: string | null;
  /** The plugin's declared slots with their bound secrets resolved. */
  credentialSlots?: BoundCredentialSlot[];
}

export interface DevicePluginAssignmentInput {
  pluginId: string;
  secretId?: string | null;
  isPrimary?: boolean;
  /** Extra credential slots to bind (slot name → secrets.id; null clears). */
  extraCredentials?: Record<string, string | null>;
}

/** A device address as presented by the API (primary flag included). */
export interface DeviceAddress {
  /** IPv4, IPv6 literal, or DNS name (no scheme). */
  address: string;
  /** True for the device's managementAddress. */
  isPrimary: boolean;
  /** Row id of a secondary IP; null/undefined for the primary. */
  id?: string | null;
}

/** One row of the device_ips table (a secondary IP). */
export interface DeviceIpRow {
  id: string;
  deviceId: string;
  address: string;
  createdAt?: string;
}

/** A managed site (name + description + address/country/timezone/GPS). */
export interface Site {
  id: string;
  name: string;
  description?: string | null;
  address?: string | null;
  /** ISO-3166-1 alpha-2 country code, e.g. "DE". */
  country?: string | null;
  /** IANA timezone identifier, e.g. "Europe/Berlin". */
  timezone?: string | null;
  /** GPS location (WGS84 decimal degrees) — set together or both absent. */
  latitude?: number | null;
  longitude?: number | null;
  createdAt?: string;
}

export interface SiteCreateRequest {
  name: string;
  description?: string;
  address?: string;
  /** ISO-3166-1 alpha-2 country code, e.g. "DE". */
  country?: string;
  timezone?: string;
  /** GPS location — all-or-nothing (both set or both omitted/null). */
  latitude?: number | null;
  longitude?: number | null;
}

/** One configured network row from the cross-device inventory view.
 * Rows for the same interface on one device+plugin are merged into a single
 * row — a dual-stack interface appears once with both its IPv4 and IPv6 CIDRs. */
/** One device/interface that reports a logical network (a member of NetworkRow.devices). */
export interface NetworkDeviceMember {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the plugin instance that collected this row (e.g. "OPNsense Plugin (site-a)"). */
  pluginName?: string | null;
  /** Interface name(s) carrying this network on the device (e.g. ["lan"], ["WLAN-1","WLAN-2"]). */
  interfaces: string[];
  /** Addresses configured on those interfaces with their prefix when known, IPv4 first; empty for IP-less rows (SSIDs). */
  cidrs: string[];
  mac?: string | null;
  status?: string | null;
}

/** One LOGICAL network across devices. Several device interfaces that share a
 * subnet or VLAN are merged into one row — e.g. the same SSID/VLAN broadcast by
 * many APs appears once with all reporting devices listed. */
export interface NetworkRow {
  /** Canonical identity (subnet:<cidr>, vlan:<id> or name:<interface>). Stable for table keys. */
  key: string;
  /** Display label: subnet when known ("192.168.1.0/24"), else "VLAN <id>", else the interface name. */
  name: string;
  /** Subnet (network address + prefix) when any member carries an IP — null for pure SSID/VLAN rows. */
  subnet: string | null;
  /** ALL real subnets of this logical network, IPv4 first (dual-stack groups carry both). Empty for pure SSID/VLAN rows. */
  subnets?: string[];
  vlanId?: number | null;
  /** Address families present across all members (e.g. ["v4","v6"] for dual-stack). */
  versions: ('v4' | 'v6')[];
  devices: NetworkDeviceMember[];
  collectedAt: string;
}

/** One device+plugin instance that observed a host. */
export interface HostDeviceMember {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the plugin instance that observed this host. */
  pluginName?: string | null;
  /** Interface(s) on the observing device where the host was seen (e.g. ["lan"], ["wlan0"]). */
  interfaces: string[];
}

/** One physical host from the cross-device inventory view.
 * Rows with the same MAC are merged into a single row ACROSS devices and
 * plugins — e.g. a WLAN client on an AP that also appears in the router's ARP
 * table shows once, with all observing devices listed and hostname/manufacturer
 * taken from whichever source reported them. */
export interface HostRow {
  mac: string;
  /** All known addresses of this host, IPv4 first. */
  ips: string[];
  /** Discovery sources that reported this MAC anywhere on the network (e.g. arp + wlan; 'self' = the appliance's own interfaces). */
  sources: ('arp' | 'ndp' | 'dhcp' | 'wlan' | 'self')[];
  hostname?: string | null;
  manufacturer?: string | null;
  /** Lease expiry (when a DHCP lease is known for this MAC). */
  expiry?: string | null;
  lastSeenAt: string;
  /** Every device+plugin instance that observed this host (one entry each). */
  devices: HostDeviceMember[];
}

/** One configured tunnel from the cross-device inventory view. Unlike networks/hosts,
 * rows are NOT merged across devices — a tunnel row is one logical tunnel on one device. */
export interface TunnelRow {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the reporting plugin instance (e.g. "OPNsense Plugin"). */
  pluginName?: string | null;
  /** Tunnel/interface name on the device (e.g. "wg0", "IPSEC-1", "gre1"). */
  name: string;
  type: 'wireguard' | 'openvpn' | 'ipsec' | 'pppoe' | 'gre';
  /** Remote endpoint (peer IP/FQDN, remote gateway, GRE destination); '' = unknown. */
  peerAddress?: string;
  /** Local side of the tunnel (WG server IP, local gateway, PPPoE WAN IP); '' = unknown. */
  localAddress?: string;
  /** Tunnel subnet / assigned network (e.g. "10.99.0.0/24"). */
  subnet?: string | null;
  status: 'up' | 'down' | 'enabled' | 'disabled' | 'unknown';
  /** Live session uptime in seconds (null when not a live-session metric). */
  uptimeSeconds?: number | null;
  /** Seconds since the last handshake (WireGuard peers; null = no live data). */
  lastHandshakeSeconds?: number | null;
  /** Kernel interface carrying the tunnel traffic. */
  interfaceName?: string | null;
  /** Receive rate in bytes/s (plugin-computed counter delta; null when unavailable). */
  rxRate?: number | null;
  /** Transmit rate in bytes/s (plugin-computed counter delta; null when unavailable). */
  txRate?: number | null;
  /** Type-specific extras (ikeType, cryptAlg, mode, allowedIPs, ...). */
  extra?: Record<string, unknown>;
  collectedAt: string;
}

/** One discovered host matched by a firewall rule address (merged across devices). */
export interface FirewallResolvedHost {
  mac: string;
  /** All known addresses of this host, IPv4 first. */
  ips: string[];
  hostname?: string | null;
  manufacturer?: string | null;
  /** Device names that observed this host (deduped). */
  devices: string[];
}

/** Cross-device resolution of a firewall rule address against the inventory. */
export interface FirewallAddressResolution {
  /** Known subnets the address covers ("192.168.1.0/24"), IPv4 first. */
  subnets: string[];
  /** Interfaces carrying those subnets, labeled "DeviceName: iface". */
  interfaces: string[];
  /** Number of discovered hosts inside the address (may exceed hosts.length). */
  hostCount: number;
  /** Matched hosts, capped at 50 for payload size. */
  hosts: FirewallResolvedHost[];
  /** Tokens that are neither IP literals nor CIDRs — alias names not expandable here. */
  unresolved: string[];
}

/** One firewall rule (filter + NAT kinds) normalized across vendors by the plugins. */
export interface FirewallRuleRow {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the reporting plugin instance (e.g. "OPNsense Plugin"). */
  pluginName?: string | null;
  /** Normalized rule kind — filter rules vs. NAT kinds. */
  ruleType: 'filter' | 'dnat' | 'snat' | 'one-to-one' | 'npt';
  /** Stable vendor-side identity (OPNsense uuid / RouterOS .id). */
  vendorRuleId: string;
  /** Order within its rule set on the device (0-based; display data only). */
  position: number;
  /** Normalized protocol name ('tcp', 'udp', …); '' = any/unknown. */
  protocol?: string;
  /** Source network/CIDR or alias name as configured; '' = any. */
  sourceIp?: string;
  /** Destination network/CIDR or alias name as configured; '' = any. */
  destIp?: string;
  /** Source port(s) — single port or range string (null when n/a). */
  sourcePort?: string | null;
  /** Destination port(s) — single port or range string (null when n/a). */
  destPort?: string | null;
  /** Normalized verdict — allow/deny for filter rules; NAT actions map to 'other'. */
  action: 'allow' | 'deny' | 'other';
  enabled: boolean;
  /** Rule description / comment; '' = none. */
  description?: string;
  /** Where the rule applies (OPNsense interface, RouterOS chain + iface lists). */
  scope?: string;
  /** IP family the rule applies to — v4 / v6 / both. */
  ipVersion?: 'v4' | 'v6' | 'both';
  /** Live hit counter — packets matched (OPNsense + RouterOS; null when not reported). */
  packets?: number | null;
  /** Live hit counter — bytes matched (OPNsense + RouterOS; null when not reported). */
  bytes?: number | null;
  /** Current connection-state count (OPNsense pf states; null when not reported). */
  states?: number | null;
  /** Vendor-specific extras (uuid, family, log, tag, to-addresses, ...). */
  extra?: Record<string, unknown>;
  /** Cross-device resolution of the source address (null when nothing matched). */
  sourceResolved?: FirewallAddressResolution | null;
  /** Cross-device resolution of the destination address (null when nothing matched). */
  destResolved?: FirewallAddressResolution | null;
  collectedAt: string;
}

/** A physical port as reported by a device's latest telemetry snapshot. */
export interface TopologyPort {
  name: string;
  linkUp?: 'up' | 'down';
  speed?: string | null;
  /** access | trunk | hybrid (switches that report it). */
  mode?: string | null;
  pvid?: number | null;
  /** VLANs traversing this port — drives the per-VLAN edge coloring. */
  vlans: number[];
  mac?: string | null;
}

/** One node of the topology graph (GET /topology). `kind` discriminates shape. */
export type TopologyNode =
  | {
      id: string;
      kind: 'device';
      name: string;
      status: string;
      siteId: string | null;
      managementAddress: string;
      /** Resolved network-layer id (manual override > plugin suggestion > heuristic). */
      layer: string;
      ports: TopologyPort[];
      /** VLAN ids this device participates in. */
      vlans: number[];
    }
  | { id: string; kind: 'segment'; label: string; vlanId: number | null; subnets: string[] }
  | { id: string; kind: 'host'; mac: string; hostname: string | null; ips: string[] }
  /** Tunnel peer that is not part of this inventory (e.g. public WireGuard endpoint). */
  | { id: string; kind: 'remote'; label: string };

/** One edge of the topology graph. `kind` discriminates shape. */
export type TopologyEdge =
  | {
      id: string;
      source: string;
      target: string;
      kind: 'cable';
      /** Evidence the link was inferred from. */
      via: 'mac-table' | 'lacp';
      portA?: string | null;
      portB?: string | null;
      /** VLANs traversing the observing port (trunk coloring); empty = unknown. */
      vlans: number[];
    }
  | { id: string; source: string; target: string; kind: 'tunnel'; type: string; status: string | null }
  | { id: string; source: string; target: string; kind: 'membership'; vlanId: number | null };

/** Response of GET /topology — the physical + logical network graph. */
export interface TopologyResponse {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

/** One network layer — a horizontal band of the topology view (GET /layers).
 * Built-ins (core/distribution/access/endpoint) are seeded at boot; custom
 * layers are user-created and deletable when unreferenced. */
export interface NetworkLayer {
  id: string;
  name: string;
  /** Band order — 1 is topmost. */
  sort: number;
  /** Hex accent color (e.g. "#e11d48") used for band headers + device chips. */
  color: string;
  isBuiltin: boolean;
}

export interface LayerCreateRequest {
  name: string;
  color?: string;
}

export interface LayerUpdateRequest {
  name?: string;
  color?: string;
  sort?: number;
}

/** One route entry from the cross-device inventory view. Rows are NOT merged
 * across devices — a route row is one entry on one device. Static and
 * dynamically-learned routes to the same destination appear as separate rows
 * (protocol is part of the identity). */
export interface RouteRow {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the reporting plugin instance (e.g. "OPNsense Plugin"). */
  pluginName?: string | null;
  /** Destination network as CIDR ("10.25.0.0/16", "0.0.0.0/0" for default). */
  destination: string;
  /** Next-hop gateway address or name ('' = directly connected / unknown). */
  gateway?: string;
  protocol: 'static' | 'connected' | 'ospf' | 'bgp' | 'rip' | 'other';
  /** Administrative distance (null when the source doesn't expose it). */
  distance?: number | null;
  /** Route metric / cost (null when n/a). */
  metric?: number | null;
  mtu?: number | null;
  status: 'active' | 'inactive' | 'unknown';
  /** Protocol-specific extras: uuid/description/gatewayStatus/gatewayLatencyMs
   * (OPNsense), rtgTag/peer/rawType (LCOS). */
  extra?: Record<string, unknown>;
  collectedAt: string;
}

/** One structured log entry emitted by a plugin (see GET /logs). */
export interface LogEntry {
  id: string;
  /** Plugin instance id (the sender's effective UUID). */
  pluginId: string;
  /** Display name of the plugin instance. */
  pluginName?: string | null;
  /** Device the entry relates to; null for plugin-level events. */
  deviceId?: string | null;
  deviceName?: string | null;
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  /** Structured details ({endpoint, httpStatus, oid, ...}); null when absent. */
  context?: Record<string, unknown> | null;
  timestamp: string;
}

// --- Notification center ------------------------------------------------------

export type NotificationSeverity = 'info' | 'warning' | 'critical';
export type NotificationSource = 'system' | 'device' | 'plugin';
export type NotificationStatus = 'open' | 'acknowledged' | 'resolved' | 'closed';

/** One notification-center row (see GET /notifications). */
export interface Notification {
  id: string;
  /** Stable identity of an ongoing condition; null for one-shot events. */
  dedupeKey?: string | null;
  severity: NotificationSeverity;
  source: NotificationSource;
  pluginId?: string | null;
  pluginName?: string | null;
  deviceId?: string | null;
  deviceName?: string | null;
  title: string;
  message: string;
  context?: Record<string, unknown> | null;
  createdAt: string;
  lastSeenAt: string;
  occurrences: number;
  status: NotificationStatus;
  acknowledgedBy?: string | null;
  acknowledgedAt?: string | null;
  resolvedAt?: string | null;
}

/** Per-user visibility prefs (source → allowed severities). */
export interface NotificationPrefs {
  userId: string;
  visibility: Record<string, NotificationSeverity[]>;
}

// --- System/HA (Workers page) -------------------------------------------------

/** Runtime state of one worker role on THIS instance (GET /system/status). */
export interface WorkerRuntime {
  name: string;
  /** Advisory-lock key for this role (-1 = not leader-gated; every replica runs it). */
  leaderKey: number;
  isLeader: boolean;
  becameLeaderAt?: string | null;
  beatsCompleted: number;
  lastBeatStartedAt?: string | null;
  lastBeatFinishedAt?: string | null;
  lastBeatDurationMs?: number | null;
  beatErrors: number;
  lastError?: string | null;
}

/** Telemetry poll-cycle counters (cycle guard + durations). */
export interface TelemetryCycleStats {
  cyclesCompleted: number;
  /** Beats skipped because the previous cycle was still running. */
  cyclesSkippedOverlap: number;
  devicesPolledLastCycle: number;
  assignmentsPolledLastCycle: number;
  lastCycleDurationMs?: number | null;
  /** /monitoring calls currently in flight (dispatcher budget gauge). */
  pollsInFlight?: number;
  /** Successful + failed polls completed in the trailing 60 s. */
  pollsPerMinute?: number;
  /** Assignments whose metrics deadline has passed but are waiting for a free slot. */
  overdueWaiting?: number;
  /** Duration of the most recent single /monitoring call (ms). */
  lastPollDurationMs?: number | null;
}

/** Recent leadership/error event (ring buffer, newest first). */
export interface SystemEvent {
  id: number;
  at: string;
  type: 'leadership-acquired' | 'leadership-lost' | 'worker-started' | 'beat-error';
  worker?: string | null;
  message: string;
}

/** One tracked Postgres table (approx rows + total size incl. indexes). */
export interface PostgresTableStat {
  name: string;
  approxRows: number;
  totalSizeBytes: number;
  totalSizePretty: string;
}

/** Read-only Postgres snapshot (version, connections, table sizes). */
export interface PostgresStats {
  version: string;
  databaseName: string;
  databaseSizePretty?: string;
  maxConnections: number;
  connectionsTotal: number;
  connectionsActive: number;
  connectionsIdle: number;
  tables: PostgresTableStat[];
}

/** Full system status payload (GET /system/status). */
export interface SystemStatus {
  instance: { hostname: string; pid: number; uptimeSeconds: number; nodeVersion: string };
  workers: WorkerRuntime[];
  telemetry: TelemetryCycleStats;
  events: SystemEvent[];
  postgres: PostgresStats;
}

/** Admin-tunable worker/HA settings (GET/PUT /system/settings). */
export interface SystemSettings {
  telemetryPollIntervalMs?: number;
  /** Inventory refresh window in ms — how often the slow/static collection runs. */
  telemetryInventoryWindowMs?: number;
  /** Max concurrent /monitoring calls in flight. */
  telemetryMaxConcurrency?: number;
  /** Random spread applied to each rescheduled deadline, percent of the window (0–90). */
  telemetryJitterPercent?: number;
}

export interface SystemSettingsResponse extends SystemSettings {
  limits: {
    MIN_POLL_INTERVAL_MS: number;
    MAX_POLL_INTERVAL_MS: number;
    MIN_INVENTORY_WINDOW_MS: number;
    MAX_INVENTORY_WINDOW_MS: number;
    MIN_CONCURRENCY: number;
    MAX_CONCURRENCY: number;
    MIN_JITTER_PERCENT: number;
    MAX_JITTER_PERCENT: number;
  };
}

/** One distinct (band, channel) pair broadcasting an SSID. */
export interface WifiChannelRef {
  /** '2.4' | '5' | '6'; '' when the device cannot say which band. */
  band: string;
  channel?: number | null;
}

/** One device broadcasting an SSID (one entry per device+plugin instance). */
export interface WifiDeviceRef {
  deviceId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  pluginName?: string | null;
  /** Radio interface(s) broadcasting this SSID (e.g. "WLAN-1"). */
  interfaces: string[];
}

/** One SSID group in the cross-device WiFi overview (grouped by name). */
export interface WifiSsidGroup {
  name: string;
  channels: WifiChannelRef[];
  /** Distinct encryption values across the group; empty when not exposed. */
  security: string[];
  /** VLAN id — only set when unique across ALL rows of this SSID. */
  vlanId?: number | null;
  /** Connected clients currently associated with this SSID (all devices). */
  clientCount: number;
  airtimeMeanPct?: number | null;
  airtimeMaxPct?: number | null;
  devices: WifiDeviceRef[];
}

/** One channel bar in the per-band spectrum view (inSSIDer-style). */
export interface WifiChannelBar {
  channel: number;
  /** Worst-case airtime utilization across all devices on this channel. */
  utilizationPct?: number | null;
}

/** Own SSID marker at its channel position in the spectrum view. */
export interface WifiSsidMarker {
  name: string;
  channel: number;
}

/** Per-band spectrum data (2.4 / 5 / 6 GHz). */
export interface WifiBandView {
  band: '2.4' | '5' | '6';
  minChannel?: number | null;
  maxChannel?: number | null;
  /** Noisiest radio noise floor on this band (dBm) — shaded line under bars. */
  noiseFloorDbm?: number | null;
  channels: WifiChannelBar[];
  markers: WifiSsidMarker[];
}

/** Neighbor network seen by a device's scan engine (own BSSIDs excluded). */
export interface WifiNeighborRef {
  deviceId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  bssid: string;
  ssid?: string | null;
  band: string;
  channel?: number | null;
  signalDbm?: number | null;
}

/** Response of GET /wifi — grouped SSIDs + per-band spectrum + neighbors. */
export interface WifiOverview {
  ssids: WifiSsidGroup[];
  bands: WifiBandView[];
  neighbors: WifiNeighborRef[];
}

// --- Storage (cross-device filesystems + physical disks) -------------------

/** One filesystem/pool/dataset row from GET /storage. */
export interface StorageFilesystemRow {
  deviceId: string;
  pluginId: string;
  name: string;
  /** zfs-pool | zfs-dataset | ext4 | squashfs | usb | other (lowercase). */
  type: string;
  mountpoint?: string | null;
  sizeBytes?: number | null;
  usedBytes?: number | null;
  freeBytes?: number | null;
  /** ONLINE/DEGRADED/OFFLINE (ZFS) or up/down/unknown — lowercase. */
  status: string;
  /** Parent pool name for datasets; null for top-level pools/filesystems. */
  parent?: string | null;
  /** Plugin-specific details (JSON object): ZFS dataset props (quota, used-bytes,
   * compression, mount options), ... — consumed by expandable rows + future
   * config/state endpoints. */
  extra?: Record<string, unknown>;
  collectedAt: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  pluginName?: string | null;
}

/** One physical disk/flash row from GET /storage. */
export interface StorageDiskRow {
  deviceId: string;
  pluginId: string;
  name: string;
  model?: string | null;
  serial?: string | null;
  capacityBytes?: number | null;
  /** hdd | ssd | flash | unknown (lowercase). */
  rotationRate: string;
  /** healthy | degraded | failed | unknown (lowercase). */
  health: string;
  poolName?: string | null;
  collectedAt: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  pluginName?: string | null;
}

/** Response of GET /storage — filesystems (top table) + disks (bottom table). */
export interface StorageOverview {
  filesystems: StorageFilesystemRow[];
  disks: StorageDiskRow[];
}

// --- Containers (cross-device Apps/container workloads) --------------------

/** One docker network as reported in a container row's `extra.networks`. */
export interface ContainerNetwork {
  name: string;
  driver?: string | null;
  subnets?: string[];
}

/** One volume mount as declared in a container's compose config. */
export interface ContainerVolume {
  /** Host path or named volume (the source). */
  source: string;
  /** Path inside the container (the target); omitted when not resolvable. */
  target?: string;
  /** 'ro' | 'rw'. */
  mode?: string;
}

/** Per-service detail for multi-container apps (expandable rows).
 * mac/ip/startedAt are present when the plugin observed them via SSH
 * (`docker inspect`) — the vendor API exposes none of these. `volumes` come
 * from the compose config (app.config) and list this container's mounts. */
export interface ContainerServiceDetail {
  service?: string | null;
  image?: string | null;
  state?: string | null;
  /** Real container MAC (SSH `docker inspect` only). */
  mac?: string | null;
  /** Live IP on the primary network (SSH; falls back to compose static IP). */
  ip?: string | null;
  /** ISO start of the current RUNNING period (SSH only). */
  startedAt?: string | null;
  /** Volume mounts declared for this container (compose config). */
  volumes?: ContainerVolume[];
  // Live stats from `docker stats` over SSH (TrueNAS plugin) — absent until the
  // first enrichment cycle completes. CPU/RAM are instantaneous; the four rate
  // fields are AVERAGE throughput since the previous collection, bytes/s.
  /** Instantaneous CPU utilization in percent. */
  cpuPct?: number | null;
  memUsedBytes?: number | null;
  /** Memory limit in bytes — absent when the container has no limit. */
  memLimitBytes?: number | null;
  netRxRate?: number | null;
  netTxRate?: number | null;
  blkReadRate?: number | null;
  blkWriteRate?: number | null;
}

/** One App/container row from GET /containers. */
export interface ContainerRow {
  deviceId: string;
  pluginId: string;
  name: string;
  /** RUNNING | STOPPED | ... (uppercase). */
  state: string;
  image?: string | null;
  version?: string | null;
  upgradeAvailable?: boolean | null;
  /** Start of the current RUNNING period (ISO-8601). Real container start when
   * the plugin observed it via SSH (`docker inspect`); otherwise UNM-tracked from
   * state transitions — a lower bound that resets after restarts. Null for
   * non-RUNNING rows or apps observed already-running (UI shows "≥ X"). */
  startedAt?: string | null;
  /** Plugin-specific details (JSON): networks[], ips[], ports[], containerCount,
   * containers[] per-service detail, volumeMounts[]. */
  extra?: Record<string, unknown>;
  collectedAt: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  pluginName?: string | null;
}

/** One docker image row from GET /containers (the `images` panel). */
export interface DockerImageRow {
  deviceId: string;
  pluginId: string;
  /** Full image reference (e.g. "nginx:1.27-alpine", "ghcr.io/x/y@sha256:..."). */
  name: string;
  sizeBytes?: number | null;
  /** ISO-8601 creation timestamp of the image. */
  createdAt?: string | null;
  /** True when a newer version is available (TrueNAS only; null elsewhere). */
  updateAvailable?: boolean | null;
  /** Dangling image (<none>:<none> / unreferenced layers). */
  dangling: boolean;
  extra?: Record<string, unknown>;
  collectedAt: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  pluginName?: string | null;
}

/** Response of GET /containers — apps/containers (top table) + images (bottom panel). */
export interface ContainersOverview {
  containers: ContainerRow[];
  images: DockerImageRow[];
}

/** One device attached to a VM — NIC, disk, display, CD-ROM, PCIe passthrough…
 * (from the plugin's `vms` metric, extra.devices[]). Generic across hypervisor
 * plugins: `dtype` is the appliance-native type; `label`/`detail` are pre-formatted. */
export interface VmDevice {
  /** Appliance-native device type (NIC | DISK | DISPLAY | CDROM | PCI | …). */
  dtype: string;
  /** Primary display value (MAC, disk path, "Display (SPICE)", …). */
  label?: string;
  /** Secondary detail (model → bridge, controller type, resolution:port, …). */
  detail?: string;
}

/** @deprecated legacy shape — replaced by VmDevice[] in extra.devices. Kept so
 * older plugin versions' rows still parse (extra.nics) without breaking the UI. */
export interface VmNic {
  mac?: string;
  type?: string;
  nicAttach?: string;
}

/** One VM row from GET /vms. */
export interface VmRow {
  deviceId: string;
  pluginId: string;
  name: string;
  /** RUNNING | STOPPED | SUSPENDED | ... (uppercase). */
  state: string;
  vcpus?: number | null;
  /** Memory allocated in MiB. */
  memoryMiB?: number | null;
  /** Guest architecture / machine type when reported. */
  archType?: string | null;
  /** Start of the current RUNNING period (ISO-8601) — UNM-tracked from state
   * transitions, a lower bound that resets after restarts. Null for non-RUNNING rows. */
  startedAt?: string | null;
  /** Plugin-specific details (JSON): devices[] VmDevice (every attached device —
   * NICs, disks, displays, CD-ROMs, PCIe…), description, uuid, autostart. */
  extra?: Record<string, unknown>;
  collectedAt: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  pluginName?: string | null;
}

/** Response of GET /vms — one row per VM on one device (no cross-device merge). */
export interface VmsOverview {
  vms: VmRow[];
}

/** A user account (never includes password hashes or TOTP secrets). */
export interface User {
  id: string;
  username: string;
  roles: string[];
  /** Explicit permission grants only (role-derived ones are added at login). */
  permissions: string[];
  /** True when ANY second factor is enrolled (TOTP or ≥1 passkey). */
  twoFactorEnabled: boolean;
  totpEnabled?: boolean;
  passkeyCount?: number;
  createdAt?: string;
}

/** Credential policy — which 2nd factors are required at login and which AMRs satisfy the privileged-action gate. */
export interface CredentialPolicy {
  /** Enrolled methods that satisfy login step 2 (empty = no 2FA). */
  requiredMethods: ('totp' | 'webauthn')[];
  /** Session AMRs that satisfy require2FA (config-job submission etc.). */
  gateAmrs: string[];
}

export interface PolicyWithSource {
  policy: CredentialPolicy;
  /** Where the effective policy comes from. */
  source: 'user' | 'global' | 'default';
}

/** TOTP enrollment payload returned by user-create / totp-enroll. */
export interface TotpEnrollment {
  /** Base32 TOTP secret (shown as text + QR code). */
  secret: string;
  /** otpauth:// URI for authenticator-app setup. */
  otpauthUri: string;
}

/** A named bundle of permissions (roles are expanded at login time). */
export interface Role {
  name: string;
  description?: string | null;
  permissions: string[];
  createdAt?: string;
}

export interface PermissionCatalog {
  permissions: { id: string; description: string }[];
  roles: { name: string; description?: string | null; permissions: string[] }[];
}

export interface DeviceCreateRequest {
  name: string;
  vendor: string;
  /** All roles this device fulfills, e.g. ["router", "firewall"] (required). */
  deviceTypes: string[];
  /** Free-form user tags for filtering / plan targeting (optional). */
  tags?: string[];
  /** Primary address — IPv4, IPv6 literal, or DNS name (no scheme). */
  managementAddress: string;
  /** Optional assigned site. */
  siteId?: string | null;
  /** Optional secondary IPs registered at creation time. */
  ips?: string[];
  /** At least one plugin assignment; the first becomes primary. */
  plugins: DevicePluginAssignmentInput[];
  /** Optional hardware model (from a plugin's advertised catalog). */
  model?: string | null;
  /** Optional firmware version for the selected model. */
  firmwareVersion?: string | null;
  /** Manual topology-layer override (a network_layers id); null/omitted = auto-classify. */
  layerOverride?: string | null;
  /** Per-device metrics poll window in ms; null/omitted = inherit plugin/system default. */
  pollIntervalMs?: number | null;
  /** Telemetry polling toggle (default true); disabled devices keep their history. */
  enabled?: boolean;
}

export interface Device {
  id: string;
  name: string;
  vendor: string;
  /** Legacy single type (first of `deviceTypes`) — kept for old clients. */
  deviceType?: string | null;
  /** All roles this device fulfills, e.g. ["router", "firewall"]. */
  deviceTypes: string[];
  /** Free-form user tags for filtering / plan targeting. */
  tags: string[];
  managementAddress: string;
  siteId?: string | null;
  /** Display name of the assigned site (null = unassigned). */
  siteName?: string | null;
  status: string;
  /** All addresses, primary first (list endpoints include this). */
  ips?: DeviceAddress[];
  /** Assigned plugins (list endpoints include this). */
  plugins?: DevicePluginAssignment[];
  /** Headline metrics (marked `summary` by the plugin) for inline table display. */
  summaryMetrics?: SummaryMetric[];
  /** Hardware model selected from a plugin's advertised catalog (null = unset). */
  model?: string | null;
  /** Firmware version for the selected model (null = unset). */
  firmwareVersion?: string | null;
  /** Manual topology-layer override (a network_layers id); null = auto-classify. */
  layerOverride?: string | null;
  /** Per-device metrics poll window in ms (null = inherit plugin/system default). */
  pollIntervalMs?: number | null;
  /** Firmware version detected by the plugins' latest telemetry (list endpoints only; null = not reported). */
  detectedFirmwareVersion?: string | null;
  /** Serial number from the plugins' latest telemetry (list endpoints only; null = not reported). */
  serialNumber?: string | null;
  /** Telemetry polling toggle — disabled devices are not polled; their historical
   * data and last metrics stay preserved. Defaults to true when absent. */
  enabled?: boolean;
}

/** Per-device outcome of a forced refresh (POST /devices/refresh). */
export interface DeviceRefreshResult {
  deviceId: string;
  /** Device display name (empty for unknown ids). */
  name: string;
  /** True when at least one assignment was polled successfully. */
  ok: boolean;
  /** Number of plugin assignments re-polled (0 = none possible). */
  assignmentsPolled: number;
  results: { pluginId: string; health: string; reachable: boolean; error?: string }[];
  /** Device-level problem (unknown device / polling disabled) — no polls ran. */
  error?: string;
}

/** One supported device model as advertised by a plugin in /discover.
 * Drives the Model + Firmware dropdowns in the device create/edit form. */
export interface DeviceModelEntry {
  /** Vendor this entry applies to (matches one of the plugin's `vendors`). */
  vendor: string;
  /** Display name of the hardware model, e.g. "LX45". */
  model: string;
  /** Optional icon path relative to the plugin root (served via the API icon proxy). */
  iconPath?: string;
  /** Optional list of firmware versions for this model (plain strings). */
  firmwareVersions?: string[];
  /** Suggested topology layer for devices of this model (a network_layers id). */
  defaultLayerId?: string;
}

/** Builds the URL of a plugin's icon through the API proxy.
 * `path` overrides the plugin's default iconUrl (used for per-model icons). */
export function pluginIconUrl(pluginId: string, path?: string | null): string {
  const p = path ? encodeURIComponent(path) : '';
  return `${BASE}/plugins/${encodeURIComponent(pluginId)}/icon${p ? `?path=${p}` : ''}`;
}

/** One plugin's monitoring snapshot for a device. */
export interface PluginTelemetrySnapshot {
  pluginId: string;
  collectedAt?: string | null;
  health: string;
  metrics: Record<string, unknown>;
  metricDescriptors?: MetricDescriptor[];
}

/** GET /devices/:id/monitoring — one snapshot per assigned plugin. */
export interface DeviceMonitoring {
  deviceId: string;
  /** Overall device health = worst-wins across all assignments. */
  health: string;
  snapshots: PluginTelemetrySnapshot[];
}

export interface Plugin {
  id: string;
  name: string;
  version: string;
  vendors: string[];
  capabilities: string[];
  endpoint: string;
  authType: string;
  /** Icon path relative to the plugin root (null = no icon advertised). */
  iconUrl?: string | null;
  /** Supported device model catalog (null/absent = no catalog, e.g. ICMP). */
  deviceModels?: DeviceModelEntry[] | null;
  /** Additional named credential slots beyond the primary secret (null = none). */
  credentialSlots?: CredentialSlotDescriptor[] | null;
  /** Number of metric descriptors declared in /discover (how many metrics it can emit); null when unknown. */
  declaredMetricCount?: number | null;
  lastSeenAt?: string | null;
}

/** One self-metrics sample of a plugin process (GET /plugins/:id/self-metrics). */
export interface PluginSelfMetricsSample {
  id: string;
  pluginId: string;
  uptimeSeconds: number | null;
  heapUsedBytes: number | null;
  heapTotalBytes: number | null;
  rssBytes: number | null;
  /** % of one core (can exceed 100 on multi-core hosts). */
  cpuPercent: number | null;
  eventLoopLagMs: number | null;
  inFlight: number | null;
  lastPollMs: number | null;
  errorRatePercent: number | null;
  emittedMetricsCount: number | null;
  logQueueDepth: number | null;
  timestamp: string;
}

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
  /** Column field names for `table` visualizations (see MetricView). */
  columns?: string[];
  summary?: boolean;
  intervalMs?: number;
}

/** A headline metric shown inline in the device overview table. */
export interface SummaryMetric {
  key: string;
  label: string;
  value: unknown;
  unit?: string;
  format?: 'bytes' | 'bits' | 'duration' | 'number' | 'text';
  visualization: 'gauge' | 'plot' | 'text' | 'table';
  min?: number;
  max?: number;
  color?: string;
}

export interface PluginMetrics {
  pluginId: string;
  metrics: MetricDescriptor[];
}

/** A single option a plugin declares in its /discover response. */
export interface PluginOptionBase {
  key: string;
  label: string;
  type: 'string' | 'integer' | 'boolean';
  default?: unknown;
  description?: string;
  docsUrl?: string;
}

export interface StringOption extends PluginOptionBase {
  type: 'string';
  pattern?: string;
  minLength?: number;
  maxLength?: number;
}

export interface IntegerOption extends PluginOptionBase {
  type: 'integer';
  min?: number;
  max?: number;
}

export interface BooleanOption extends PluginOptionBase {
  type: 'boolean';
}

export type PluginOptionDescriptor = StringOption | IntegerOption | BooleanOption;

/** GET /plugins/:id/options response. */
export interface PluginOptionsResponse {
  pluginId: string;
  options: PluginOptionDescriptor[];
  /** Stored overrides only (key -> value). Empty when nothing was set. */
  values: Record<string, unknown>;
  /** Defaults merged with stored overrides — what the form should initialize to. */
  effectiveValues: Record<string, unknown>;
}

/** Per-field validation errors returned by PUT /plugins/:id/settings on failure. */
export interface PluginSettingsError {
  error: string;
  fieldErrors?: Record<string, string>;
}

export interface ConfigJob {
  id: string;
  deviceId: string;
  /** The assignment that executes this job. */
  pluginId?: string;
  action: string;
  status: string;
  result?: Record<string, unknown>;
  createdAt: string;
  finishedAt?: string;
}

// --- Execution plans ---------------------------------------------------------

/** One property of an action's input schema (JSON-Schema subset from the plugin). */
export interface InputSchemaProperty {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  label?: string;
  description?: string;
  required?: boolean;
  default?: unknown;
  pattern?: string;
  min?: number;
  max?: number;
  enum?: (string | number)[];
  items?: InputSchemaProperty;
  properties?: Record<string, InputSchemaProperty>;
}

/** A map of property name → schema (the catalog's `inputSchema`). */
export type InputSchema = Record<string, InputSchemaProperty>;

/** One entry of a plugin's action catalog (from /discover `actions`). */
export interface CatalogEntry {
  id: string;
  label: string;
  description?: string;
  module?: string;
  riskLevel?: 'read' | 'write' | 'dangerous';
  /** Exact device count for multi-device intents, or 'N' for fan-out. */
  deviceCount?: number | 'N';
  beOnly?: boolean;
  timeoutMs?: number;
  inputSchema?: InputSchema;
}

// ---------------------------------------------------------------------------
// Device state (per-device Config page) — mirrored from @unm/plugin-sdk.
// The API brokers the plugin's GET /state document verbatim; actions reference
// catalog ids and are executed through the plan workflow.
// ---------------------------------------------------------------------------

/** A reference to an executable action of a plugin's catalog. */
export interface StateActionRef {
  actionId: string;
  /** Pre-filled input values merged under the schema defaults. */
  prefill?: Record<string, unknown>;
}

/** One row of a state section — e.g. a switch port or an appliance interface. */
export interface StateItem {
  key: string;
  title: string;
  subtitle?: string | null;
  /** up | down | enabled | disabled | ok | degraded | critical (free string). */
  status?: string | null;
  /** Label-ready values; arrays render as chip lists (e.g. per-port MACs). */
  fields: Record<string, string | number | null | unknown[]>;
  actions?: StateActionRef[];
}

/** One band of ports on a virtual switch face — e.g. one physical row, or an SFP+/PoE section. */
export interface SwitchPortGroup {
  id: string;
  /** Band header rendered above the ports (e.g. 'RJ45', 'SFP+'); null/omitted = unlabeled band. */
  label?: string | null;
  /** Item keys in panel order (left → right). Keys must match StateItem.key of this section's items. */
  portKeys: string[];
}

/** Plugin-propagated switch-face layout for a `kind: 'switch'` state section.
 *  When absent the webapp falls back to a generic layout (balanced rows, no labels). */
export interface SwitchLayout {
  /** Bands top → bottom. Items not referenced by any band are appended after all bands. */
  groups: SwitchPortGroup[];
}

/** A horizontal band of the Config page — e.g. Ports, Interfaces, Pools, System. */
export interface StateSection {
  id: string;
  label: string;
  description?: string | null;
  /** Rendering hint: 'table' (default) renders the item table; 'switch' renders a virtual switch face with per-port selection for bulk actions. */
  kind?: 'table' | 'switch';
  /** Switch-face layout (only meaningful when kind === 'switch'). */
  layout?: SwitchLayout | null;
  items?: StateItem[];
  /** Section-level actions with no item context (e.g. reboot system). */
  actions?: StateActionRef[];
}

/** The dynamic device-state document a plugin serves from GET /state. */
export interface DeviceStateResponse {
  collectedAt: string;
  sections: StateSection[];
}

/** GET /devices/:id/state response — the broker wraps the state with ids. */
export interface DeviceState {
  deviceId: string;
  pluginId: string;
  state: DeviceStateResponse;
}

/** The live probe snapshot a plugin serves from POST /probe (capability 'probe').
 * `metrics` is a free-form map keyed by probe key — the shape is plugin-owned. */
export interface ProbeResult {
  collectedAt: string;
  metrics: Record<string, unknown>;
}

/** GET /devices/:id/probe response — the broker wraps the snapshot with ids. */
export interface DeviceProbe {
  deviceId: string;
  pluginId: string;
  probe: ProbeResult;
}

/** One normalized port row (device_ports table). */
export interface DevicePortRow {
  pluginId: string;
  name: string;
  status: string;
  speed?: string | null;
  duplex?: string | null;
  vlanId?: number | null;
  poe?: string | null;
  extra?: Record<string, unknown>;
  collectedAt: string;
}

/** A provisioned secret attached to a plan (metadata only — never material). */
export interface PlanProvisionedSecret {
  ref: string;
  secretId: string;
  label?: string | null;
  type?: string;
}

/** One executable step of a plan. */
export interface PlanStep {
  id: string;
  planId: string;
  /** Final ordering; doubles as topological order. */
  stepIndex: number;
  deviceId: string;
  actionId: string;
  input: Record<string, unknown>;
  dependsOn?: number[];
  secretRefs?: string[];
  bestEffort?: boolean;
  status: 'pending' | 'running' | 'succeeded' | 'failed' | 'skipped';
  result?: Record<string, unknown> | null;
  startedAt?: string | null;
  finishedAt?: string | null;
}

/** A persisted execution plan (list shape; detail adds `steps`). */
export interface Plan {
  id: string;
  pluginId: string;
  intentActionId: string;
  status: 'draft' | 'ready' | 'executing' | 'succeeded' | 'failed' | 'cancelled';
  provisionedSecrets: PlanProvisionedSecret[];
  error?: string | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  finishedAt?: string | null;
  /** Last terminal-status timestamp (cleared on re-execution) — drives the top-bar plans icon tick. */
  recentlyFinishedAt?: string | null;
  /** Present on list responses. */
  stepCount?: number;
  stepsDone?: number;
}

/** GET /plans/:id response — plan + ordered steps. */
export interface PlanDetail extends Plan {
  steps: PlanStep[];
}

function getToken(): string | null {
  return localStorage.getItem('accessToken');
}

async function apiFetch<T>(path: string, opts?: RequestInit): Promise<T> {
  const token = getToken();
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {}),
      ...opts?.headers,
    },
  });
  if (!res.ok) {
    let message = `API error ${res.status}`;
    let fieldErrors: Record<string, string> | undefined;
    let code: string | undefined;
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
      if (body?.fieldErrors && typeof body.fieldErrors === 'object') fieldErrors = body.fieldErrors;
      if (typeof body?.code === 'string') code = body.code;
    } catch {
      // ignore body parse errors, fall back to generic message
    }
    throw new ApiError(message, res.status, fieldErrors, code);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json();
}

export const api = {
  authFlow: () => apiFetch<AuthFlow>('/auth/flow'),
  authRedirect: () => apiFetch<AuthRedirect>('/auth/redirect'),
  login: (body: { username: string; password: string }) =>
    apiFetch<LoginResponse>('/auth/login', { method: 'POST', body: JSON.stringify(body) }),
  verify2fa: (body: { challengeToken: string; totpCode: string }) =>
    apiFetch<VerifyResponse>('/auth/2fa/verify', { method: 'POST', body: JSON.stringify(body) }),
  // Passkey (WebAuthn) step-2 — same session shape as verify2fa.
  webauthnAssertionOptions: (challengeToken: string) =>
    apiFetch<WebauthnAssertionOptions>(`/auth/webauthn/assertion-options?challengeToken=${encodeURIComponent(challengeToken)}`),
  verifyWebauthn: (body: { challengeToken: string; response: unknown; nonce: string }) =>
    apiFetch<VerifyResponse>('/auth/webauthn/verify', { method: 'POST', body: JSON.stringify(body) }),
  /** The caller's own profile (no users:read needed). */
  me: () => apiFetch<User & { effectivePermissions: string[] }>('/auth/me'),
  devices: () => apiFetch<Device[]>('/devices'),
  createDevice: (body: DeviceCreateRequest) =>
    apiFetch<Device & { plugins?: DevicePluginAssignment[] }>('/devices', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  /** Update identity fields of an existing device (plugins are managed separately). */
  updateDevice: (deviceId: string, body: Partial<Pick<Device, 'name' | 'vendor' | 'deviceTypes' | 'tags' | 'managementAddress' | 'model' | 'firmwareVersion' | 'layerOverride' | 'pollIntervalMs'>> & { siteId?: string | null; enabled?: boolean }) =>
    apiFetch<Device>(`/devices/${deviceId}`, { method: 'PATCH', body: JSON.stringify(body) }),
  /** Clone a device — all settings (plugins + credentials, IPs, per-device
   * overrides) are reused; the clone gets a fresh id and "(copy)" name. */
  cloneDevice: (deviceId: string) =>
    apiFetch<Device & { plugins?: DevicePluginAssignment[] }>(`/devices/${deviceId}/clone`, { method: 'POST' }),
  // Device ↔ plugin assignments.
  devicePlugins: (deviceId: string) =>
    apiFetch<{ deviceId: string; plugins: DevicePluginAssignment[] }>(`/devices/${deviceId}/plugins`),
  addDevicePlugin: (deviceId: string, body: DevicePluginAssignmentInput) =>
    apiFetch<DevicePluginAssignment>(`/devices/${deviceId}/plugins`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  removeDevicePlugin: (deviceId: string, pluginId: string) =>
    apiFetch<void>(`/devices/${deviceId}/plugins/${pluginId}`, { method: 'DELETE' }),
  /** Promote an assigned plugin to primary (demotes the current one). */
  setPrimaryPlugin: (deviceId: string, pluginId: string) =>
    apiFetch<DevicePluginAssignment>(`/devices/${deviceId}/plugins/${pluginId}`, { method: 'PATCH' }),
  /** Update an existing assignment's credentials, slot bindings and/or primary flag. */
  updateDevicePlugin: (deviceId: string, pluginId: string, body: { secretId?: string | null; isPrimary?: boolean; extraCredentials?: Record<string, string | null> }) =>
    apiFetch<DevicePluginAssignment>(`/devices/${deviceId}/plugins/${pluginId}`, { method: 'PATCH', body: JSON.stringify(body) }),
  // Device IP addresses (primary = managementAddress; secondaries managed here).
  deviceIps: (deviceId: string) =>
    apiFetch<{ deviceId: string; ips: DeviceAddress[] }>(`/devices/${deviceId}/ips`),
  addDeviceIp: (deviceId: string, address: string) =>
    apiFetch<DeviceIpRow>(`/devices/${deviceId}/ips`, { method: 'POST', body: JSON.stringify({ address }) }),
  removeDeviceIp: (deviceId: string, ipId: string) =>
    apiFetch<void>(`/devices/${deviceId}/ips/${ipId}`, { method: 'DELETE' }),
  /** Delete a device and everything that hangs off it. 409 while plans reference it. */
  deleteDevice: (deviceId: string) =>
    apiFetch<void>(`/devices/${deviceId}`, { method: 'DELETE' }),
  /** Toggle telemetry polling for one or more devices (bulk = sequential PATCHes). */
  setDevicesEnabled: async (deviceIds: string[], enabled: boolean): Promise<{ total: number; errors: string[] }> => {
    const errors: string[] = [];
    for (const id of deviceIds) {
      try {
        await api.updateDevice(id, { enabled });
      } catch (err) {
        errors.push(`${id}: ${(err as Error).message}`);
      }
    }
    return { total: deviceIds.length, errors };
  },
  /** Force an immediate re-poll of one or more devices — bypasses the
   * staggered windows and refreshes BOTH live metrics and inventory now.
   * Requires devices:write. Returns per-device outcomes (reachability +
   * transport errors) for diagnostics. */
  refreshDevices: (deviceIds: string[]) =>
    apiFetch<{ results: DeviceRefreshResult[] }>('/devices/refresh', {
      method: 'POST',
      body: JSON.stringify({ deviceIds }),
    }),
  // Per-device settings overrides (inherit global → override per device).
  devicePluginOptions: (deviceId: string, pluginId: string) =>
    apiFetch<PluginOptionsResponse>(`/devices/${deviceId}/plugins/${pluginId}/options`),
  saveDevicePluginSettings: (deviceId: string, pluginId: string, settings: Record<string, unknown>) =>
    apiFetch<PluginOptionsResponse>(`/devices/${deviceId}/plugins/${pluginId}/settings`, {
      method: 'PUT',
      body: JSON.stringify({ settings }),
    }),
  resetDevicePluginSettings: (deviceId: string, pluginId: string) =>
    apiFetch<PluginOptionsResponse>(`/devices/${deviceId}/plugins/${pluginId}/settings`, { method: 'DELETE' }),
  monitoring: (deviceId: string) => apiFetch<DeviceMonitoring>(`/devices/${deviceId}/monitoring`),
  // Live device state from one assigned plugin's GET /state endpoint.
  deviceState: (deviceId: string, pluginId?: string) =>
    apiFetch<DeviceState>(`/devices/${deviceId}/state${pluginId ? `?pluginId=${encodeURIComponent(pluginId)}` : ''}`),
  // LIVE short-cycle telemetry from one assigned plugin's POST /probe endpoint
  // (capability 'probe'). The webapp polls this on demand (1–5 s) for data too
  // slow/heavy for the background worker. `keys` selects which probe keys to
  // collect; absent = the plugin's default set. `names` optionally restricts
  // state-style keys to a subset of containers (absent = full collection).
  deviceProbe: (deviceId: string, keys?: string[], pluginId?: string, names?: string[]) => {
    const params = new URLSearchParams();
    // Comma-joined list — URLSearchParams percent-encodes the comma, which the
    // API's OpenAPI validator requires (raw reserved chars in query values 400).
    if (keys && keys.length > 0) params.set('keys', keys.join(','));
    if (pluginId) params.set('pluginId', pluginId);
    if (names && names.length > 0) params.set('names', names.join(','));
    const qs = params.toString();
    return apiFetch<DeviceProbe>(`/devices/${deviceId}/probe${qs ? `?${qs}` : ''}`);
  },
  // Normalized port inventory for a device across all plugins.
  devicePorts: (deviceId: string) =>
    apiFetch<{ deviceId: string; ports: DevicePortRow[] }>(`/devices/${deviceId}/ports`),
  deviceTelemetry: (deviceId: string, limit = 30) =>
    apiFetch<{ deviceId: string; history: { collectedAt: string; health: string; pluginId?: string; metrics: Record<string, unknown> }[] }>(
      `/devices/${deviceId}/telemetry?limit=${limit}`
    ),
  plugins: () => apiFetch<Plugin[]>('/plugins'),
  configJobs: (deviceId: string, body: unknown) =>
    apiFetch<ConfigJob>(`/devices/${deviceId}/config-jobs`, { method: 'POST', body: JSON.stringify(body) }),
  allConfigJobs: () => apiFetch<ConfigJob[]>('/config-jobs'),
  getConfigJob: (jobId: string) => apiFetch<ConfigJob>(`/config-jobs/${jobId}`),
  secrets: () => apiFetch<Secret[]>('/secrets'),
  secretProviders: () => apiFetch<SecretProvider[]>('/secrets/providers'),
  createSecret: (body: {
    type: string;
    providerId?: string;
    fields: Record<string, string>;
    label: string;
    expiresAt?: string;
  }) => apiFetch<Secret>('/secrets', { method: 'POST', body: JSON.stringify(body) }),
  /** Provider creates the key material itself (generatable types only). `fields` carries non-material context.
   *  Response may include `publicFields` = non-secret generated values to show the user (e.g. public key line). */
  generateSecret: (body: {
    type: string;
    providerId?: string;
    fields?: Record<string, string>;
    label?: string;
    expiresAt?: string;
  }) => apiFetch<{ id: string; createdAt?: string; type?: string; publicFields?: Record<string, string> }>('/secrets/generate', { method: 'POST', body: JSON.stringify(body) }),
  /** Re-roll a generatable secret's key material in place — same id, references keep working. */
  regenerateSecret: (id: string) =>
    apiFetch<Secret>(`/secrets/${id}/regenerate`, { method: 'POST' }),
  /** Fetch a secret's decrypted fields for editing (works for all types). */
  getSecret: (id: string) =>
    apiFetch<{ type: string; fields: Record<string, string> }>(`/secrets/${id}`),
  /** Update a secret's fields in place — same id, references keep working. All types supported. */
  updateSecret: (id: string, body: { fields: Record<string, string>; label?: string; expiresAt?: string | null }) =>
    apiFetch<{ id: string }>(`/secrets/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteSecret: (id: string) =>
    apiFetch<void>(`/secrets/${id}`, { method: 'DELETE' }),
  // Sites.
  sites: () => apiFetch<Site[]>('/sites'),
  createSite: (body: SiteCreateRequest) =>
    apiFetch<Site>('/sites', { method: 'POST', body: JSON.stringify(body) }),
  updateSite: (id: string, body: Partial<SiteCreateRequest>) =>
    apiFetch<Site>(`/sites/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteSite: (id: string) => apiFetch<void>(`/sites/${id}`, { method: 'DELETE' }),
  // Network layer registry (topology bands). Read is open; write needs layers:write.
  layers: () => apiFetch<NetworkLayer[]>('/layers'),
  createLayer: (body: LayerCreateRequest) =>
    apiFetch<NetworkLayer>('/layers', { method: 'POST', body: JSON.stringify(body) }),
  updateLayer: (id: string, body: LayerUpdateRequest) =>
    apiFetch<NetworkLayer>(`/layers/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteLayer: (id: string) => apiFetch<void>(`/layers/${id}`, { method: 'DELETE' }),
  // Cross-device inventory views (Networks + Hosts pages).
  networks: (params?: { deviceId?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<NetworkRow[]>(`/networks${suffix}`);
  },
  hosts: (params?: { deviceId?: string; siteId?: string; source?: 'arp' | 'ndp' | 'dhcp' | 'wlan' }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.source) qs.set('source', params.source);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<HostRow[]>(`/hosts${suffix}`);
  },
  tunnels: (params?: { deviceId?: string; siteId?: string; type?: 'wireguard' | 'openvpn' | 'ipsec' | 'pppoe' | 'gre' }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.type) qs.set('type', params.type);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<TunnelRow[]>(`/tunnels${suffix}`);
  },
  firewallRules: (params?: { deviceId?: string; siteId?: string; ruleType?: 'filter' | 'dnat' | 'snat' | 'one-to-one' | 'npt' }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.ruleType) qs.set('ruleType', params.ruleType);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<FirewallRuleRow[]>(`/firewall-rules${suffix}`);
  },
  routes: (params?: { deviceId?: string; siteId?: string; protocol?: 'static' | 'connected' | 'ospf' | 'bgp' | 'rip' | 'other' }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.protocol) qs.set('protocol', params.protocol);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<RouteRow[]>(`/routes${suffix}`);
  },
  wifi: (params?: { siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<WifiOverview>(`/wifi${suffix}`);
  },
  storage: (params?: { deviceId?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<StorageOverview>(`/storage${suffix}`);
  },
  containers: (params?: { deviceId?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<ContainersOverview>(`/containers${suffix}`);
  },
  vms: (params?: { deviceId?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<VmsOverview>(`/vms${suffix}`);
  },
  /** Physical + logical topology graph for the Topology page. */
  topology: (params?: { siteId?: string; includeHosts?: boolean }) => {
    const qs = new URLSearchParams();
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.includeHosts) qs.set('includeHosts', 'true');
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<TopologyResponse>(`/topology${suffix}`);
  },
  // Plugin log entries (global Logs page + per-device section in DeviceDetail).
  logs: (params?: {
    deviceId?: string;
    pluginId?: string;
    level?: 'debug' | 'info' | 'warn' | 'error';
    search?: string;
    from?: string;
    to?: string;
    limit?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.pluginId) qs.set('pluginId', params.pluginId);
    if (params?.level) qs.set('level', params.level);
    if (params?.search) qs.set('search', params.search);
    if (params?.from) qs.set('from', params.from);
    if (params?.to) qs.set('to', params.to);
    if (params?.limit) qs.set('limit', String(params.limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<LogEntry[]>(`/logs${suffix}`);
  },
  // Notification center (bell badge + panel + full page with filters).
  notifications: (params?: {
    status?: string;
    severity?: string;
    source?: string;
    deviceId?: string;
    pluginId?: string;
    search?: string;
    /** true = ignore personal visibility prefs (full history view). */
    all?: boolean;
    limit?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.status) qs.set('status', params.status);
    if (params?.severity) qs.set('severity', params.severity);
    if (params?.source) qs.set('source', params.source);
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.pluginId) qs.set('pluginId', params.pluginId);
    if (params?.search) qs.set('search', params.search);
    if (params?.all) qs.set('all', 'true');
    if (params?.limit) qs.set('limit', String(params.limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<Notification[]>(`/notifications${suffix}`);
  },
  notificationCount: () => apiFetch<{ count: number }>('/notifications/count'),
  acknowledgeNotifications: (ids?: string[], all?: boolean) =>
    apiFetch<{ acknowledged: number }>(
      '/notifications/ack',
      { method: 'POST', body: JSON.stringify(all ? { all: true } : { ids }) }
    ),
  /** Close rows locally; with `propagate`, mirrored appliance alerts (e.g. TrueNAS) are also dismissed on the box. */
  closeNotifications: (ids: string[], propagate = false) =>
    apiFetch<{ closed: number }>('/notifications/close', { method: 'POST', body: JSON.stringify({ ids, propagate }) }),
  resolveNotification: (id: string) => apiFetch<{ ok: boolean }>(`/notifications/${id}`, { method: 'DELETE' }),
  /** Bulk "condition fixed" — same transition as resolveNotification, for many rows at once. */
  resolveNotifications: (ids: string[]) =>
    apiFetch<{ resolved: number }>('/notifications/resolve', { method: 'POST', body: JSON.stringify({ ids }) }),
  notificationPrefs: () => apiFetch<NotificationPrefs>('/notifications/prefs'),
  setNotificationPrefs: (visibility: Record<string, NotificationSeverity[]>) =>
    apiFetch<NotificationPrefs>('/notifications/prefs', { method: 'PUT', body: JSON.stringify({ visibility }) }),
  // Runtime self-metrics of a plugin process (CPU/memory/lag/poll stats).
  pluginSelfMetrics: (pluginId: string, limit = 120) =>
    apiFetch<{ pluginId: string; latest: PluginSelfMetricsSample | null; history: PluginSelfMetricsSample[] }>(
      `/plugins/${pluginId}/self-metrics?limit=${limit}`
    ),
  // Users + permission catalog.
  users: () => apiFetch<User[]>('/users'),
  createUser: (body: { username: string; password: string; roles?: string[]; permissions?: string[] }) =>
    apiFetch<{ user: User; enrollment: TotpEnrollment }>('/users', { method: 'POST', body: JSON.stringify(body) }),
  updateUser: (id: string, body: { roles?: string[]; permissions?: string[] }) =>
    apiFetch<User>(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteUser: (id: string) => apiFetch<void>(`/users/${id}`, { method: 'DELETE' }),
  // Credential management (self needs users:self-credentials, others need users:manage-credentials).
  resetUserPassword: (id: string, body: { newPassword: string; currentPassword?: string }) =>
    apiFetch<User>(`/users/${id}/password`, { method: 'POST', body: JSON.stringify(body) }),
  enrollTotp: (id: string) =>
    apiFetch<{ user: User; enrollment: TotpEnrollment }>(`/users/${id}/totp/enroll`, { method: 'POST' }),
  disableTotp: (id: string) => apiFetch<void>(`/users/${id}/totp`, { method: 'DELETE' }),
  // Passkeys (multiple per user — one row per device).
  passkeys: (userId: string) => apiFetch<PasskeyCredential[]>(`/users/${userId}/passkeys`),
  /** Step 1 of enrollment: fetch registration options for navigator.credentials.create(). */
  startPasskeyEnrollment: (userId: string, body?: { label?: string }) =>
    apiFetch<WebauthnRegistrationOptions>(`/users/${userId}/passkeys`, {
      method: 'POST',
      body: JSON.stringify(body ?? {}),
    }),
  /** Step 2 of enrollment: verify the attestation and store the credential. */
  completePasskeyEnrollment: (userId: string, body: { nonce: string; response: unknown; label?: string }) =>
    apiFetch<{ credential: PasskeyCredential }>(`/users/${userId}/passkeys/verify`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  deletePasskey: (userId: string, credentialId: string) =>
    apiFetch<void>(`/users/${userId}/passkeys/${encodeURIComponent(credentialId)}`, { method: 'DELETE' }),
  // Credential policies (global default + per-user overrides; user wins).
  globalCredentialPolicy: () => apiFetch<{ policy: CredentialPolicy }>('/auth/policies/global'),
  setGlobalCredentialPolicy: (body: Partial<CredentialPolicy>) =>
    apiFetch<{ policy: CredentialPolicy }>('/auth/policies/global', { method: 'PUT', body: JSON.stringify(body) }),
  userCredentialPolicy: (userId: string) => apiFetch<PolicyWithSource>(`/users/${userId}/policy`),
  setUserCredentialPolicy: (userId: string, body: Partial<CredentialPolicy>) =>
    apiFetch<PolicyWithSource>(`/users/${userId}/policy`, { method: 'PUT', body: JSON.stringify(body) }),
  clearUserCredentialPolicy: (userId: string) =>
    apiFetch<PolicyWithSource>(`/users/${userId}/policy`, { method: 'DELETE' }),
  permissionCatalog: () => apiFetch<PermissionCatalog>('/permissions'),
  // API tokens (self-service; ?all=true needs users:read).
  tokens: (all = false) =>
    apiFetch<ApiToken[]>(`/tokens${all ? '?all=true' : ''}`),
  createToken: (body: { label?: string; permissions?: string[]; expiresAt?: string | null }) =>
    apiFetch<ApiTokenCreated>('/tokens', { method: 'POST', body: JSON.stringify(body) }),
  deleteToken: (id: string) => apiFetch<void>(`/tokens/${id}`, { method: 'DELETE' }),
  // Roles.
  roles: () => apiFetch<Role[]>('/roles'),
  createRole: (body: { name: string; description?: string; permissions: string[] }) =>
    apiFetch<Role>('/roles', { method: 'POST', body: JSON.stringify(body) }),
  updateRole: (name: string, body: { description?: string | null; permissions?: string[] }) =>
    apiFetch<Role>(`/roles/${encodeURIComponent(name)}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteRole: (name: string) => apiFetch<void>(`/roles/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  /** Primary secret type + any additional named credential slots the plugin declares. */
  requiredSecretType: (pluginId: string) =>
    apiFetch<{ requiredSecretType: string | null; credentialSlots?: CredentialSlotDescriptor[] | null }>(
      `/plugins/${pluginId}/required-secret-type`
    ),
  pluginMetrics: (pluginId: string) =>
    apiFetch<PluginMetrics>(`/plugins/${pluginId}/metrics`),
  // Plugin options & settings (descriptor-driven, API-validated).
  pluginOptions: (pluginId: string) =>
    apiFetch<PluginOptionsResponse>(`/plugins/${pluginId}/options`),
  savePluginSettings: (pluginId: string, settings: Record<string, unknown>) =>
    apiFetch<PluginOptionsResponse>(`/plugins/${pluginId}/settings`, {
      method: 'PUT',
      body: JSON.stringify({ settings }),
    }),
  resetPluginSettings: (pluginId: string) =>
    apiFetch<PluginOptionsResponse>(`/plugins/${pluginId}/settings`, { method: 'DELETE' }),
  // Action catalog (drives plan creation).
  pluginActions: (pluginId: string) =>
    apiFetch<{ pluginId: string; actions: CatalogEntry[] }>(`/plugins/${pluginId}/actions`),
  // Execution plans.
  plans: () => apiFetch<Plan[]>('/plans'),
  /** Top-bar plans icon feed — executing + recently-finished (default 5 min window). */
  planActivity: (windowMs = 300_000) => apiFetch<Plan[]>(`/plans/activity?windowMs=${windowMs}`),
  createPlan: (body: {
    pluginId: string;
    intentActionId: string;
    inputs?: Record<string, unknown>;
    devices: { deviceId: string }[];
  }) => apiFetch<PlanDetail>('/plans', { method: 'POST', body: JSON.stringify(body) }),
  getPlan: (id: string) => apiFetch<PlanDetail>(`/plans/${id}`),
  deletePlan: (id: string) => apiFetch<void>(`/plans/${id}`, { method: 'DELETE' }),
  executePlan: (id: string) => apiFetch<PlanDetail>(`/plans/${id}/execute`, { method: 'POST' }),
  cancelPlan: (id: string) => apiFetch<PlanDetail>(`/plans/${id}/cancel`, { method: 'POST' }),
  addPlanStep: (planId: string, body: {
    deviceId: string;
    actionId: string;
    input?: Record<string, unknown>;
    secretRefs?: string[];
    bestEffort?: boolean;
  }) => apiFetch<PlanDetail>(`/plans/${planId}/steps`, { method: 'POST', body: JSON.stringify(body) }),
  updatePlanStep: (planId: string, stepId: string, body: {
    actionId?: string;
    input?: Record<string, unknown>;
    secretRefs?: string[];
    dependsOn?: number[];
    bestEffort?: boolean;
  }) => apiFetch<PlanDetail>(`/plans/${planId}/steps/${stepId}`, { method: 'PATCH', body: JSON.stringify(body) }),
  removePlanStep: (planId: string, stepId: string) =>
    apiFetch<PlanDetail>(`/plans/${planId}/steps/${stepId}`, { method: 'DELETE' }),
  reorderPlanSteps: (planId: string, from: number, to: number) =>
    apiFetch<PlanDetail>(`/plans/${planId}/steps/reorder`, { method: 'PATCH', body: JSON.stringify({ from, to }) }),
  /** Append MANY single-device steps in one round-trip (bulk actions). */
  addPlanStepsBulk: (planId: string, steps: Array<{ deviceId: string; actionId: string; input?: Record<string, unknown>; bestEffort?: boolean }>) =>
    apiFetch<PlanDetail>(`/plans/${planId}/steps/bulk`, { method: 'POST', body: JSON.stringify({ steps }) }),
  regeneratePlanSecret: (planId: string, ref: string) =>
    apiFetch<{ id: string; type?: string }>(`/plans/${planId}/secrets/${encodeURIComponent(ref)}/regenerate`, { method: 'POST' }),
  // Run ONE single-device READ action against a device's assignment and return its
  // result details (no plan row). Only riskLevel 'read' actions are allowed server-side.
  executePluginAction: (pluginId: string, body: { deviceId: string; actionId: string; input?: Record<string, unknown> }) =>
    apiFetch<{ details: Record<string, unknown> }>(`/plugins/${pluginId}/actions/execute`, { method: 'POST', body: JSON.stringify(body) }),
  // In-session 2FA re-validation (mint a fresh token without a full re-login).
  revalidateChallenge: () => apiFetch<RevalidateChallenge>('/auth/revalidate/challenge', { method: 'POST' }),
  verifyRevalidateTotp: (body: { challengeToken: string; totpCode: string }) =>
    apiFetch<VerifyResponse>('/auth/revalidate/totp', { method: 'POST', body: JSON.stringify(body) }),
  revalidateWebauthnOptions: (challengeToken: string, userId: string) =>
    apiFetch<WebauthnAssertionOptions>(`/auth/revalidate/webauthn/options?challengeToken=${encodeURIComponent(challengeToken)}&userId=${encodeURIComponent(userId)}`),
  verifyRevalidateWebauthn: (body: { challengeToken: string; response: unknown; nonce: string }) =>
    apiFetch<VerifyResponse>('/auth/revalidate/webauthn/verify', { method: 'POST', body: JSON.stringify(body) }),
  // System/HA observability + runtime tuning (Workers page).
  systemStatus: () => apiFetch<SystemStatus>('/system/status'),
  systemSettings: () => apiFetch<SystemSettingsResponse>('/system/settings'),
  saveSystemSettings: (body: SystemSettings) =>
    apiFetch<SystemSettingsResponse>('/system/settings', { method: 'PUT', body: JSON.stringify(body) }),
};
