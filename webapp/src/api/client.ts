const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:3000/v1';

/** API error that may carry per-field validation messages (e.g. plugin settings). */
export class ApiError extends Error {
  status: number;
  /** Machine-readable error code when the API provides one (e.g. 'no_2fa_enrolled'). */
  code?: string;
  fieldErrors?: Record<string, string>;
  /** Session-credential candidates — present on `credential_selection_required` errors. */
  candidates?: SessionCredentialCandidate[];
  constructor(message: string, status: number, fieldErrors?: Record<string, string>, code?: string, candidates?: SessionCredentialCandidate[]) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.fieldErrors = fieldErrors;
    this.code = code;
    if (candidates) this.candidates = candidates;
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
  /** May this secret be used for an interactive SSH console session? */
  interactiveLoginAllowed?: boolean;
  /** May this secret be used for SFTP file-access sessions? */
  fileAccessAllowed?: boolean;
}

// --- Session credentials (interactive SSH console / SFTP) ---------------------
/** Which kind of interactive session a credential applies to. */
export type SessionPurpose = 'console' | 'filesystem';

/** One secret the caller may use for an interactive session on a device. */
export interface SessionCredentialCandidate {
  id: string;
  label: string | null;
  type: string;
  /** True when this is the caller's own secret (vs. from the shared pool). */
  own: boolean;
}

/** GET /devices/:id/session-credentials response — eligible credentials ordered by
 *  the stored preference; `defaultSecretId` = what would be auto-used (null = prompt). */
export interface SessionCredentialOptions {
  deviceId: string;
  purpose: SessionPurpose;
  candidates: SessionCredentialCandidate[];
  defaultSecretId: string | null;
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
  /** True when the user's password has exceeded its max age — force a change right after sign-in. */
  passwordExpired?: boolean;
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

/** GET /auth/session response — server-computed session expiry + warning lead time. */
export interface SessionInfo {
  /** Unix epoch MILLISECONDS at which the current session expires (server-side, per-user-capped). */
  expiresAt: number;
  /** Effective TTL applied to this session in seconds. */
  ttlSeconds: number;
  /** Warning lead time in seconds (0 = warning disabled). */
  warnSeconds: number;
  /** True when the caller may extend their session at all (policy allows it AND a second factor is enrolled). */
  extensionAllowed: boolean;
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

/** One quick action a plugin propagates for its devices (Devices page "Device Actions" column). */
export interface QuickAction {
  /** Stable id within the plugin's quick-action list (e.g. 'webui', 'shell'). */
  id: string;
  label: string;
  description?: string;
  /** Optional icon path served from the plugin's /icons dir via the API icon proxy; generic per-kind glyph when absent. */
  iconPath?: string;
  kind: 'url' | 'shell' | 'files' | 'action';
  /** kind 'url': path the plugin appends to the resolved base URL. */
  url?: { path?: string };
  /** kind 'action': id of a single-device entry in this plugin's action catalog. */
  actionId?: string;
  /** Pre-filled input values merged under the action schema defaults (kind 'action'). */
  prefill?: Record<string, unknown>;
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
  /** Position within the device's ordered plugin list (0-based); row 0 = primary. */
  order?: number;
  createdAt: string;
  // Enriched fields returned by the list endpoints:
  pluginName?: string;
  pluginVersion?: string;
  pluginEndpoint?: string;
  /** The assigned plugin's advertised capabilities (e.g. 'deviceState'). */
  pluginCapabilities?: string[];
  /** The assigned plugin's quick actions for the Devices page "Device Actions" column. */
  pluginQuickActions?: QuickAction[];
  pluginOnline?: boolean;
  secretLabel?: string | null;
  /** The plugin's declared slots with their bound secrets resolved. */
  credentialSlots?: BoundCredentialSlot[];
  /** The plugin's device-support document (license/help/docs + support matrix). */
  deviceSupport?: DeviceSupport | null;
  /** Capabilities evaluated as effective for THIS device (feature/slot/firmware gating applied). */
  effectiveCapabilities?: CapabilityEvaluation[];
  /** Intents allowed on THIS device per the plugin's support matrix. */
  effectiveIntents?: CapabilityEvaluation[];
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

// --- Documented hosts (user-maintained host documentation) -------------------

/** One documented IP address of a documented host, enriched with live discovery data. */
export interface DocumentedHostIp {
  id: string;
  /** Bare IPv4/IPv6 literal. */
  address: string;
  version: 'v4' | 'v6';
  /** The DOCUMENTED (expected) MAC in colon form; null = unknown. */
  mac: string | null;
  /** Known-network reference or free-form label for an unknown network. */
  networkLabel: string | null;
  /** VLAN id the address lives in; null = unknown. */
  vlanId: number | null;
  /** Resolved display name of the referenced network. */
  networkName: string | null;
  /** True when the label refers to a known logical network (vs free-form). */
  networkKnown: boolean;
  /** True when this address was observed in the live inventory recently. */
  discovered: boolean;
  /** MAC currently observed for this address; null = not observed. */
  observedMac: string | null;
  /** Documented MAC is set AND differs from what is currently observed here. */
  macMismatch: boolean;
}

/** One documented host (user-maintained inventory) with live discovery info. */
export interface DocumentedHost {
  id: string;
  /** DNS names / FQDNs (lowercase); the FIRST entry is the primary name. */
  dnsNames: string[];
  friendlyName: string | null;
  description: string | null;
  siteId: string | null;
  siteName: string | null;
  layerId: string | null;
  layerName: string | null;
  /** User-assigned free-form tags (same data basis as devices.tags). */
  tags: string[];
  /** Additional known MACs of this host (rotated/randomized client MACs synced from the inventory). */
  macs: string[];
  ips: DocumentedHostIp[];
  /** True when any documented MAC or IP was observed in the live inventory. */
  discovered: boolean;
  /** Most recent observation matching this host; null = never seen. */
  lastSeenAt: string | null;
  /** Hostname reported by the best-matching live row (DHCP preferred). */
  observedHostname: string | null;
  /** Any documented MAC differs from what is currently observed for its address. */
  macMismatch: boolean;
  /** User-maintained lifecycle flag — false = stale/retired (row stays, dimmed in the UI). Default true. */
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

/** One IP entry of a documented-host create/update payload. */
export interface DocumentedHostIpRequest {
  address: string;
  /** Documented MAC (any common format); null/empty = unknown. */
  mac?: string | null;
  /** Known-network reference or free-form label for an unknown network. */
  networkLabel?: string | null;
  /** VLAN id the address lives in; null/omitted = unknown. */
  vlanId?: number | null;
}

/** Create/update payload for a documented host. */
export interface DocumentedHostRequest {
  dnsNames: string[];
  friendlyName?: string | null;
  description?: string | null;
  siteId?: string | null;
  layerId?: string | null;
  /** Free-form user tags (same data basis as devices.tags); omitted = none. */
  tags?: string[];
  /** Lifecycle flag — false marks the host stale/retired (new hosts default to active). */
  isActive?: boolean;
  ips: DocumentedHostIpRequest[];
}

/** Result of a batch lifecycle update on documented hosts. */
export interface DocumentedHostBulkResult {
  /** Hosts whose flag was changed. */
  updated: number;
  /** Submitted ids that do not exist. */
  missing: string[];
}

/** Result of a bulk documented-host import. */
export interface DocumentedHostImportResult {
  created: number;
  updated: number;
  /** Matched rows left untouched (updateExisting=false). */
  skipped: number;
  errors: { index: number; error: string }[];
}

/** Options for copying the live host inventory into the documented hosts. */
export interface DocumentedHostInventoryImportOptions {
  /** Skip live hosts without a usable hostname (default true). */
  skipWithoutHostname?: boolean;
  /** Skip live hosts whose addresses match no known logical network (default false). */
  skipUnknownNetworks?: boolean;
  /** How to treat public IPv4 addresses: keep | strip (drop only the public ones, still import the host) | skip-host. Default 'keep'. */
  publicIpv4Policy?: 'keep' | 'strip' | 'skip-host';
  /** How to treat public IPv6 addresses (GUA; ULA counts as internal): keep | strip | skip-host. Default 'keep'. */
  publicIpv6Policy?: 'keep' | 'strip' | 'skip-host';
  /** Range filter mode, applied before all other options: include-only = only hosts inside `ranges`; exclude = skip hosts inside `ranges`. Default 'keep-all'. */
  rangeMode?: 'keep-all' | 'include-only' | 'exclude';
  /** CIDR blocks (192.168.1.0/24) and/or inclusive IP ranges (192.168.1.10-192.168.1.50). Empty = no range filtering. */
  ranges?: string[];
  /** Skip live hosts whose addresses resolve to no known network with a discovered VLAN id (default false). */
  skipWithoutVlan?: boolean;
  /** Only import hosts observed within this many hours (0 = all, default 24). */
  maxAgeHours?: number;
  /** How to reconcile documented vs observed MACs: keep = never touch (default), replace = set the address's documented MAC to the observed one, add = keep it and remember the observed MAC as an additional identity of the host. */
  macSyncPolicy?: 'keep' | 'replace' | 'add';
  /** Preview only — compute the plan without writing anything (default true). */
  dryRun?: boolean;
}

/** One planned change for a single live host (or merged hostname group). */
export interface DocumentedHostInventoryPlanEntry {
  /** Representative MAC of this entry (first-seen; first NIC for merged groups). */
  mac: string;
  hostname: string | null;
  ips: number;
  action: 'create' | 'update' | 'skip';
  reason?: string;
  /** Public addresses removed by a strip policy (action=create/update only). */
  stripped?: number;
  /** Extra MACs folded into this entry by the smart hostname merge (multi-NIC host); empty/absent = single-MAC row. */
  mergedFrom?: string[];
  /** Documented-vs-observed MAC mismatches that would be REPLACED with the observed MAC (macSyncPolicy='replace'). */
  macReplaced?: number;
  /** Observed MACs that would be ADDED as additional identities of this host (macSyncPolicy='add'). */
  macAdded?: number;
}

/** Result of the inventory import (dry-run plan or applied summary). */
export interface DocumentedHostInventoryImportResult {
  dryRun: boolean;
  totalLiveHosts: number;
  planned: DocumentedHostInventoryPlanEntry[];
  created: number;
  updated: number;
  skipped: number;
  /** How many live MAC rows were folded into one entry by the hostname merge (dry-run only). */
  mergedGroups?: number;
  /** Total documented-vs-observed MAC mismatches replaced with the observed MAC. */
  macReplaced?: number;
  /** Total observed MACs added as additional identities of their host. */
  macAdded?: number;
}

/** Result of merging several documented host rows into one. */
export interface DocumentedHostMergeResult {
  /** The surviving (merged) host — oldest row's id + createdAt kept. */
  merged: DocumentedHost;
  /** Ids of the rows that were deleted. */
  removed: string[];
  /** Number of rows that were merged. */
  count: number;
}

/** Per-host outcome of a documented-host MAC sync. */
export interface DocumentedHostMacSyncDetail {
  id: string;
  /** Primary name for display (first DNS name, else first address). */
  name: string;
  /** Documented per-address MACs replaced with the currently observed ones. */
  macReplaced: number;
}

/** Result of replacing documented MACs with the currently observed ones. */
export interface DocumentedHostMacSyncResult {
  /** Hosts where at least one MAC (or a stale additional entry) changed. */
  updated: number;
  /** Hosts that were already in sync — nothing written. */
  unchanged: number;
  /** Submitted ids that do not exist. */
  missing: string[];
  details: DocumentedHostMacSyncDetail[];
}

// --- Documented networks (user-maintained network documentation) --------------

/** Per-subnet host-address stats — one entry per documented subnet, both families. */
export interface SubnetHostStats {
  cidr: string;
  family: 'v4' | 'v6';
  /** Total usable addresses in this subnet (string — a v6 /64's 2^64 overflows safe integers). */
  total: string;
  /** Distinct documented host IPs inside this subnet. */
  used: number;
  /** Free = total − used, clamped at 0 (string like `total`). */
  free: string;
  /** First usable address of the subnet (v6: the network address itself). */
  firstHost: string | null;
  lastHost: string | null;
  /** Broadcast address — v4 /30 and larger only; null for v6. */
  broadcastAddress: string | null;
}

/** One documented network (user-maintained inventory) with live discovery info. */
export interface DocumentedNetwork {
  id: string;
  /** Primary label / identity ("VLAN 30", "10.40.0.0/16", "Mgmt LAN"). Unique case-insensitively. */
  name: string;
  /** Canonicalized CIDR blocks, IPv4 first (may be empty for name-only rows). */
  subnets: string[];
  vlanId: number | null;
  gateways: string[];
  dnsServers: string[];
  ntpServers: string[];
  friendlyName: string | null;
  description: string | null;
  siteId: string | null;
  siteName: string | null;
  layerId: string | null;
  layerName: string | null;
  /** User-assigned free-form tags (same data basis as devices.tags). */
  tags: string[];
  /** True when a merged live logical network matches this documented one. */
  discovered: boolean;
  /** Most recent collection of any matching live group; null = never seen. */
  lastSeenAt: string | null;
  /** Subnets observed on the matching live groups (union, IPv4 first). */
  observedSubnets: string[];
  /** VLAN id observed on a matching live group (null when none known). */
  observedVlanId: number | null;
  /** Usable IPv4 host addresses over all v4 subnets; null for name-only / v6-only rows. */
  totalHosts: number | null;
  /** Usable hosts minus documented host IPs inside the network's v4 subnets (≥ 0). */
  freeHosts: number | null;
  /** First usable host of each v4 subnet, ", "-joined; null when no v4 subnet. */
  firstHost: string | null;
  lastHost: string | null;
  broadcastAddress: string | null;
  /** First address of each v6 subnet (the network address itself), ", "-joined; null when none. */
  firstHostV6: string | null;
  lastHostV6: string | null;
  /** Per-subnet used/free breakdown for every documented subnet (v4 + v6). */
  subnetStats: SubnetHostStats[];
  /** User-maintained lifecycle flag — false = stale/retired (row stays, dimmed in the UI). Default true. */
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

/** Create/update payload for a documented network. */
export interface DocumentedNetworkRequest {
  name: string;
  /** CIDR blocks ("10.40.0.0/16", "fd00::/64"); may be empty (name-only row). */
  subnets?: string[];
  vlanId?: number | null;
  gateways?: string[];
  dnsServers?: string[];
  ntpServers?: string[];
  friendlyName?: string | null;
  description?: string | null;
  siteId?: string | null;
  layerId?: string | null;
  /** Free-form user tags (same data basis as devices.tags); omitted = none. */
  tags?: string[];
  /** Lifecycle flag — false marks the network stale/retired (new networks default to active). */
  isActive?: boolean;
}

/** Result of a batch lifecycle update on documented networks. */
export interface DocumentedNetworkBulkResult {
  updated: number;
  missing: string[];
}

/** Result of a bulk documented-network import. */
export interface DocumentedNetworkImportResult {
  created: number;
  updated: number;
  /** Matched rows left untouched (updateExisting=false). */
  skipped: number;
  errors: { index: number; error: string }[];
}

/** Options for copying the live network inventory into the documented networks. */
export interface DocumentedNetworkInventoryImportOptions {
  /** Skip live logical networks without any real subnet (pure SSID/VLAN groups). Default true. */
  skipWithoutSubnet?: boolean;
  /** Skip live logical networks with no discovered VLAN id. Default false. */
  skipWithoutVlan?: boolean;
  /** Only import networks carrying this address family ('all' = both). Default 'all'. */
  version?: 'all' | 'v4' | 'v6';
  /** Policy for publicly routable IPv4 subnets (RFC 1918 + loopback/link-local count as internal). Default 'keep'. */
  publicIpv4Policy?: 'keep' | 'strip' | 'skip-network';
  /** Policy for publicly routable IPv6 subnets (GUA 2000::/3; ULA fc00::/7 counts as internal). Default 'keep'. */
  publicIpv6Policy?: 'keep' | 'strip' | 'skip-network';
  /** Range filter mode: include-only / exclude applied to the network's subnets. Default 'keep-all'. */
  rangeMode?: 'keep-all' | 'include-only' | 'exclude';
  /** CIDR blocks and/or inclusive IP ranges (empty = no filtering). */
  ranges?: string[];
  /** Only import networks observed within this many hours (0 = all, default 24). */
  maxAgeHours?: number;
  /** Preview only — compute the plan without writing anything (default true). */
  dryRun?: boolean;
}

/** One planned change for a single live logical network. */
export interface DocumentedNetworkInventoryPlanEntry {
  name: string;
  subnets: string[];
  vlanId: number | null;
  action: 'create' | 'update' | 'skip';
  reason?: string;
  /** Public subnets removed by a 'strip' policy (action=create/update only). */
  stripped?: number;
}

/** Result of the inventory import (dry-run plan or applied summary). */
export interface DocumentedNetworkInventoryImportResult {
  dryRun: boolean;
  totalLiveNetworks: number;
  planned: DocumentedNetworkInventoryPlanEntry[];
  created: number;
  updated: number;
  skipped: number;
  /** Ids of the documented rows this run created or updated (empty on a pure dry-run). */
  affectedIds?: string[];
}

/** Result of merging several documented network rows into one. */
export interface DocumentedNetworkMergeResult {
  /** The surviving (merged) network — oldest row's id + createdAt kept. */
  merged: DocumentedNetwork;
  /** Ids of the rows that were deleted. */
  removed: string[];
  /** Number of rows that were merged. */
  count: number;
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

/** One service from the cross-device inventory view (Services page). Unlike
 * networks/hosts, rows are NOT merged across devices — a row is one logical
 * service on one device. `type` labels the init system / framework managing it. */
export interface ServiceRow {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the reporting plugin instance (e.g. "OPNsense Plugin"). */
  pluginName?: string | null;
  /** Service name on the device ("sshd", "smb", "unbound", "nginx.service"). */
  name: string;
  /** Init system / framework: systemd | openrc | runit | sysvinit | freebsd-rc | truenas. */
  type: 'systemd' | 'openrc' | 'runit' | 'sysvinit' | 'freebsd-rc' | 'truenas' | string;
  status: 'running' | 'stopped' | 'failed' | 'unknown';
  /** True when enabled to start on boot (null = not observable). */
  enabled?: boolean | null;
  /** Main process id (null when stopped or not a live-process metric). */
  pid?: number | null;
  /** Human description from the vendor; '' = none. */
  description?: string;
  /** Vendor-specific extras (systemd sub-state, TrueNAS matched process, …). */
  extra?: Record<string, unknown>;
  collectedAt: string;
}

/** One mail domain from the cross-device Mail page inventory view. Rows are NOT
 * merged across devices — a row is one logical domain on one device. Quota
 * columns are bytes (double precision in the DB). */
export interface MailDomainRow {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the reporting plugin instance (e.g. "Mailcow Plugin"). */
  pluginName?: string | null;
  /** FQDN of the mail domain ("example.com"). */
  domain: string;
  active: boolean;
  description?: string;
  /** Total quota for all mailboxes in this domain, bytes (null = unlimited/unknown). */
  quotaBytes?: number | null;
  /** Per-mailbox quota ceiling within the domain, bytes. */
  maxQuotaPerMailboxBytes?: number | null;
  /** Default quota applied to new mailboxes in this domain, bytes. */
  defaultQuotaBytes?: number | null;
  mailboxCount?: number | null;
  aliasCount?: number | null;
  backupMx: boolean;
  collectedAt: string;
}

/** One mailbox from the cross-device Mail page inventory view. Identity is the
 * full username (email address). Quota columns are bytes. */
export interface MailMailboxRow {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the reporting plugin instance (e.g. "Mailcow Plugin"). */
  pluginName?: string | null;
  /** Full address ("user@example.com"). */
  username: string;
  domain: string;
  localPart: string;
  /** Display name of the mailbox owner; '' = none. */
  name: string;
  active: boolean;
  quotaBytes?: number | null;
  quotaUsedBytes?: number | null;
  messageCount?: number | null;
  forcePwUpdate: boolean;
  forceTfa: boolean;
  sogoAccess: boolean;
  collectedAt: string;
}

/** One alias from the cross-device Mail page inventory view. Identity is the
 * address (catch-all = "@domain.tld"). `mailcowId` is the numeric id mailcow's
 * edit/delete API requires — null means the row cannot be updated/deleted via a plan. */
export interface MailAliasRow {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the reporting plugin instance (e.g. "Mailcow Plugin"). */
  pluginName?: string | null;
  /** Alias address ("alias@example.com", catch-all "@example.com"). */
  address: string;
  domain: string;
  /** Comma-separated list of forwarding targets; '' = none. */
  goto: string;
  active: boolean;
  isCatchAll: boolean;
  /** Numeric id required by mailcow's edit/delete API (null = not observable). */
  mailcowId?: number | null;
  collectedAt: string;
}

/** One available update on one device, as reported by a plugin's `updates` metric. */
export interface UpdateRow {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the reporting plugin instance (e.g. "Generic SSH Plugin (Linux)"). */
  pluginName?: string | null;
  kind: 'firmware' | 'os-package' | 'docker-image' | 'app';
  /** Stable identity within (device, kind): "os" for firmware, a package name, an app/image name. */
  name: string;
  currentVersion?: string | null;
  latestVersion?: string | null;
  rebootRequired?: boolean | null;
  sizeBytes?: number | null;
  /** Vendor release-notes URL for this update (changelog page / docs anchor). */
  releaseNotesUrl?: string | null;
  /** Release-notes text propagated from the device's own update feed. */
  releaseNotes?: string | null;
  /** The device's current update branch/channel (TrueNAS profile, distro line, vendor track). */
  branch?: string | null;
  /** Catalog action id (of the reporting plugin) that applies this row; null = no apply path. */
  applyActionId?: string | null;
  /** Prefilled input for applyActionId. */
  applyInput?: Record<string, unknown>;
  extra?: Record<string, unknown>;
  collectedAt: string;
}

/** The "UNM itself" card on the Updates page (stack self-update info). */
export interface StackUpdateInfo {
  apiVersion: string;
  plugins: { name: string; version: string }[];
  feedConfigured: boolean;
  latestApiVersion?: string | null;
  available: boolean;
  notesUrl?: string | null;
}

export interface UpdatesResponse {
  rows: UpdateRow[];
  stack: StackUpdateInfo;
}

/** One actionable security finding on one device, as reported by a plugin's `securityChecks` metric. */
export interface SecurityCheckRow {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the reporting plugin instance (e.g. "Generic SSH Plugin (Linux)"). */
  pluginName?: string | null;
  kind: 'auth-failures' | 'file-integrity' | 'rate-limiting' | 'account' | 'service-exposure' | 'other';
  /** Stable identity within (device, kind): "auth-failures", "/etc/passwd", … */
  name: string;
  status: 'info' | 'warning' | 'critical';
  detail?: string | null;
  count?: number | null;
  extra?: Record<string, unknown>;
  collectedAt: string;
}

export interface SecurityChecksResponse {
  rows: SecurityCheckRow[];
}

/** The X.509 leaf certificate of one endpoint (ssh rows carry synthetic fields). */
export interface CertificateInfo {
  commonName: string;
  subject: string;
  issuer: string;
  selfSigned: boolean;
  notBefore: string;
  notAfter: string;
  keyAlgorithm: string;
  keySizeBits?: number | null;
  curveName?: string | null;
  signatureAlgorithm: string;
  sanNames: string[];
  serialNumber: string;
}

/** One certificate endpoint on one device (management HTTPS cert or SSH host key). */
export interface CertificateRow {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  /** Display name of the reporting plugin instance. */
  pluginName?: string | null;
  /** Stable endpoint identity, e.g. "https:443" / "ssh:22". */
  name: string;
  type: 'https' | 'ssh' | 'mtls';
  host?: string;
  port?: number | null;
  /** SHA-256 fingerprint of the key currently OBSERVED on the endpoint. */
  fingerprint?: string | null;
  /** The TRUSTED (pinned) fingerprint — what plugins verify before transmitting credentials. */
  trustedFingerprint?: string | null;
  /** True when observed !== trusted — strict pinning refuses connections until accepted. */
  fingerprintMismatch?: boolean;
  commonName?: string;
  subject?: string;
  issuer?: string;
  selfSigned?: boolean;
  notBefore?: string;
  notAfter?: string;
  keyAlgorithm?: string;
  keySizeBits?: number | null;
  curveName?: string | null;
  signatureAlgorithm?: string;
  sanNames?: string[];
  serialNumber?: string;
  /** Chain-validation verdict (null = unknown / not a cert). */
  valid?: boolean | null;
  invalidReason?: string | null;
  /** Days until the leaf expires (negative = expired); null when n/a. */
  daysToExpiry?: number | null;
  /** Days until the earliest chain element expires (issuer expiry). */
  chainDaysToExpiry?: number | null;
  /** Full served chain, leaf first (parsed array). */
  chain?: CertificateInfo[];
  /** True when the CA registry has this leaf revoked (mtls rows only). */
  revoked?: boolean;
  collectedAt: string;
}

/** One distinct fingerprint ever observed on a certificate endpoint (history row). */
export interface CertificateHistoryRow {
  deviceId: string;
  pluginId: string;
  /** Stable endpoint identity, e.g. "https:443" / "ssh:22". */
  name: string;
  type: 'https' | 'ssh';
  fingerprint: string;
  commonName?: string;
  subject?: string;
  issuer?: string;
  selfSigned?: boolean;
  notBefore?: string;
  notAfter?: string;
  keyAlgorithm?: string;
  keySizeBits?: number | null;
  curveName?: string | null;
  signatureAlgorithm?: string;
  /** First time this fingerprint was observed on the endpoint. */
  firstSeenAt: string;
  /** Last time it was still the current key. */
  lastSeenAt: string;
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

// --- Flows (sFlow/NetFlow traffic visibility) ---------------------------------

/** One top source or destination IP by estimated bytes (GET /flows/top-talkers). */
export interface FlowTalker {
  ip: string;
  /** Estimated bytes = reported bytes × sample rate. */
  estBytes: number;
  /** Raw reported bytes from the collector samples. */
  reportedBytes: number;
  deviceId: string | null;
  deviceName: string | null;
  internal: boolean;
  /** Hostname — inventory name for known hosts (container/VM, DHCP lease) or
   *  best-effort reverse-DNS for external IPs (null when unknown). */
  hostname: string | null;
  /** Where the hostname came from ('inventory' = hosts table, 'reverse-dns'). */
  hostnameSource?: 'inventory' | 'reverse-dns' | null;
  /** Inventoried network this IP lives in (longest-prefix match), e.g. "LAN". */
  networkName: string | null;
  /** VLAN id of that network (null = untagged/unknown). */
  vlanId: number | null;
  /**
   * How many distinct exporters observed this IP's flows in the window. >1 =
   * several devices on the path exported the same traffic and it was
   * deduplicated to a single best observation (0 = pre-dedup data or one exporter).
   */
  observedBy: number;
}

export interface FlowTopTalkersResponse {
  fromMs: number;
  toMs: number;
  /** Which aggregate table served the window (flow_agg_5m or flow_agg_1h). */
  table: 'flow_agg_5m' | 'flow_agg_1h';
  sources: FlowTalker[];
  destinations: FlowTalker[];
}

/** One L4 port row by estimated bytes (GET /flows/ports). Port 0 = no transport header. */
export interface FlowPortRow {
  port: number;
  proto: number;
  estBytes: number;
  reportedBytes: number;
}

export interface FlowPortsResponse {
  fromMs: number;
  toMs: number;
  table: 'flow_agg_5m' | 'flow_agg_1h';
  /** Set when the drilldown was scoped to one host. */
  ip?: string;
  sourcePorts: FlowPortRow[];
  destinationPorts: FlowPortRow[];
}

/** One LOGICAL network by traffic (GET /flows/networks) — same grouping as the
 * Networks page (several interfaces on one subnet/VLAN collapse into one row). */
export interface FlowNetworkRow {
  /** Logical-network label — the group's named interface when one exists
   * (e.g. "NET_DMZ_WAN01"), else its canonical subnet; "(external)" for
   * internet-classified traffic, "(unknown)" for unmatched internal. */
  name: string;
  vlanId: number | null;
  /** All subnets of the group (v4 first) — empty for unknown/VLAN-only rows. */
  subnets?: string[];
  srcEstBytes: number;
  dstEstBytes: number;
  estBytes: number;
}

export interface FlowNetworksResponse {
  fromMs: number;
  toMs: number;
  table: 'flow_agg_5m' | 'flow_agg_1h';
  networks: FlowNetworkRow[];
}

/** Per-device internet egress row (GET /flows/internet). */
export interface FlowInternetDevice {
  deviceId: string;
  deviceName: string | null;
  estBytes: number;
  distinctDestinations: number;
}

export interface FlowInternetResponse {
  fromMs: number;
  toMs: number;
  table: 'flow_agg_5m' | 'flow_agg_1h';
  total: { estBytes: number; distinctDestinations: number };
  perDevice: FlowInternetDevice[];
}

/** One internal device-to-device pair by estimated bytes (GET /flows/pairs). */
export interface FlowPair {
  srcDeviceId: string;
  dstDeviceId: string;
  srcName: string | null;
  dstName: string | null;
  estBytes: number;
  distinctPairs: number;
  /** Busiest source IP of this pair (the actual host behind the device). */
  srcTopIp?: string | null;
  /** Hostname of that IP from the hosts inventory (container/VM name, DHCP lease). */
  srcTopHost?: string | null;
  /** Busiest destination IP of this pair. */
  dstTopIp?: string | null;
  /** Hostname of that IP from the hosts inventory. */
  dstTopHost?: string | null;
}

export interface FlowPairsResponse {
  fromMs: number;
  toMs: number;
  table: 'flow_agg_5m' | 'flow_agg_1h';
  pairs: FlowPair[];
}

/** One gap-filled point of the flow timeseries (GET /flows/timeseries). */
export interface FlowTimeseriesPoint {
  /** Bucket start, ISO-8601. */
  bucket: string;
  estBytes: number;
}

export interface FlowTimeseriesResponse {
  fromMs: number;
  toMs: number;
  table: 'flow_agg_5m' | 'flow_agg_1h';
  bucket: '5m' | '1h';
  points: FlowTimeseriesPoint[];
}

/** Ingest queue counters of the flows worker on this API replica. */
export interface FlowIngestStats {
  queueDepth: number;
  enqueuedTotal: number;
  droppedTotal: number;
  insertedTotal: number;
  lastInsertAt: string | null;
  lastError: string | null;
}

/** Live stats of one flow-collector plugin instance (GET /flow-collectors). */
export interface FlowCollectorStats {
  id: string;
  name: string;
  reachable: boolean;
  samplesPerSec: number;
  tuplesPerSec: number;
  droppedTuplesTotal: number;
  queueDepth: number;
  pushesTotal: number;
  pushFailuresTotal: number;
}

export interface FlowCollectorsResponse {
  ingest: FlowIngestStats;
  collectors: FlowCollectorStats[];
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

/** Which nav items can carry a badge count (mirrors the API's /counts keys). */
export type NavCountKey = 'notifications' | 'configJobs' | 'plans' | 'certificates' | 'updates' | 'securityChecks';

/** Per-user navigation preferences (order + hidden pages), additive over defaults. */
export interface NavPreferences {
  /** Nav path strings in the user's chosen order; unknown paths are ignored on merge. */
  navOrder: string[];
  /** Nav path strings the user has hidden from the sidebar. */
  hiddenPages: string[];
  // --- Date/time display preferences (see utils/time.tsx) ---------------------
  /** IANA timezone id for rendering timestamps; null/absent = follow the browser's local zone. */
  timezone?: string | null;
  /** Format preset: 'locale' (default), 'iso', 'us', 'eu'. */
  dateFormat?: string;
  /** Append a short timezone label in parentheses after rendered timestamps. */
  showTzSuffix?: boolean;
}

/** Aggregated nav-badge counts (keys present only when the caller may read that page). */
export type NavCounts = Partial<Record<NavCountKey, number>>;

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

/** One user table (or one partition, when listed in `partitions`). Regular and
 * partitioned-parent rows carry isPartitioned/partitionCount/partitionKey;
 * partition child rows carry bound + parent. */
export interface PostgresTableStat {
  name: string;
  approxRows: number;
  totalSizeBytes: number;
  totalSizePretty: string;
  /** True for partitioned parent tables (relkind 'p'). */
  isPartitioned?: boolean;
  /** Direct partition count (0/undefined when not partitioned). */
  partitionCount?: number;
  /** PARTITION BY definition, e.g. "RANGE (ts)" — set on partitioned parents only. */
  partitionKey?: string | null;
  /** Partition bound (e.g. "FOR VALUES FROM (...) TO (...)") — partition child rows only. */
  bound?: string | null;
  /** Parent table name — partition child rows only. */
  parent?: string;
}

/** Read-only Postgres snapshot (version, connections, ALL user tables + partitions). */
export interface PostgresStats {
  version: string;
  databaseName: string;
  databaseSizePretty?: string;
  maxConnections: number;
  connectionsTotal: number;
  connectionsActive: number;
  connectionsIdle: number;
  /** Every user table (regular + partitioned parents), largest first. */
  tables: PostgresTableStat[];
  /** One row per partition of every user partitioned table (expandable detail). */
  partitions: PostgresTableStat[];
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

/** One central system setting (GET /settings). */
export interface SettingView {
  key: string;
  label: string;
  type: 'integer' | 'string' | 'boolean';
  category: string;
  help: string;
  unit?: string | null;
  /** Effective value (stored override ⊕ env default), already clamped. */
  value: number | string | boolean;
  /** Baseline the setting reverts to on reset. */
  defaultValue: number | string | boolean;
  isModified: boolean;
  min?: number | null;
  max?: number | null;
  pattern?: string | null;
}

export interface SettingsListResponse {
  settings: SettingView[];
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

// --- Shares (cross-device file-share exports + live client sessions) -------

/** One file-share export row from GET /shares. */
export interface ShareRow {
  deviceId: string;
  pluginId: string;
  /** Share/export name as reported (SMB share name, NFS path, iSCSI target, NVMe-oF NQN). */
  name: string;
  /** smb | nfs | iscsi | nvmeof (lowercase). */
  type: 'smb' | 'nfs' | 'iscsi' | 'nvmeof' | string;
  /** Dataset/path backing the share (null for block-protocol targets without a path). */
  path?: string | null;
  /** up | down | enabled | disabled | unknown (lowercase). */
  status: string;
  /** Number of active client sessions on this share (null when not observable). */
  sessionCount?: number | null;
  /** Plugin-specific details (JSON): smb {comment}, nfs {readOnly, hosts[]},
   * iscsi {id, iscsiName, datasets[]}, nvmeof {id, serialNumber, modelNumber, namespaces[]}. */
  extra?: Record<string, unknown>;
  collectedAt: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  pluginName?: string | null;
}

/** One live file-share client session row from GET /shares (bottom panel). */
export interface ShareSessionRow {
  deviceId: string;
  pluginId: string;
  /** smb | nfs — the protocol of this session. */
  type: 'smb' | 'nfs';
  /** Share/export name the client is connected to ('' for NFS sessions without a resolvable share). */
  shareName: string;
  /** Client host address (IP or hostname as reported); '' = unknown. */
  clientAddress: string;
  /** Client username (SMB); null for NFS. */
  user?: string | null;
  /** Seconds this session has been open (null when not observable). */
  uptimeSeconds?: number | null;
  collectedAt: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  pluginName?: string | null;
}

/** Response of GET /shares — share exports (top table) + live sessions (bottom panel). */
export interface SharesOverview {
  shares: ShareRow[];
  sessions: ShareSessionRow[];
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

// --- Device time (cross-device clock overview, Time page) -------------------

/** One device's reported clock from GET /device-time.
 * `available` is false when the assigned plugin can't read a wall clock
 * (SNMP-only / ICMP / …) or the reading has no resolvable instant — those
 * devices still appear so the page shows which boxes are covered. */
export interface DeviceTimeRow {
  deviceId: string;
  name: string;
  managementAddress: string;
  siteId?: string | null;
  /** Plugin that produced the latest snapshot (null when no telemetry yet). */
  pluginId?: string | null;
  /** ISO timestamp of the underlying telemetry row (null = never polled). */
  collectedAt?: string | null;
  available: boolean;
  /** Device's local wall clock as reported (ISO-8601, may carry an offset). */
  localIso?: string | null;
  /** IANA timezone identifier when known. */
  timezone?: string | null;
  /** Fixed UTC offset in minutes baked into the reading (when no IANA zone). */
  utcOffsetMinutes?: number | null;
  /** Absolute instant of the device clock, epoch ms (null = not resolvable). */
  deviceEpochMs?: number | null;
  /** UNM's own clock at response time, epoch ms. */
  unmNowMs: number;
  /** deviceEpochMs − unmNowMs — positive = device ahead, negative = behind. */
  driftMs?: number | null;

  // --- NTP-served time (generic-ntp plugin) ----------------------------------
  // The instant the device SERVES over its NTP/SNTP service — distinct from its
  // own system clock above (a box can serve accurate NTP while its wall clock is
  // off, or vice versa). All null when no NTP-capable plugin has reported.
  /** True when an NTP-served reading exists for this device. */
  ntpAvailable?: boolean;
  /** Plugin that produced the latest NTP-served reading (live-probe target). */
  ntpPluginId?: string | null;
  /** ISO timestamp of the underlying NTP telemetry row. */
  ntpCollectedAt?: string | null;
  /** UTC wall clock served by the device's NTP service (ISO-8601 "…Z"). */
  ntpTimeUtc?: string | null;
  /** Absolute instant served over NTP, epoch ms (null = not resolvable). */
  ntpEpochMs?: number | null;
  /** Stratum of the source (1 = reference clock … 15 = unsynchronized). */
  ntpStratum?: number | null;
  /** Reference ID (dotted IPv4 for stratum ≤ 1, else a 4-char tag like "GOOG"). */
  ntpReferenceId?: string | null;
  /** ntpEpochMs − reading instant — positive = serves ahead of UNM. */
  ntpDriftMs?: number | null;
}

/** Response of GET /device-time — every device with its clock + drift vs UNM. */
export interface DeviceTimeOverview {
  /** UNM's own clock at response time, epoch ms (the reference for all rows). */
  unmNowMs: number;
  devices: DeviceTimeRow[];
}

// --- Public NTP references (fleet time-base check, Time page) ---------------

/** One configured public NTP reference from GET /ntp-references. */
export interface NtpReferenceRow {
  /** Hostname or IP literal of the public reference. */
  server: string;
  port?: number | null;
  /** ok = healthy reply · unreachable = no reply/DNS failure · unsynced = server itself not synchronized (excluded from consensus). */
  status: 'ok' | 'unreachable' | 'unsynced';
  error?: string | null;
  rttMs?: number | null;
  /** Served instant − UNM clock at read time — positive = UNM behind, negative = ahead. Null when no usable instant. */
  driftMs?: number | null;
  stratum?: number | null;
  referenceId?: string | null;
  /** UTC wall clock served by the reference (ISO-8601 "…Z"). */
  timeUtc?: string | null;
  collectedAt: string;
}

/** Response of GET /ntp-references — all references + consensus verdict. */
export interface NtpReferenceOverview {
  /** UNM's own clock at response time, epoch ms. */
  unmNowMs: number;
  /** Median drift across healthy references (UNM vs international consensus). Null when no reference is currently healthy. */
  consensusMs?: number | null;
  /** How many healthy references contributed to the median. */
  sampleCount: number;
  references: NtpReferenceRow[];
}

/** One device attached to a VM — NIC, disk, display, CD-ROM, PCIe passthrough…
 * (from the plugin's `vms` metric, extra.devices[]). Generic across hypervisor
 * plugins: `dtype` is the appliance-native type; `label`/`detail` are pre-formatted. */
export interface VmDevice {
  /** Appliance-native device type (NIC | DISK | DISPLAY | CDROM | PCI | …). */
  dtype: string;
  /** The appliance's integer device id when known — target of vms.device-detach/edit. */
  id?: number;
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

/** One file in the central repository (device-independent store of ISOs, firmware,
 * config backups and scripts — files live on a volume only the API mounts). */
export interface FileRepoEntry {
  id: string;
  /** Original file name as uploaded. */
  name: string;
  /** Open category set (iso | firmware | config-backup | script | other). */
  category: string;
  sizeBytes: number;
  sha256: string;
  uploadedBy: string | null;
  createdAt: string;
  /** File-repo plugin storing the bytes (capability `fileRepo`); null = api-local volume (legacy). */
  providerId?: string | null;
  /** Display name for `uploadedBy` — user id resolved to username ('plugin' passes through). */
  uploadedByName?: string | null;
}

/** A registered file-repo storage backend (GET /files/providers). */
export interface FileRepoProvider {
  id: string;
  name: string;
  endpoint: string;
  online: boolean;
}

/** One usage record of a repo file (audit trail — which device, when). */
export interface FileRepoUse {
  id: string;
  fileId: string;
  deviceId: string | null;
  note: string | null;
  usedBy: string | null;
  createdAt: string;
  /** Display name for `usedBy` — user id resolved to username ('plugin' passes through). */
  usedByName?: string | null;
}

/** Device-level access scope rules — a user may see any device matching ANY rule. Empty = unrestricted. */
export interface DeviceScope {
  /** Visible devices assigned to any of these site ids. */
  siteIds?: string[];
  /** Visible devices carrying any of these tags. */
  tags?: string[];
  /** Explicitly visible device ids. */
  deviceIds?: string[];
}

/** A user account (never includes password hashes or TOTP secrets). */
export interface User {
  id: string;
  username: string;
  roles: string[];
  /** Explicit permission grants only (role-derived ones are added at login). */
  permissions: string[];
  /** The user's OWN device-scope rules (role scopes are unioned server-side). Empty = unrestricted. */
  deviceScope?: DeviceScope;
  /** True when ANY second factor is enrolled (TOTP or ≥1 passkey). */
  twoFactorEnabled: boolean;
  totpEnabled?: boolean;
  passkeyCount?: number;
  createdAt?: string;
  /** Disabled accounts are rejected at login and their live sessions terminate. */
  disabled?: boolean;
  /** Most recent successful authentication (drives the inactivity auto-disable sweep). */
  lastLoginAt?: string | null;
}

/** Credential policy — 2FA requirements, password rules and session caps. A per-user override wins over the global default field by field. */
export interface CredentialPolicy {
  /** Enrolled methods that satisfy login step 2 (empty = no 2FA). */
  requiredMethods: ('totp' | 'webauthn')[];
  /** Session AMRs that satisfy require2FA (config-job submission etc.). */
  gateAmrs: string[];
  /** Minimum characters for new/reset passwords (null = built-in default of 8). */
  minPasswordLength: number | null;
  /** Force a password change after this many days (null = no forced rotation). */
  passwordMaxAgeDays: number | null;
  /** Auto-disable the account if it has not logged on for this many days (null = off). */
  inactiveDisableAfterDays: number | null;
  /** Per-user cap on session lifetime in seconds — sessions expire at min(global, this) (null = inherit global). */
  sessionTimeoutSeconds: number | null;
  /** Whether the user may extend their own session via a 2FA revalidation. False = hardening kill switch. */
  allowSessionExtension?: boolean;
}

export interface PolicyWithSource {
  /** The EFFECTIVE policy (per-user override merged onto the global default). */
  policy: CredentialPolicy;
  /** The raw per-user override row; null when no override exists. */
  override: CredentialPolicy | null;
  /** Where the effective policy comes from (user = has an override). */
  source: 'user' | 'global';
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
  /** Group-level device-scope default for every member carrying this role. Empty = unrestricted. */
  deviceScope?: DeviceScope;
  createdAt?: string;
}

export interface PermissionCatalog {
  permissions: { id: string; description: string }[];
  roles: { name: string; description?: string | null; permissions: string[]; deviceScope?: DeviceScope }[];
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

/** Builds the URL of a plugin's static text asset (LICENSE.md, docs/*.md)
 * through the API proxy. `path` defaults to the plugin's advertised docPath. */
export function pluginAssetUrl(pluginId: string, path?: string | null): string {
  const p = path ? `?path=${encodeURIComponent(path)}` : '';
  return `${BASE}/plugins/${encodeURIComponent(pluginId)}/asset${p}`;
}

// ---------------------------------------------------------------------------
// Device support metadata (mirrors @unm/plugin-sdk deviceSupport.ts)
// ---------------------------------------------------------------------------

/** License metadata a plugin propagates to UNM. */
export interface PluginLicense {
  name: string;
  url?: string;
  /** Path of the bundled LICENSE.md relative to the plugin root (API asset proxy). */
  file?: string;
}

/** One gating condition on a capability/intent grant — all must hold. */
export interface SupportCondition {
  requiresFeatures?: string[];
  requiredSlots?: string[];
  minFirmware?: string;
  maxFirmware?: string;
}

/** One capability grant with optional gating conditions. */
export interface SupportCapabilityGrant {
  name: string;
  label?: string;
  conditions?: SupportCondition;
}

/** One intent (catalog action id) grant with optional gating conditions. */
export interface SupportIntentGrant {
  actionId: string;
  label?: string;
  conditions?: SupportCondition;
}

/** One row of the plugin's supported-device matrix (first match wins). */
export interface DeviceSupportProfile {
  vendor?: string;
  model?: string;
  minFirmware?: string;
  maxFirmware?: string;
  capabilities: SupportCapabilityGrant[];
  intents?: SupportIntentGrant[];
}

/** The full device-support document a plugin advertises in /discover. */
export interface DeviceSupport {
  license?: PluginLicense;
  helpUrl?: string;
  /** Path of the built-in markdown documentation (API asset proxy). */
  docPath?: string;
  defaultCapabilities?: SupportCapabilityGrant[];
  profiles?: DeviceSupportProfile[];
}

/** One evaluated capability/intent: effective for this device or not, with reasons. */
export interface CapabilityEvaluation {
  name: string;
  label?: string;
  effective: boolean;
  /** Human-readable reasons why it is NOT effective (empty when effective). */
  reasons: string[];
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
  /** Device support metadata — license/help/docs + supported-device matrix (null = not advertised). */
  deviceSupport?: DeviceSupport | null;
  /** Number of metric descriptors declared in /discover (how many metrics it can emit); null when unknown. */
  declaredMetricCount?: number | null;
  lastSeenAt?: string | null;
  /** True when the plugin's own mTLS listener is live (serving :4080 over TLS with a CA-issued leaf). */
  tlsLive?: boolean;
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
  /** Closed set of allowed values — rendered as a combobox (select). */
  enumOptions?: string[];
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
/** One suggested input field from a plugin preflight probe. */
export interface PreflightValueDto {
  key: string;
  value: unknown;
  confidence: 'high' | 'medium' | 'low';
  note?: string;
}

/** Server-side overlap finding (name/subnet/vlan collision with the live inventory). */
export interface NetworkCheckWarningDto {
  kind: 'name' | 'subnet' | 'vlan';
  message: string;
  networkKey: string;
}

/** Per-device server check attached to a preflight result (network.create only). */
export interface PreflightNetworkCheckDto {
  /** true when the live inventory already shows this network on the device. */
  deployed: boolean;
  warnings: NetworkCheckWarningDto[];
}

/** One physical port entry from a preflight result (network.create). */
export interface PreflightPortDto {
  /** Vendor-local port name — the value that goes into `vlanPorts`. */
  name: string;
  /** Whether the port is currently a trunk/uplink (carries >1 VLAN, or user-marked). */
  trunk?: boolean;
  /** Untagged default VLAN id, when known. */
  pvid?: number | null;
  /** True when the user has persistently marked this port as an uplink in UNM. */
  uplink?: boolean;
}

/** One candidate interface for the `interface` input (network.create). */
export interface PreflightInterfaceOptionDto {
  /** The value that goes into the intent's `interface` input. */
  name: string;
  kind?: 'physical' | 'bridge' | 'bundle' | 'vlan';
  note?: string;
}

/** The preflight result for one device of one plugin (POST /plans/preflight). */
export interface PreflightResultDto {
  deviceId: string;
  values: PreflightValueDto[];
  degraded?: boolean;
  error?: string;
  check?: PreflightNetworkCheckDto;
  /** Physical ports with trunk status — feeds the dialog's All/Trunk/Uplinks/Select quick-selects. */
  ports?: PreflightPortDto[];
  /** Candidate interfaces for the `interface` input (NICs/bridges/bundles). */
  interfaces?: PreflightInterfaceOptionDto[];
  /** Capability flags advertised by the plugin (e.g. explicit vlanPorts lists). */
  capabilities?: { vlanPorts?: boolean };
}

/** One user-assigned port role row (GET /devices/:id/port-roles). */
export interface PortRoleDto {
  pluginId: string;
  portName: string;
  role: 'uplink' | 'trunk';
  note?: string;
}

/** Free-range suggestions from gaps in the live inventory (GET /networks/suggestions). */
export interface NetworkSuggestions {
  nextFreeSubnetV4: string | null;
  /** Next free ULA /64 — only when the fleet already uses IPv6. */
  nextFreeSubnetV6: string | null;
  lowestFreeVlanId: number | null;
}

/** Per-device rollout outcome from the server-side network check. */
export interface NetworkCheckDeviceDto {
  deviceId: string;
  deviceName: string;
  status: 'deployed' | 'new';
}

/** Next free host address(es) for one device, computed by the API (auto-assign). */
export interface IpSuggestionDto {
  v4?: string | null;
  v6?: string | null;
}

/** Server-side overlap-check result (POST /plans/network-check). */
export interface NetworkCheckResultDto {
  warnings: NetworkCheckWarningDto[];
  devices: NetworkCheckDeviceDto[];
  suggestions: NetworkSuggestions;
  /** deviceId → next free address(es); present only when `autoAssign` was requested. */
  ipSuggestions?: Record<string, IpSuggestionDto>;
}

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
  /** When false the plan executor never re-dispatches this action (flapping guard). */
  retryOnDispatchFailure?: boolean;
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

// --- Filesystem (SFTP file manager, capability 'filesystem') -----------------

/** One file/directory entry from a filesystem `list` operation. */
export interface FilesystemEntry {
  name: string;
  isDirectory: boolean;
  sizeBytes: number | null;
  mtimeMs: number | null;
}

/** The file operation to perform (mirrors the SDK's FilesystemOp). */
export type FilesystemOp = 'list' | 'read' | 'stat' | 'write' | 'mkdir' | 'rmdir' | 'unlink' | 'rename';

/** Result of one filesystem operation — returned verbatim from the plugin. */
export interface FilesystemResult {
  collectedAt: string;
  /** Absolute path operated on (after root resolution). */
  path?: string;
  /** For `list`: the directory's entries. */
  entries?: FilesystemEntry[];
  /** For `read`: file contents, base64-encoded. */
  contentBase64?: string;
  sizeBytes?: number | null;
  mtimeMs?: number | null;
  isDirectory?: boolean;
}

/** POST /devices/:id/filesystem response — the broker wraps the result with ids. */
export interface FilesystemResponse {
  deviceId: string;
  pluginId: string;
  result: FilesystemResult;
}

// --- SSH console (capability 'sshConsole') -----------------------------------

/** Response of POST /devices/:id/console — a single-use, 60 s console ticket. */
export interface ConsoleTicketResponse {
  deviceId: string;
  /** Pass as ?ticket= on the console WebSocket endpoint (see openConsoleSocket). */
  ticket: string;
}

/** Builds the browser-facing console WebSocket URL for one minted ticket.
 *  The API proxies it verbatim to the plugin's /console endpoint — binary frames
 *  are raw terminal I/O, text frames carry JSON control messages ({ type: 'ready' |
 *  'resize' | 'exit' | 'error', … }). */
export function consoleSocketUrl(deviceId: string, ticket: string): string {
  const base = BASE.replace(/\/$/, '');
  const wsBase = base.replace(/^http/i, 'ws');
  return `${wsBase}/devices/${encodeURIComponent(deviceId)}/console/ws?ticket=${encodeURIComponent(ticket)}`;
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

/** Per-plan retry override for failed steps — partial; missing keys inherit the global defaults. */
export interface PlanRetryPolicy {
  /** Max dispatch attempts per step (0 = no retries). */
  maxAttempts?: number;
  /** Wait between attempts in ms when the plugin gives no per-failure hint. */
  waitMs?: number;
}

/** A persisted execution plan (list shape; detail adds `steps`). */
export interface Plan {
  id: string;
  pluginId: string;
  intentActionId: string;
  /** The raw intent inputs as submitted — the payload of every execution (re-runs and retries carry the same values). */
  intentInputs?: Record<string, unknown>;
  /** 'unverified' = applied without error but at least one write step could not be confirmed against device state. */
  status: 'draft' | 'ready' | 'scheduled' | 'executing' | 'succeeded' | 'unverified' | 'failed' | 'cancelled' | 'skipped';
  provisionedSecrets: PlanProvisionedSecret[];
  error?: string | null;
  createdBy: string;
  /** Display name of the creator (falls back to the raw user id). */
  createdByName?: string;
  /** User who started the CURRENT execution (null until executed; may differ from createdBy). */
  executedBy?: string | null;
  executedByName?: string | null;
  createdAt: string;
  updatedAt: string;
  /** When the current execution actually started (set by the executor); null while queued. */
  startedAt?: string | null;
  finishedAt?: string | null;
  /** Last terminal-status timestamp (cleared on re-execution) — drives the top-bar plans icon tick. */
  recentlyFinishedAt?: string | null;
  /** Set when this plan was created via retry — id of the duplicated plan. */
  retriedFrom?: string | null;
  /** Due instant of the current schedule (null when not scheduled). */
  scheduledAt?: string | null;
  /** What happens if the plugin is unreachable at the due instant: 'run-asap' retries with backoff, 'skip' marks it skipped. */
  schedulePolicy?: 'run-asap' | 'skip' | null;
  /** Per-plan retry override for failed steps; null = global defaults (only transient failures are retried). */
  retryPolicy?: PlanRetryPolicy | null;
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
    let candidates: SessionCredentialCandidate[] | undefined;
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
      if (body?.fieldErrors && typeof body.fieldErrors === 'object') fieldErrors = body.fieldErrors;
      if (typeof body?.code === 'string') code = body.code;
      if (Array.isArray(body?.candidates)) candidates = body.candidates as SessionCredentialCandidate[];
    } catch {
      // ignore body parse errors, fall back to generic message
    }
    // A 401 with a policy code means the session was terminated server-side —
    // either the account got DISABLED or its (per-user-capped) lifetime ended.
    // Drop the token and bounce to /login so the user sees why, not a wall of
    // failing requests. Only when we actually held a token (not on the login page).
    if (res.status === 401 && code && token && window.location.pathname !== '/login') {
      localStorage.removeItem('accessToken');
      window.location.assign('/login' + (code === 'user_disabled' ? '?reason=disabled' : ''));
    }
    throw new ApiError(message, res.status, fieldErrors, code, candidates);
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
  /** Server-computed session expiry + warning lead time (top-bar countdown chip). */
  sessionInfo: () => apiFetch<SessionInfo>('/auth/session'),
  // Session extension — ALWAYS requires re-proving a second factor (TOTP or
  // passkey) against a fresh challenge; the server also enforces the policy's
  // allowSessionExtension kill switch and an enrolled-factor requirement.
  sessionExtendChallenge: () => apiFetch<RevalidateChallenge>('/auth/session/extend/challenge', { method: 'POST' }),
  verifySessionExtendTotp: (body: { challengeToken: string; totpCode: string }) =>
    apiFetch<VerifyResponse>('/auth/session/extend/totp', { method: 'POST', body: JSON.stringify(body) }),
  sessionExtendWebauthnOptions: (challengeToken: string, userId: string) =>
    apiFetch<WebauthnAssertionOptions>(`/auth/session/extend/webauthn/options?challengeToken=${encodeURIComponent(challengeToken)}&userId=${encodeURIComponent(userId)}`),
  verifySessionExtendWebauthn: (body: { challengeToken: string; response: unknown; nonce: string }) =>
    apiFetch<VerifyResponse>('/auth/session/extend/webauthn/verify', { method: 'POST', body: JSON.stringify(body) }),
  /** Rotate the caller's own password (forced-change flow after an expired login). */
  changeOwnPassword: (body: { currentPassword: string; newPassword: string }) =>
    apiFetch<User>('/auth/me/password', { method: 'POST', body: JSON.stringify(body) }),
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
  /** Reorder a device's plugin list (drag & drop). The first id becomes primary. */
  reorderDevicePlugins: (deviceId: string, order: string[]) =>
    apiFetch<{ deviceId: string; plugins: DevicePluginAssignment[] }>(`/devices/${deviceId}/plugins/order`, { method: 'PUT', body: JSON.stringify({ order }) }),
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
  // One file operation on a device's filesystem, brokered to the assigned plugin's
  // POST /filesystem endpoint (capability 'filesystem'). The Storage page browses
  // dataset contents and the Containers page browses container volume mounts.
  // `context` names WHAT to browse; the plugin maps it onto an SFTP root and confines
  // every path to it. Gated on devices:write — file ops mutate device state.
  filesystem: (
    deviceId: string,
    op: FilesystemOp,
    params: { path?: string; targetPath?: string; contentBase64?: string; parents?: boolean; context?: Record<string, unknown>; pluginId?: string; secretId?: string } = {},
  ) =>
    apiFetch<FilesystemResponse>(`/devices/${deviceId}/filesystem`, {
      method: 'POST',
      body: JSON.stringify({ op, ...params }),
    }),
  // Mint a single-use, 60 s ticket for an interactive SSH console (capability
  // 'sshConsole'). Gated on devices:write; the plugin's capability is checked here.
  // `secretId` = the user's chosen session credential (from the picker); absent =
  // auto-use (stored default / sole candidate) or a 409 with candidates to prompt.
  mintConsoleTicket: (deviceId: string, params: { pluginId?: string; context?: Record<string, unknown>; secretId?: string } = {}) =>
    apiFetch<ConsoleTicketResponse>(`/devices/${deviceId}/console`, {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  // Session credentials (interactive SSH console / SFTP file access).
  /** The caller's eligible session credentials for a device+purpose, ordered by
   *  their stored preference; `defaultSecretId` = auto-used (null = must prompt). */
  sessionCredentials: (deviceId: string, purpose: SessionPurpose) =>
    apiFetch<SessionCredentialOptions>(`/devices/${deviceId}/session-credentials?purpose=${encodeURIComponent(purpose)}`),
  /** Store the caller's ORDERED preference for a device+purpose (first = default). */
  setSessionCredentials: (deviceId: string, purpose: SessionPurpose, secretIds: string[]) =>
    apiFetch<{ deviceId: string; purpose: SessionPurpose; secretIds: string[]; candidates: SessionCredentialCandidate[] }>(
      `/devices/${deviceId}/session-credentials`,
      { method: 'PUT', body: JSON.stringify({ purpose, secretIds }) },
    ),
  // Normalized port inventory for a device across all plugins.
  devicePorts: (deviceId: string) =>
    apiFetch<{ deviceId: string; ports: DevicePortRow[] }>(`/devices/${deviceId}/ports`),
  // User-assigned port roles (uplink/trunk markers). role=null clears the mark.
  devicePortRoles: (deviceId: string, pluginId?: string) =>
    apiFetch<{ deviceId: string; roles: PortRoleDto[] }>(`/devices/${deviceId}/port-roles${pluginId ? `?pluginId=${encodeURIComponent(pluginId)}` : ''}`),
  setDevicePortRole: (deviceId: string, body: { pluginId: string; portName: string; role: 'uplink' | 'trunk' | null }) =>
    apiFetch<{ deviceId: string; pluginId: string; portName: string; role: 'uplink' | 'trunk' | null }>(
      `/devices/${deviceId}/port-roles`,
      { method: 'PUT', body: JSON.stringify(body) },
    ),
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
    /** Opt the secret in for interactive SSH console sessions. */
    interactiveLoginAllowed?: boolean;
    /** Opt the secret in for SFTP file-access sessions. */
    fileAccessAllowed?: boolean;
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
  /** Update a secret's fields in place — same id, references keep working. All types supported.
   *  The two usage flags are only sent when provided (omitted = leave unchanged). */
  updateSecret: (id: string, body: { fields: Record<string, string>; label?: string; expiresAt?: string | null; interactiveLoginAllowed?: boolean; fileAccessAllowed?: boolean }) =>
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
  /** Free-range suggestions from gaps in the live inventory (rollout dialog one-click fills). */
  networksSuggestions: () => apiFetch<NetworkSuggestions>('/networks/suggestions'),
  hosts: (params?: { deviceId?: string; siteId?: string; source?: 'arp' | 'ndp' | 'dhcp' | 'wlan' }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.source) qs.set('source', params.source);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<HostRow[]>(`/hosts${suffix}`);
  },
  // Documented hosts — the user-maintained host documentation page.
  documentedHosts: (params?: { siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<DocumentedHost[]>(`/documented-hosts${suffix}`);
  },
  createDocumentedHost: (body: DocumentedHostRequest) =>
    apiFetch<DocumentedHost>('/documented-hosts', { method: 'POST', body: JSON.stringify(body) }),
  updateDocumentedHost: (id: string, body: Partial<DocumentedHostRequest>) =>
    apiFetch<DocumentedHost>(`/documented-hosts/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteDocumentedHost: (id: string) =>
    apiFetch<void>(`/documented-hosts/${id}`, { method: 'DELETE' }),
  /** Batch lifecycle update — marks the given hosts active or stale in one call. */
  bulkUpdateDocumentedHosts: (ids: string[], isActive: boolean) =>
    apiFetch<DocumentedHostBulkResult>('/documented-hosts/bulk', { method: 'POST', body: JSON.stringify({ ids, isActive }) }),
  /** Bulk site/layer placement — sets the given fields on every id (null clears). */
  bulkSetDocumentedHostPlacement: (ids: string[], placement: { siteId?: string | null; layerId?: string | null }) =>
    apiFetch<DocumentedHostBulkResult>('/documented-hosts/bulk', { method: 'POST', body: JSON.stringify({ ids, ...placement }) }),
  mergeDocumentedHosts: (ids: string[]) =>
    apiFetch<DocumentedHostMergeResult>('/documented-hosts/merge', { method: 'POST', body: JSON.stringify({ ids }) }),
  /** Replaces documented per-address MACs with the currently observed ones for a set of hosts. */
  syncDocumentedHostMacs: (ids: string[]) =>
    apiFetch<DocumentedHostMacSyncResult>('/documented-hosts/sync-macs', { method: 'POST', body: JSON.stringify({ ids }) }),
  importDocumentedHosts: (body: { hosts: DocumentedHostRequest[]; matchBy?: 'dns' | 'mac'; updateExisting?: boolean }) =>
    apiFetch<DocumentedHostImportResult>('/documented-hosts/import', { method: 'POST', body: JSON.stringify(body) }),
  /** Copy the live host inventory into the documented hosts (additive merge).
   *  dryRun defaults to true — returns a per-host plan without writing. */
  importDocumentedHostsFromInventory: (body: DocumentedHostInventoryImportOptions = {}) =>
    apiFetch<DocumentedHostInventoryImportResult>('/documented-hosts/import-from-inventory', { method: 'POST', body: JSON.stringify(body) }),
  // Documented networks — the user-maintained network documentation page.
  documentedNetworks: (params?: { siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<DocumentedNetwork[]>(`/documented-networks${suffix}`);
  },
  createDocumentedNetwork: (body: DocumentedNetworkRequest) =>
    apiFetch<DocumentedNetwork>('/documented-networks', { method: 'POST', body: JSON.stringify(body) }),
  updateDocumentedNetwork: (id: string, body: Partial<DocumentedNetworkRequest>) =>
    apiFetch<DocumentedNetwork>(`/documented-networks/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteDocumentedNetwork: (id: string) =>
    apiFetch<void>(`/documented-networks/${id}`, { method: 'DELETE' }),
  /** Batch lifecycle update — marks the given networks active or stale in one call. */
  bulkUpdateDocumentedNetworks: (ids: string[], isActive: boolean) =>
    apiFetch<DocumentedNetworkBulkResult>('/documented-networks/bulk', { method: 'POST', body: JSON.stringify({ ids, isActive }) }),
  /** Bulk site/layer placement — sets the given fields on every id (null clears). */
  bulkSetDocumentedNetworkPlacement: (ids: string[], placement: { siteId?: string | null; layerId?: string | null }) =>
    apiFetch<DocumentedNetworkBulkResult>('/documented-networks/bulk', { method: 'POST', body: JSON.stringify({ ids, ...placement }) }),
  mergeDocumentedNetworks: (ids: string[]) =>
    apiFetch<DocumentedNetworkMergeResult>('/documented-networks/merge', { method: 'POST', body: JSON.stringify({ ids }) }),
  importDocumentedNetworks: (body: { networks: DocumentedNetworkRequest[]; matchBy?: 'name' | 'subnet'; updateExisting?: boolean }) =>
    apiFetch<DocumentedNetworkImportResult>('/documented-networks/import', { method: 'POST', body: JSON.stringify(body) }),
  /** Copy the live network inventory into the documented networks (additive merge).
   *  dryRun defaults to true — returns a per-network plan without writing. */
  importDocumentedNetworksFromInventory: (body: DocumentedNetworkInventoryImportOptions = {}) =>
    apiFetch<DocumentedNetworkInventoryImportResult>('/documented-networks/import-from-inventory', { method: 'POST', body: JSON.stringify(body) }),
  tunnels: (params?: { deviceId?: string; siteId?: string; type?: 'wireguard' | 'openvpn' | 'ipsec' | 'pppoe' | 'gre' }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.type) qs.set('type', params.type);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<TunnelRow[]>(`/tunnels${suffix}`);
  },
  services: (params?: { deviceId?: string; siteId?: string; type?: string; status?: 'running' | 'stopped' | 'failed' | 'unknown' }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.type) qs.set('type', params.type);
    if (params?.status) qs.set('status', params.status);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<ServiceRow[]>(`/services${suffix}`);
  },
  mailDomains: (params?: { deviceId?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<MailDomainRow[]>(`/mail/domains${suffix}`);
  },
  mailMailboxes: (params?: { deviceId?: string; siteId?: string; domain?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.domain) qs.set('domain', params.domain);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<MailMailboxRow[]>(`/mail/mailboxes${suffix}`);
  },
  mailAliases: (params?: { deviceId?: string; siteId?: string; domain?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.domain) qs.set('domain', params.domain);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<MailAliasRow[]>(`/mail/aliases${suffix}`);
  },
  certificates: (params?: { deviceId?: string; siteId?: string; type?: 'https' | 'ssh' | 'mtls' }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.type) qs.set('type', params.type);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<CertificateRow[]>(`/certificates${suffix}`);
  },
  /** Fingerprint history of one endpoint (newest first). */
  certificateHistory: (deviceId: string, name: string, limit = 20) => {
    const qs = new URLSearchParams({ deviceId, name, limit: String(limit) });
    return apiFetch<CertificateHistoryRow[]>(`/certificates/history?${qs.toString()}`);
  },
  /** Accept the currently observed key (or a previously-seen one) as trusted. */
  acceptCertificate: (deviceId: string, name: string, fingerprint?: string) =>
    apiFetch<{ ok: boolean; deviceId: string; name: string; trustedFingerprint: string }>('/certificates/accept', {
      method: 'POST',
      body: JSON.stringify({ deviceId, name, ...(fingerprint ? { fingerprint } : {}) }),
    }),
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
  shares: (params?: { deviceId?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<SharesOverview>(`/shares${suffix}`);
  },
  containers: (params?: { deviceId?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<ContainersOverview>(`/containers${suffix}`);
  },
  /** Cross-device clock overview — every device's local time + drift vs UNM. */
  deviceTime: (params?: { deviceId?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<DeviceTimeOverview>(`/device-time${suffix}`);
  },
  /** Public NTP reference overview — the fleet's time-base check (Time page). */
  ntpReferences: () => apiFetch<NtpReferenceOverview>('/ntp-references'),
  vms: (params?: { deviceId?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<VmsOverview>(`/vms${suffix}`);
  },
  // --- Central file repository (device-independent store) ---------------------
  /** Lists repo files, newest first. Optional category filter. */
  repoFiles: (category?: string) => {
    const suffix = category ? `?category=${encodeURIComponent(category)}` : '';
    return apiFetch<{ files: FileRepoEntry[] }>(`/files${suffix}`);
  },
  /** Lists the registered file-repo storage backends + online state, plus the
   * effective default (what new uploads go to when no repo is picked). */
  fileRepoProviders: () => apiFetch<{ providers: FileRepoProvider[]; defaultProviderId: string | null }>('/files/providers'),
  /** Uploads a file to the repo. RAW octet-stream body + x-file-name header —
   * multi-GB ISOs stream through without base64/buffering. Identical content is
   * deduplicated (existing entry returned, deduplicated: true). `providerId`
   * optionally targets a specific file-repo backend (multi-segment repos). */
  uploadRepoFile: async (file: File, category?: string, providerId?: string): Promise<{ file: FileRepoEntry; deduplicated: boolean }> => {
    const token = getToken();
    const res = await fetch(`${BASE}/files`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'x-file-name': file.name,
        ...(category ? { 'x-file-category': category } : {}),
        ...(providerId ? { 'x-file-provider': providerId } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: file,
    });
    if (!res.ok) {
      let message = `API error ${res.status}`;
      try { const b = await res.json(); if (b?.error) message = b.error; } catch { /* keep generic */ }
      throw new ApiError(message, res.status);
    }
    return res.json() as Promise<{ file: FileRepoEntry; deduplicated: boolean }>;
  },
  /** Downloads a repo file as a Blob (authed — the API records a usage row). */
  downloadRepoFile: async (id: string): Promise<Blob> => {
    const token = getToken();
    const res = await fetch(`${BASE}/files/${encodeURIComponent(id)}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      let message = `API error ${res.status}`;
      try { const b = await res.json(); if (b?.error) message = b.error; } catch { /* keep generic */ }
      throw new ApiError(message, res.status);
    }
    return res.blob();
  },
  /** Deletes a repo file (content + metadata). Usage rows are kept. */
  deleteRepoFile: (id: string) => apiFetch<void>(`/files/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  /** The usage audit trail of one repo file (newest first). */
  repoFileUses: (id: string) => apiFetch<{ fileId: string; uses: FileRepoUse[] }>(`/files/${encodeURIComponent(id)}/uses`),
  /** Cross-device update center — available updates + stack self-update info. */
  updates: (params?: { deviceId?: string; siteId?: string; kind?: 'firmware' | 'os-package' | 'docker-image' | 'app' }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.kind) qs.set('kind', params.kind);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<UpdatesResponse>(`/updates${suffix}`);
  },
  /** Cross-device security findings — actionable checks only (warning/critical). */
  securityChecks: (params?: { deviceId?: string; siteId?: string; kind?: string; status?: 'info' | 'warning' | 'critical' }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.kind) qs.set('kind', params.kind);
    if (params?.status) qs.set('status', params.status);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<SecurityChecksResponse>(`/security-checks${suffix}`);
  },
  /** Physical + logical topology graph for the Topology page. */
  topology: (params?: { siteId?: string; includeHosts?: boolean }) => {
    const qs = new URLSearchParams();
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.includeHosts) qs.set('includeHosts', 'true');
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<TopologyResponse>(`/topology${suffix}`);
  },
  // Flows page — sFlow/NetFlow traffic visibility (aggregate tables only).
  flowsTopTalkers: (params?: { from?: string; to?: string; limit?: number; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.from) qs.set('from', params.from);
    if (params?.to) qs.set('to', params.to);
    if (params?.limit) qs.set('limit', String(params.limit));
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<FlowTopTalkersResponse>(`/flows/top-talkers${suffix}`);
  },
  flowsInternet: (params?: { from?: string; to?: string; deviceId?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.from) qs.set('from', params.from);
    if (params?.to) qs.set('to', params.to);
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<FlowInternetResponse>(`/flows/internet${suffix}`);
  },
  flowsPairs: (params?: { from?: string; to?: string; limit?: number; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.from) qs.set('from', params.from);
    if (params?.to) qs.set('to', params.to);
    if (params?.limit) qs.set('limit', String(params.limit));
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<FlowPairsResponse>(`/flows/pairs${suffix}`);
  },
  flowsTimeseries: (params?: { from?: string; to?: string; bucket?: '5m' | '1h'; deviceId?: string; class?: 'internet' | 'internal'; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.from) qs.set('from', params.from);
    if (params?.to) qs.set('to', params.to);
    if (params?.bucket) qs.set('bucket', params.bucket);
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.class) qs.set('class', params.class);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<FlowTimeseriesResponse>(`/flows/timeseries${suffix}`);
  },
  flowsPorts: (params?: { from?: string; to?: string; limit?: number; ip?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.from) qs.set('from', params.from);
    if (params?.to) qs.set('to', params.to);
    if (params?.limit) qs.set('limit', String(params.limit));
    if (params?.ip) qs.set('ip', params.ip);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<FlowPortsResponse>(`/flows/ports${suffix}`);
  },
  flowsNetworks: (params?: { from?: string; to?: string; limit?: number; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.from) qs.set('from', params.from);
    if (params?.to) qs.set('to', params.to);
    if (params?.limit) qs.set('limit', String(params.limit));
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<FlowNetworksResponse>(`/flows/networks${suffix}`);
  },
  flowCollectors: () => apiFetch<FlowCollectorsResponse>('/flow-collectors'),
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
  // Per-user navigation preferences (order + hidden pages) — self-service.
  getNavPrefs: () => apiFetch<NavPreferences>('/auth/me/preferences'),
  setNavPrefs: (prefs: Partial<NavPreferences>) =>
    apiFetch<NavPreferences>('/auth/me/preferences', { method: 'PUT', body: JSON.stringify(prefs) }),
  // Aggregated nav-badge counts for the sidebar (permission-aware).
  navCounts: () => apiFetch<NavCounts>('/counts'),
  // Runtime self-metrics of a plugin process (CPU/memory/lag/poll stats).
  pluginSelfMetrics: (pluginId: string, limit = 120) =>
    apiFetch<{ pluginId: string; latest: PluginSelfMetricsSample | null; history: PluginSelfMetricsSample[] }>(
      `/plugins/${pluginId}/self-metrics?limit=${limit}`
    ),
  // Static text asset of a plugin (LICENSE.md, docs/*.md) via the API proxy.
  // `path` defaults to the plugin's advertised docPath on the server side.
  // Plain fetch (not apiFetch): the response is raw markdown/text, not JSON.
  pluginAsset: async (pluginId: string, path?: string | null) => {
    const p = path ? `?path=${encodeURIComponent(path)}` : '';
    const token = getToken();
    const res = await fetch(`${BASE}/plugins/${encodeURIComponent(pluginId)}/asset${p}`, {
      headers: token ? { Authorization: 'Bearer ' + token } : {},
    });
    if (!res.ok) throw new Error(`Failed to load plugin asset (HTTP ${res.status})`);
    return res.text();
  },
  // Users + permission catalog.
  users: () => apiFetch<User[]>('/users'),
  createUser: (body: { username: string; password: string; roles?: string[]; permissions?: string[]; deviceScope?: DeviceScope }) =>
    apiFetch<{ user: User; enrollment: TotpEnrollment }>('/users', { method: 'POST', body: JSON.stringify(body) }),
  updateUser: (id: string, body: { roles?: string[]; permissions?: string[]; deviceScope?: DeviceScope }) =>
    apiFetch<User>(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteUser: (id: string) => apiFetch<void>(`/users/${id}`, { method: 'DELETE' }),
  /** Enable/disable a user account (requires users:write). */
  setUserStatus: (id: string, disabled: boolean) =>
    apiFetch<User>(`/users/${id}/status`, { method: 'PATCH', body: JSON.stringify({ disabled }) }),
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
  // userId = mint on behalf of another user (requires users:write) — used to
  // provision API tokens for service-only accounts that can't sign in.
  createToken: (body: { label?: string; permissions?: string[]; expiresAt?: string | null; userId?: string }) =>
    apiFetch<ApiTokenCreated>('/tokens', { method: 'POST', body: JSON.stringify(body) }),
  deleteToken: (id: string) => apiFetch<void>(`/tokens/${id}`, { method: 'DELETE' }),
  // Roles.
  roles: () => apiFetch<Role[]>('/roles'),
  createRole: (body: { name: string; description?: string; permissions: string[]; deviceScope?: DeviceScope }) =>
    apiFetch<Role>('/roles', { method: 'POST', body: JSON.stringify(body) }),
  updateRole: (name: string, body: { description?: string | null; permissions?: string[]; deviceScope?: DeviceScope }) =>
    apiFetch<Role>(`/roles/${encodeURIComponent(name)}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteRole: (name: string) => apiFetch<void>(`/roles/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  /** Primary secret type + any additional named credential slots the plugin declares. */
  requiredSecretType: (pluginId: string) =>
    apiFetch<{
      requiredSecretType: string | null;
      /** All acceptable PRIMARY secret types (empty = any / undeclared). */
      requiredSecretTypes?: string[];
      credentialSlots?: CredentialSlotDescriptor[] | null;
    }>(`/plugins/${pluginId}/required-secret-type`),
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
    /** Optional per-device input overrides for fan-out intents — the rollout
     * wizard's confirmed preflight values (merged over `inputs` per device). */
    deviceInputs?: Record<string, Record<string, unknown>>;
    /** Optional per-plan retry override; wins over the plugin's suggestion and the global defaults. */
    retryPolicy?: PlanRetryPolicy | null;
  }) => apiFetch<PlanDetail>('/plans', { method: 'POST', body: JSON.stringify(body) }),
  /** Read-only best-guess resolution for a fleet intent — one result per device
   * (suggested values + confidence + notes from the plugin's live-state probe). */
  plansPreflight: (body: {
    pluginId: string;
    intentActionId: string;
    inputs?: Record<string, unknown>;
    deviceIds: string[];
  }, opts?: RequestInit) => apiFetch<{ results: PreflightResultDto[] }>('/plans/preflight', { method: 'POST', body: JSON.stringify(body), ...opts }),
  /** Server-side network-overlap check for a rollout (warnings + per-device
   * deployed/new status + free-range suggestions). Read-only, no 2FA. */
  plansNetworkCheck: (body: {
    inputs?: Record<string, unknown>;
    deviceIds?: string[];
    /** Ask the API to compute per-device next-free-address suggestions. */
    autoAssign?: boolean;
  }) =>
    apiFetch<NetworkCheckResultDto>('/plans/network-check', { method: 'POST', body: JSON.stringify(body) }),
  getPlan: (id: string) => apiFetch<PlanDetail>(`/plans/${id}`),
  /** Update plan-level settings (currently: the per-plan retry policy). Draft/ready/scheduled only. */
  updatePlan: (id: string, body: { retryPolicy?: PlanRetryPolicy | null }) =>
    apiFetch<PlanDetail>(`/plans/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deletePlan: (id: string) => apiFetch<void>(`/plans/${id}`, { method: 'DELETE' }),
  executePlan: (id: string) => apiFetch<PlanDetail>(`/plans/${id}/execute`, { method: 'POST' }),
  /** Resolve a kind:'url' quick action into the device's management web-UI URL. */
  resolveQuickAction: (deviceId: string, actionId: string, pluginId?: string) =>
    apiFetch<{ deviceId: string; url: string }>(`/devices/${deviceId}/quick-action`, {
      method: 'POST',
      body: JSON.stringify({ actionId, ...(pluginId ? { pluginId } : {}) }),
    }),
  /** Duplicate this plan (same payload + provisioned secrets) and execute the copy. */
  retryPlan: (id: string) => apiFetch<PlanDetail>(`/plans/${id}/retry`, { method: 'POST' }),
  /** (Re-)schedule a saved or finished plan for later execution. Relative (`inMinutes`) or absolute (`at`). */
  schedulePlan: (id: string, body: { at?: string; inMinutes?: number; policy?: 'run-asap' | 'skip' }) =>
    apiFetch<PlanDetail>(`/plans/${id}/schedule`, { method: 'POST', body: JSON.stringify(body) }),
  /** Remove the schedule — the plan returns to its pre-schedule status. */
  unschedulePlan: (id: string) => apiFetch<PlanDetail>(`/plans/${id}/schedule`, { method: 'DELETE' }),
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
  // Force a fresh mTLS leaf for one plugin (rotation — the old leaf stays valid until expiry).
  renewPluginTls: (pluginId: string) =>
    apiFetch<{ renewed: boolean; ok: boolean }>(`/plugins/${pluginId}/tls/renew`, { method: 'POST' }),
  // Force a fresh mTLS leaf for one of UNM's own services ('api' | 'mcp').
  caRenew: (subject: 'api' | 'mcp') =>
    apiFetch<{ renewed: boolean; ok: boolean }>('/ca/renew', { method: 'POST', body: JSON.stringify({ subject }) }),
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
  // Central system settings (the Settings page).
  listSettings: () => apiFetch<SettingsListResponse>('/settings'),
  updateSetting: (key: string, value: number | string | boolean) =>
    apiFetch<{ setting: SettingView }>(`/settings/${encodeURIComponent(key)}`, { method: 'PUT', body: JSON.stringify({ value }) }),
  resetSetting: (key: string) =>
    apiFetch<{ setting: SettingView }>(`/settings/${encodeURIComponent(key)}`, { method: 'DELETE' }),
};
