/**
 * @unm/plugin-sdk — shared contract types.
 *
 * The SINGLE SOURCE OF TRUTH for everything that crosses the API <-> plugin
 * boundary. Both sides compile against these definitions:
 *   - plugins emit them (in /discover, /monitoring responses, /plan output),
 *   - the central API consumes them (discovery upsert, telemetry ingestion,
 *     plan validation) — types-only import, no runtime coupling.
 *
 * Keep this file in sync with `openapi/unified-network-manager.openapi.yaml`
 * when a wire shape changes; the OpenAPI spec documents the public HTTP API,
 * these types document the plugin contract.
 */

// ---------------------------------------------------------------------------
// Health + capabilities
// ---------------------------------------------------------------------------

/** Plugin health vocabulary (the API derives device status worst-wins from it). */
export type Health = 'ok' | 'warning' | 'critical' | 'unknown';

/** Capability strings a plugin may advertise in /discover. */
export const CAPABILITIES = [
  'monitoring',
  'inventory',
  'configuration',
  'planning',
  // Serves GET /state — a dynamic, device-specific state document (ports with
  // live states + per-port MACs, interfaces, ZFS pools, system info) that the
  // webapp's per-device Config page renders. Actions referenced in it must be
  // entries of this plugin's action catalog.
  'deviceState',
  // Can reach the device over SSH (see createSshClient / resolveSshCredentials).
  // Advertise when the plugin uses SSH as a data path — e.g. for inventory the
  // vendor API does not expose (per-container MACs via `docker inspect`). The
  // plugin must declare an 'ssh' credential slot (secretType usernamePassword
  // or sshKeyPair) in /discover so users can bind credentials to it.
  'ssh',
  'secretsProvider',
  'identityProvider',
  // Reserved for future log-forwarder plugins (syslog daemon, OpenSearch, ...).
  // Regular plugins do NOT advertise this — they ship logs via createPluginLogger.
  'logIngestion',
] as const;
export type PluginCapability = (typeof CAPABILITIES)[number];

// ---------------------------------------------------------------------------
// Metric descriptors — the webapp renders entirely from these
// ---------------------------------------------------------------------------

/** How a metric value should be humanized by the UI. */
export type MetricFormat = 'bytes' | 'bits' | 'duration' | 'number' | 'text';
/** Default render hint for a metric. */
export type MetricVisualization = 'gauge' | 'plot' | 'text' | 'table';
/** Value type of the metric. */
export type MetricValueType = 'number' | 'string' | 'boolean' | 'enum';

/**
 * A plugin's self-description of one metric it emits. The webapp renders from
 * these — adding a new metric (or a new plugin) requires NO webapp code.
 * Mirrors `MetricDescriptor` in webapp/src/api/client.ts and the OpenAPI spec.
 */
export interface MetricDescriptor {
  /** Metric id; must match a key in the telemetry `metrics` map. */
  key: string;
  /** Human-readable name. */
  label: string;
  /** Unit of measure (%, MB, bps, s, ...) — raw unit, kept for machine comparison. */
  unit?: string;
  /** Rendering hint: bytes | bits | duration | number | text. */
  format?: MetricFormat;
  type: MetricValueType;
  visualization: MetricVisualization;
  /** Optional section grouping (e.g. "System", "Network"). */
  group?: string;
  min?: number;
  max?: number;
  color?: string;
  /** For 'table': the row keys (e.g. interface names). */
  rows?: string[];
  /** Column field names for `table` visualizations. */
  columns?: string[];
  /** true = headline metric shown inline in the device overview table. */
  summary?: boolean;
  /** Refresh cadence hint (ms) — how often this group should be re-fetched from the device. */
  intervalMs?: number;
}

// ---------------------------------------------------------------------------
// Plugin option descriptors (/discover `options`)
// ---------------------------------------------------------------------------

export interface PluginOptionBase {
  /** Short internal name; unique per plugin. Used as the settings key. */
  key: string;
  /** Human-readable display name shown in the UI. */
  label: string;
  type: 'string' | 'integer' | 'boolean';
  /** Default value used when the user has not set an override. */
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

/** Discriminated union on `type` — mirrors api/src/types/pluginOptions.ts. */
export type PluginOptionDescriptor = StringOption | IntegerOption | BooleanOption;

// ---------------------------------------------------------------------------
// Device model catalog + credential slots (/discover)
// ---------------------------------------------------------------------------

/** One hardware model a plugin supports (drives the webapp Model/Firmware dropdowns). */
export interface DeviceModelEntry {
  /** Vendor this entry applies to; must match one of the plugin's `vendors`. */
  vendor: string;
  /** Display name of the hardware model, e.g. "LX45". */
  model: string;
  /** Optional icon path relative to the plugin root (served via the API's icon proxy). */
  iconPath?: string;
  /** Optional list of firmware versions for this model (plain strings). */
  firmwareVersions?: string[];
  /**
   * Optional suggested network layer for devices of this model (a
   * `network_layers` id, e.g. "core" or a user-defined custom layer id).
   * Used by the topology view's auto-classification: manual override > this
   * suggestion > type/vendor/port heuristic > 'access'. Not validated against
   * the layers table at discovery time — resolution is lazy, so a layer can be
   * added after the fact.
   */
  defaultLayerId?: string;
}

/** One named credential slot beyond the primary secret (e.g. a web-UI login). */
export interface CredentialSlotDescriptor {
  /** Slot key (e.g. "web"). Unique per plugin; used as the map key everywhere. */
  name: string;
  /** Secret type the bound secret must have (e.g. "usernamePassword", "snmp").
   *  Legacy single-type form — declare `secretTypes` when a slot accepts several,
   *  and repeat its first entry here for backward compatibility with older APIs. */
  secretType?: string;
  /** Allowed secret types for this slot (one or many). Wins over `secretType`
   *  when present and non-empty — e.g. an SSH slot that accepts BOTH a
   *  username/password login AND a key pair: ['usernamePassword', 'sshKeyPair']. */
  secretTypes?: string[];
  required?: boolean;
  /** Info text shown in the UI: what this credential is used for on the device
   *  (which data path it unlocks), so users can decide whether to bind one. */
  description?: string;
}

/** Effective allowed types of a slot — `secretTypes` wins over legacy `secretType`. */
export function allowedSecretTypes(
  slot: Pick<CredentialSlotDescriptor, 'secretType' | 'secretTypes'>
): string[] {
  if (Array.isArray(slot.secretTypes) && slot.secretTypes.length > 0) return slot.secretTypes;
  return typeof slot.secretType === 'string' && slot.secretType !== '' ? [slot.secretType] : [];
}

// ---------------------------------------------------------------------------
// Secrets (provider-declared field schemas)
// ---------------------------------------------------------------------------

/** A secret field as declared by a provider's secret type schema. */
export interface SecretField {
  name: string;
  label: string;
  /** textarea = multi-line input (PEM private keys, certificate bundles). */
  input: 'text' | 'password' | 'select' | 'textarea';
  /** true = rendered as a password input / never echoed back in plaintext. */
  secret?: boolean;
  required?: boolean;
  options?: string[];
}

/** A secret type (e.g. `apiKey`, `usernamePassword`) with its field schema. */
export interface SecretType {
  type: string;
  label: string;
  fields: SecretField[];
  /** True when the provider can create/rotate this type's material itself. */
  generatable?: boolean;
}

// ---------------------------------------------------------------------------
// Action catalog + input schemas (/discover `actions`, /config, /plan)
// ---------------------------------------------------------------------------

/** How risky an action is. The API gates `dangerous` behind 2FA + explicit confirm. */
export type RiskLevel = 'read' | 'write' | 'dangerous';

/** Whether the action targets one device or fans out across many (multi-device intent). */
export type DeviceCount = 1 | 'N';

/**
 * A single input property schema — a small JSON-Schema subset mirroring the
 * shape the webapp's SchemaForm renders. Superset of all plugin copies:
 * includes swos's minLength/maxLength for strings.
 */
export interface InputSchemaProperty {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  label?: string;
  description?: string;
  required?: boolean;
  default?: unknown;
  /** Regex the string value must match. */
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  enum?: (string | number)[];
  /** For type 'array': schema of each element. */
  items?: InputSchemaProperty;
  /** For type 'object': nested property schemas. */
  properties?: Record<string, InputSchemaProperty>;
}

/** The action's input contract: a map of property name → schema. */
export type InputSchema = Record<string, InputSchemaProperty>;

/** One entry as advertised in /discover `actions` (the API persists + validates against it). */
export interface CatalogEntry {
  id: string;
  label: string;
  description?: string;
  /** Module grouping for catalog display. */
  module: string;
  riskLevel: RiskLevel;
  /** Exact device count (1 = single-device action, N = multi-device intent). */
  deviceCount: number | 'N';
  /** Per-action timeout override (ms) for long-running ops. */
  timeoutMs?: number;
  /** Only executable on Business Edition (OPNsense-specific flag). */
  beOnly?: boolean;
  inputSchema: InputSchema;
}

/** A request for durable credentials the API must create before plan steps run. */
export interface ProvisionRequest {
  /** Stable ref within this plan; steps reference it via secretRefs. */
  ref: string;
  /** Secret type to create (must be a type the secrets provider serves). */
  type: string;
  /** Non-secret context fields (labels, CN/SANs...). Never private material. */
  fields?: Record<string, unknown>;
  label?: string;
}

/** A single step in an execution plan (plugin-side shape = API's plan_steps row). */
export interface PlanStep {
  stepIndex: number;
  deviceId: string;
  actionId: string;
  input: Record<string, unknown>;
  /** Indices of steps that must succeed before this one runs. */
  dependsOn?: number[];
  /** Provisioned secrets to merge into this step's credentials (namespaced by ref). */
  secretRefs?: string[];
  /** Best-effort step — failure is recorded but does not abort the plan. */
  bestEffort?: boolean;
}

/** The output of /plan: ordered, dependency-aware steps + credential requests. */
export interface Plan {
  id: string;
  createdAt: string;
  intentActionId: string;
  provisionRequests: ProvisionRequest[];
  steps: PlanStep[];
}

/** One device in a /plan request (credentials = primary secret fields only). */
export interface PlanDevice<Credentials extends object = Record<string, unknown>> {
  deviceId: string;
  managementAddress: string;
  credentials: Credentials;
}

/** The body of POST /plan. Plugins may extend with their own options (e.g. transport overrides). */
export interface PlanRequest<Credentials extends object = Record<string, unknown>> {
  intent: { actionId: string; inputs: Record<string, unknown> };
  devices: PlanDevice<Credentials>[];
}

/** The result an action executor returns. `verified` = plugin re-read state post-apply. */
export interface ActionResult {
  success: boolean;
  applied?: boolean;
  verified?: boolean;
  details?: Record<string, unknown>;
  error?: string;
}

// ---------------------------------------------------------------------------
// Wire shapes — POST /monitoring (API -> plugin)
// ---------------------------------------------------------------------------

/** One known address of the device (primary first). */
export interface DeviceAddress {
  address: string;
  isPrimary: boolean;
}

/** Decrypted credential fields for one assignment. Primary secret at top level, bound slots under `slots`. */
export interface StepCredentials {
  /** Bound credential slots: slot name -> decrypted field map (see CredentialSlotDescriptor). */
  slots?: Record<string, Record<string, string>>;
  [field: string]: unknown;
}

/** Body of POST /monitoring as sent by the API's telemetry worker. */
export interface MonitoringRequestBody {
  deviceId: string;
  /** Legacy scalar — keep reading it (still present on every poll). */
  managementAddress: string;
  /** All known addresses, primary first. */
  ipAddresses?: DeviceAddress[];
  /** User-selected hardware model from the device row (null = not set). */
  model?: string | null;
  /** User-selected firmware version from the device row (null = not set). */
  firmwareVersion?: string | null;
  credentials: StepCredentials;
  /**
   * Window-based scheduling hint (API ≥ window-scheduler release): true only on
   * INVENTORY-due polls. When false/absent, skip slow/static collection and
   * OMIT the inventory metric keys from `metrics` — an absent key never wipes
   * stored rows, so metrics-only polls are safe by contract. Old API versions
   * omit this field entirely; treat absent as "collect everything" for
   * backward compatibility with pre-scheduler APIs.
   */
  collectInventory?: boolean;
}

/** Response of POST /monitoring — the API reads exactly these three fields. */
export interface MonitoringResponseBody {
  health?: Health;
  metrics?: Record<string, unknown>;
  metricDescriptors?: MetricDescriptor[];
}

// ---------------------------------------------------------------------------
// Wire shapes — POST /config (API -> plugin). TWO request shapes coexist:
//   A) legacy config job:      { action, payload }        (15s timeout)
//   B) plan step:              { actionId, input }        (catalog timeoutMs or 60s)
// Plugins accept both via `actionId ?? action`, `input ?? payload`.
// ---------------------------------------------------------------------------

/** Body of POST /config (both shapes). */
export interface ConfigRequestBody {
  deviceId?: string;
  managementAddress: string;
  ipAddresses?: DeviceAddress[];
  credentials: StepCredentials;
  /** Shape B (preferred): registry action id + validated input. */
  actionId?: string;
  input?: Record<string, unknown>;
  /** Shape A (legacy config job). */
  action?: string;
  payload?: Record<string, unknown>;
}

/** Response of POST /config — the API marks a job failed only when success === false. */
export interface ConfigResponseBody {
  success?: boolean;
  result?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Device state — GET /state (API -> plugin), advertised via capability 'deviceState'
// The webapp's per-device Config page renders this document verbatim: sections
// of items (ports with live states, interfaces, ZFS pools, system info) plus
// context-aware action references. Plugins own the shape; the API brokers it
// without interpreting content and only validates that referenced action ids
// exist in the plugin's persisted action catalog.
// ---------------------------------------------------------------------------

/** Body of GET /state as sent by the API broker (same credential model as /monitoring). */
export interface StateRequestBody {
  deviceId: string;
  managementAddress: string;
  ipAddresses?: DeviceAddress[];
  /** User-selected hardware model from the device row (null = not set). */
  model?: string | null;
  firmwareVersion?: string | null;
  credentials: StepCredentials;
}

/** A reference to an executable action of this plugin's catalog. */
export interface StateActionRef {
  /** Must match an id in the plugin's /discover `actions` (deviceCount 1). */
  actionId: string;
  /** Pre-filled input values (e.g. `{ port: 5 }`) — merged under schema defaults. */
  prefill?: Record<string, unknown>;
}

/** One row of a state section — e.g. a switch port or an appliance interface. */
export interface StateItem {
  /** Stable key within the section (e.g. 'P1', 'opt0'). */
  key: string;
  title: string;
  subtitle?: string | null;
  /** up | down | enabled | disabled | ok | degraded | critical — free string, rendered as a badge. */
  status?: string | null;
  /** Display fields (label-ready values; the webapp renders them verbatim). Arrays render as chip lists (e.g. per-port MACs). */
  fields: Record<string, string | number | null | unknown[]>;
  /** Actions applicable to this item (e.g. shutdown port, set speed mode). */
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

/** Response of GET /state — the API returns it to the webapp verbatim. */
export interface DeviceStateResponse {
  collectedAt: string;
  sections: StateSection[];
}

// ---------------------------------------------------------------------------
// Inventory rows — arrays inside `metrics` consumed by the API's ingestInventory()
// (api/src/workers/telemetry.ts). Each key upserts on its natural key and
// deletes-on-absent when the key is present at all. Absent key = "plugin does
// not report this" — never wipes data.
// ---------------------------------------------------------------------------

/** `metrics['networks']` row → networks table, PK (deviceId, pluginId, name, ip). */
export interface NetworkRow {
  /** Interface/network label (required). */
  name: string;
  /** IP address ('' = interface without an IP — kept for topology detection). */
  ip?: string | null;
  /** CIDR prefix length. */
  prefix?: number | null;
  /** 'v4' | 'v6' (canonical values; the API also tolerates 'ipv4'/'ipv6'). */
  version?: string | null;
  vlanId?: number | null;
  mac?: string | null;
  status?: string | null;
}

/** `metrics['arp'|'ndp'|'dhcpLeases'|'wlanClients']` row → hosts table. */
export interface HostRow {
  /** MAC address (required, lowercased by the API). */
  mac: string;
  /** IP ('0.0.0.0'/'::' placeholders are skipped; empty allowed only for source 'mac'). */
  ip?: string;
  hostname?: string | null;
  manufacturer?: string | null;
  intf?: string | null;
  /** ISO expiry (DHCP leases). */
  expiry?: string | null;
}

/** `metrics['macTable']` row → hosts table with source 'mac' (IP-less allowed). */
export interface MacTableRow {
  mac: string;
  intf?: string | null;
}

/** `metrics['tunnels']` row → tunnels table, PK (deviceId, pluginId, name, type). */
export interface TunnelRow {
  name: string;
  /** wireguard | openvpn | ipsec | pppoe | gre (free string, lowercased by the API). */
  type: string;
  peerAddress?: string;
  localAddress?: string;
  subnet?: string | null;
  /** up | down | enabled | disabled | unknown. */
  status?: string;
  uptimeSeconds?: number | null;
  lastHandshakeSeconds?: number | null;
  interfaceName?: string | null;
  /** bytes/s (computed by the plugin from cumulative counters). */
  rxRate?: number | null;
  txRate?: number | null;
  extra?: Record<string, unknown>;
}

/** `metrics['routes']` row → routes table, PK (deviceId, pluginId, destination, protocol). */
export interface RouteRow {
  /** Destination CIDR (required). */
  destination: string;
  gateway?: string;
  /** static | connected | ospf | bgp | rip | other (unknown labels become 'other'). */
  protocol?: string;
  distance?: number | null;
  metric?: number | null;
  mtu?: number | null;
  status?: string;
  extra?: Record<string, unknown>;
}

/** `metrics['wifiNetworks']` row → wifi_ssids table, PK (deviceId, pluginId, name, band). */
export interface WifiNetworkRow {
  name: string;
  /** '2g' | '5g' | '6g'. */
  band: string;
  channel?: number | null;
  bssid?: string | null;
  encryption?: string | null;
  vlanId?: number | null;
  ifc?: string | null;
}

/** `metrics['wifiAirtime']` row → wifi_channels table, PK (deviceId, pluginId, channel). */
export interface WifiAirtimeRow {
  channel: number;
  utilizationPct?: number | null;
}

/** `metrics['wifiRadios']` row → wifi_radios table, PK (deviceId, pluginId, ifc). */
export interface WifiRadioRow {
  ifc: string;
  band?: string;
  channel?: number | null;
  bandwidthMhz?: number | null;
  noiseFloorDbm?: number | null;
}

/** `metrics['wifiNeighbors']` row → wifi_neighbors table, PK (deviceId, pluginId, bssid). */
export interface WifiNeighborRow {
  bssid: string;
  ssid?: string | null;
  band?: string;
  channel?: number | null;
  signalDbm?: number | null;
}

/** `metrics['ports']` row → device_ports table, PK (deviceId, pluginId, name). */
export interface PortRow {
  /** Port/interface label (required — e.g. 'P1', 'opt0', 'port 4'). */
  name: string;
  /** up | down | enabled | disabled | unknown (lowercased by the API). */
  status?: string;
  speed?: string | null;
  duplex?: string | null;
  vlanId?: number | null;
  poe?: string | null;
  extra?: Record<string, unknown>;
}

/** All inventory keys the API's ingestInventory() understands. */
export const INVENTORY_KEYS = [
  'networks',
  'arp',
  'ndp',
  'dhcpLeases',
  'wlanClients',
  'macTable',
  'tunnels',
  'routes',
  'wifiNetworks',
  'wifiAirtime',
  'wifiRadios',
  'wifiNeighbors',
  'ports',
] as const;
