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
  // Can browse + manage the device's filesystem over SFTP (see createSftpPool /
  // SftpSession). Advertise when the plugin serves POST /filesystem — a generic,
  // root-scoped file manager (list/read/write/mkdir/rename/delete) that the webapp
  // renders on the Storage page (dataset contents) and Containers page (volume
  // mounts). Like 'ssh', it rides the same bound 'ssh' credential slot. The plugin
  // owns what each path means (e.g. a dataset mountpoint or a container volume's
  // host source); the webapp only ever passes paths relative to that root.
  'filesystem',
  // Serves POST /probe — SHORT-CYCLE live telemetry (1–5 s cadence) for the
  // webapp's on-demand polling, as opposed to /monitoring which is the API's
  // background worker at a much slower beat. The caller selects WHICH probe
  // keys it wants via `keys` so a page only pays for what it renders (the
  // plugin decides how each key maps onto its data path and skips everything
  // else — no overload). Response is a free-form metrics map; the API brokers
  // it verbatim without interpreting content. Advertise when the plugin can
  // answer cheaply (cached connections, single read-only command, ...).
  'probe',
  // Serves an interactive SSH console over WebSocket (see makeConsoleUpgrade /
  // createTerminalPool in terminal.ts + consoleWs.ts). The webapp's DeviceDetail
  // page offers a "Shell" button and the Containers page a per-container console —
  // both open a full xterm.js terminal that talks to the device like PuTTY would.
  // Like 'ssh'/'filesystem', it rides the same bound 'ssh' credential slot; the
  // plugin owns what each `context` means (a host login shell, or an exec into a
  // container). The API brokers the WebSocket verbatim — credentials travel only
  // over the authenticated API→plugin hop, never to the browser.
  'sshConsole',
  // Gathers available updates for its devices (firmware, OS packages via package
  // manager, Docker images/apps) and emits them as `metrics['updates']` = UpdateRow[]
  // during inventory collection (see updates.ts). The webapp's Updates page renders
  // the cross-device table from this; applying an update is always a plan — each row
  // may carry applyActionId/applyInput pointing at THIS plugin's action catalog.
  'updates',
  // Runs per-appliance security checks (unsuccessful logins, important-file
  // integrity, active rate limiting / brute-force protection, …) and emits them
  // as `metrics['securityChecks']` = SecurityCheckRow[] during inventory
  // collection (see security.ts). The webapp's Security page renders the
  // cross-device findings table from this. Each plugin owns WHAT to check —
  // every appliance exposes these signals differently; only the result shape is
  // shared. Rows with status 'ok' are dropped by the API (findings-only table).
  'securityChecks',
  'secretsProvider',
  'identityProvider',
  // Reserved for future log-forwarder plugins (syslog daemon, OpenSearch, ...).
  // Regular plugins do NOT advertise this — they ship logs via createPluginLogger.
  'logIngestion',
  // Serves POST /quick-action — resolves a plugin-declared quick action of kind
  // 'url' into the device's management web-UI URL (see QuickAction + buildWebUiUrl).
  // The PLUGIN owns the URL knowledge (scheme, path); the API brokers the request
  // and never assembles URLs itself. Advertise when /discover carries quickActions
  // with at least one kind:'url' entry.
  'quickActions',
  // Keeps an EXTERNAL monitoring subsystem (Zabbix, Nagios, …) consistent with
  // UNM's host inventory. The API serves the authoritative snapshot through the
  // internal GET /plugin/inventory/hosts endpoint; the plugin reconciles it against
  // its external system and applies create/update/delete via a plan action. Each
  // monitoring system has different logic + settings, so the contract stays generic
  // (see InventorySnapshot) and ALL subsystem-specific mapping is owned by the
  // plugin through its own options + actions. Advertise when /discover carries an
  // inventory-sync action in `actions`.
  'inventorySync',
] as const;
export type PluginCapability = (typeof CAPABILITIES)[number];

// ---------------------------------------------------------------------------
// Quick actions (/discover `quickActions`, POST /quick-action) — the Devices
// page "Device Actions" column. A plugin propagates a small set of one-click
// shortcuts for its devices: open the management web UI, drop into an SSH shell,
// browse files, or run a catalog action with risk-based gating (read = instant,
  // write = confirm dialog, dangerous = never offered here).
// ---------------------------------------------------------------------------

/** The kind of shortcut a quick action performs. */
export type QuickActionKind = 'url' | 'shell' | 'files' | 'action';

/** One entry as advertised in /discover `quickActions`. */
export interface QuickAction {
  /** Stable id within this plugin's quick-action list (e.g. "webui", "shell"). */
  id: string;
  /** Label rendered on the button (e.g. "Web UI", "Shell", "Files"). */
  label: string;
  /** Tooltip / description shown in the menu. */
  description?: string;
  /**
   * Optional icon for this action, served from the plugin's static `/icons` dir
   * (same rules as `iconUrl`). The webapp renders it through the API icon proxy;
   * when absent, a generic per-kind glyph is shown instead.
   */
  iconPath?: string;
  kind: QuickActionKind;
  /**
   * kind 'url' — the plugin resolves this to a full URL via POST /quick-action
   * (it owns the scheme + path knowledge, e.g. `https://<host>/ui/`). The API
   * brokers the call and hands the URL to the browser verbatim.
   */
  url?: {
    /** Path appended to the resolved base (may be empty). */
    path?: string;
  };
  /** kind 'action' — id of a single-device entry in this plugin's action catalog. */
  actionId?: string;
  /** Pre-filled input values merged under the action schema defaults. */
  prefill?: Record<string, unknown>;
}

/** Body of POST /quick-action (API → plugin). Mirrors StateRequestBody minus credentials. */
export interface QuickActionRequestBody {
  deviceId: string;
  managementAddress: string;
  /** The quick-action id the caller clicked (must be one of the advertised ones). */
  actionId: string;
}

/** Response of POST /quick-action for kind 'url' entries. */
export interface QuickActionResponseBody {
  /** Fully resolved, browser-openable URL (scheme + host + port + path). */
  url: string;
}

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
  /**
   * Closed set of allowed values — the webapp renders a combobox (select)
   * instead of a free-text input, and the API rejects any value outside this
   * list. Use for mode/transport/method toggles; keep `pattern` only for
   * genuinely open-ended strings with format constraints.
   */
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
  /**
   * When false, the plan executor NEVER re-dispatches this action after a failed
   * attempt — even if the failure looks transient (device not ready yet) or the
   * plugin reports retryable:true. Set on power / firmware-flash / config-restore
   * actions where a re-dispatch would flap the device (e.g. reboot it twice).
   * Absent/true = the normal per-plan retry policy applies.
   */
  retryOnDispatchFailure?: boolean;
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

/** Per-plan retry override for FAILED plan steps (see ActionResult.retryable). */
export interface PlanRetryPolicy {
  /** Max dispatch attempts per step (0 = no retries, 1..10; default from global settings). */
  maxAttempts?: number;
  /** Wait between attempts in ms when the plugin gives no per-failure waitMs hint. */
  waitMs?: number;
}

/** The output of /plan: ordered, dependency-aware steps + credential requests. */
export interface Plan {
  id: string;
  createdAt: string;
  intentActionId: string;
  provisionRequests: ProvisionRequest[];
  steps: PlanStep[];
  /**
   * Optional per-plan retry policy the plugin wants for this plan — e.g.
   * `{ maxAttempts: 0 }` to DISABLE step retries for a critical intent where
   * every failure must surface immediately. The user's explicit choice at
   * creation time (or an edit before execution) wins over this; when neither is
   * set, the global settings apply. Omit it to inherit the defaults.
   */
  retryPolicy?: PlanRetryPolicy | null;
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

/** The result an action executor returns. `verified` = plugin re-read state post-apply.
 *
 * RETRY SEMANTICS (plan steps only): when `success` is false the UNM plan
 * executor decides whether to RE-DISPATCH this step based on:
 *   - `retryable: true`  → transient failure (appliance not ready yet, service
 *     still starting, container not up, …) — the step is retried per the plan's
 *     retry policy; omit/false = hard failure that fails the plan immediately.
 *   - `waitMs`           → suggested wait before the next attempt (e.g. minutes
 *     for an update to settle); wins over the policy default for this attempt.
 * A thrown error is a HARD failure by contract — return { success: false,
 * retryable: true } instead when you want the executor to retry.
 */
export interface ActionResult {
  success: boolean;
  applied?: boolean;
  verified?: boolean;
  details?: Record<string, unknown>;
  error?: string;
  /** Only meaningful with success=false — marks a TRANSIENT failure worth re-dispatching. */
  retryable?: boolean;
  /** Only meaningful with success=false + retryable=true — suggested wait before the next attempt (ms). */
  waitMs?: number;
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
// Wire shapes — POST /probe (API -> plugin), advertised via capability 'probe'
// Short-cycle live telemetry: the webapp polls on demand (1–5 s) through the
// API's generic broker (GET /v1/devices/:id/probe). Unlike /monitoring this is
// a LIVE read path — no DB writes, no worker. The plugin owns what each key
// means and how it collects it; `keys` lets the caller request only what it
// needs so an idle page never overloads the device or the plugin.
// ---------------------------------------------------------------------------

/** Body of POST /probe as sent by the API broker (same credential model as /monitoring). */
export interface ProbeRequestBody {
  deviceId: string;
  managementAddress: string;
  /** All known addresses, primary first. */
  ipAddresses?: DeviceAddress[];
  /** User-selected hardware model from the device row (null = not set). */
  model?: string | null;
  /** User-selected firmware version from the device row (null = not set). */
  firmwareVersion?: string | null;
  credentials: StepCredentials;
  /**
   * Which probe keys to collect. Absent/empty = the plugin's default set
   * (usually its cheapest key(s)). Unknown keys are ignored — plugins evolve
   * independently of callers, and a stale caller must not break a fresh one.
   */
  keys?: string[];
  /**
   * Optional container-name selection: when present, state-style probe keys
   * (e.g. `containerStates`) collect ONLY these containers instead of the full
   * set — lets a page watch a small subset at a tighter cadence without paying
   * for everything else. Absent/empty = no restriction (full collection).
   */
  names?: string[];
}

/** Response of POST /probe — the API broker returns it verbatim to the webapp. */
export interface ProbeResponseBody {
  /** ISO-8601 timestamp when the plugin collected this snapshot. */
  collectedAt: string;
  /** Free-form metrics map keyed by probe key (e.g. `containerStats`). Shape is plugin-owned. */
  metrics: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Filesystem — POST /filesystem (API -> plugin), advertised via capability 'filesystem'
// A generic, root-scoped file manager over SFTP. The webapp's Storage page (dataset
// contents) and Containers page (volume mounts) drive it through the API broker.
// The caller passes a `context` describing WHAT to browse (a dataset, a container
// volume, …); the plugin maps that context onto an SFTP root and confines every path
// to it — so a webapp-supplied relative path can never walk out of the scoped tree.
// ---------------------------------------------------------------------------

/** One file/directory entry as reported by POST /filesystem `list`. */
export interface FilesystemEntry {
  /** Entry name (basename, no leading/trailing slash). */
  name: string;
  isDirectory: boolean;
  sizeBytes: number | null;
  mtimeMs: number | null;
}

/** The file operation to perform. Read ops are non-mutating; the rest change device state. */
export type FilesystemOp = 'list' | 'read' | 'stat' | 'write' | 'mkdir' | 'rmdir' | 'unlink' | 'rename';

/** Body of POST /filesystem as sent by the API broker (same credential model as /probe). */
export interface FilesystemRequestBody {
  deviceId: string;
  managementAddress: string;
  ipAddresses?: DeviceAddress[];
  /** User-selected hardware model from the device row (null = not set). */
  model?: string | null;
  /** User-selected firmware version from the device row (null = not set). */
  firmwareVersion?: string | null;
  credentials: StepCredentials;
  /** The operation to perform. */
  op: FilesystemOp;
  /** Path WITHIN the scoped root (relative, or absolute when the plugin allows it).
   *  For `rename` this is the SOURCE path. Empty/absent = the root itself (for list/stat). */
  path?: string;
  /** Destination path for `rename`. */
  targetPath?: string;
  /** File contents for `write`, base64-encoded (binary-safe). */
  contentBase64?: string;
  /** For `mkdir`: create intermediate directories as needed. */
  parents?: boolean;
  /** Plugin-owned context describing what to browse — the plugin maps this onto an
   *  SFTP root and validates it. E.g. `{ kind: 'dataset', name }` or
   *  `{ kind: 'container-volume', source, target? }`. The webapp never passes raw
   *  device-internal paths for datasets; it names the dataset and lets the plugin resolve it. */
  context?: Record<string, unknown>;
}

/** Response of POST /filesystem — the API broker returns it verbatim to the webapp. */
export interface FilesystemResponseBody {
  /** ISO-8601 timestamp when the plugin performed this operation. */
  collectedAt: string;
  /** The absolute path that was operated on (after root resolution) — for list/stat/read. */
  path?: string;
  /** For `list`: the directory's entries. */
  entries?: FilesystemEntry[];
  /** For `read`: file contents, base64-encoded. */
  contentBase64?: string;
  /** For `read`/`stat`: metadata. */
  sizeBytes?: number | null;
  mtimeMs?: number | null;
  isDirectory?: boolean;
}

// ---------------------------------------------------------------------------
// SSH console — WebSocket (API -> plugin), advertised via capability 'sshConsole'
// An interactive terminal over SSH: the webapp's xterm.js talks to the API, which
// proxies VERBATIM to the plugin's /console endpoint. BINARY frames are raw
// terminal I/O both directions; TEXT frames carry ConsoleControlMessage JSON.
// The FIRST text frame from the API is a ConsoleHelloFrame with fresh credentials —
// the plugin maps `context` onto an SshTerminalSession (host shell or container exec).
// ---------------------------------------------------------------------------

/** First text frame the API sends to the plugin's /console endpoint after upgrade. */
export interface ConsoleHelloFrame {
  deviceId: string;
  /** The device address as registered (may carry a scheme — strip it for SSH). */
  managementAddress: string;
  /** All known addresses, primary first. */
  ipAddresses?: DeviceAddress[];
  /** Fresh decrypted credentials (primary + bound slots) — same shape as /monitoring. */
  credentials: StepCredentials;
  /** Plugin-owned context naming WHAT to attach to. E.g. `{ kind: 'host' }` for a
   *  login shell, or `{ kind: 'container', name?, service? }` for an exec into a
   *  container (the plugin resolves the docker name + entrypoint). */
  context?: Record<string, unknown>;  /** The assignment's effective plugin settings (defaults ⊕ overrides) — lets onOpen()
   *  resolve per-device options such as a non-default SSH port. Absent on older APIs. */
  settings?: Record<string, unknown>;}

/** Control messages carried in TEXT frames on the console WebSocket. */
export type ConsoleControlMessage =
  | { type: 'ready' }
  | { type: 'resize'; cols: number; rows: number }
  | { type: 'exit'; code: number }
  | { type: 'error'; message: string }
  | { type: 'closed' };

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

// ---------------------------------------------------------------------------
// Inventory sync (capability 'inventorySync') — the API serves UNM's host
// inventory to a plugin so it can keep an EXTERNAL monitoring subsystem in
// step. The contract is deliberately SUBSYSTEM-AGNOSTIC: the snapshot below is
// plain data about UNM hosts; how that maps onto Zabbix/Nagios/… (host names,
// groups, templates, IPs, status semantics) is 100% plugin-owned via its own
// options + actions. The API never interprets it — it only brokers the read.
// ---------------------------------------------------------------------------

/** One IP address of a host in the inventory snapshot. */
export interface InventoryHostAddress {
  /** Bare IPv4/IPv6 literal (no scheme, no port). */
  address: string;
  /** Documented (expected) MAC when known — "aa:bb:cc:dd:ee:ff", else null. */
  mac?: string | null;
  /** Network label the user associated with this address (free-form or a canonical network key), else null. */
  networkLabel?: string | null;
  /** VLAN id when known, else null. */
  vlanId?: number | null;
}

/** One host in the inventory snapshot — documented hosts and/or live observations merged. */
export interface InventoryHost {
  /** Stable UNM identifier: the documented_hosts.id when the host is user-documented, else a synthetic "live:<mac|ip>" key. */
  id: string;
  /** Primary display name (first DNS name of a documented host, or observed hostname / IP for live-only hosts). */
  name: string;
  /** All known DNS names / FQDNs (documented hosts); empty array for live-only hosts. */
  dnsNames?: string[];
  /** Friendly name (documented hosts), else null. */
  friendlyName?: string | null;
  /** Free-form description, else null. */
  description?: string | null;
  /** User-assigned tags, else empty array. */
  tags?: string[];
  /** Site id the host is placed in (documented hosts), else null. */
  siteId?: string | null;
  /** Topology layer id (documented hosts), else null. */
  layerId?: string | null;
  /** User-maintained lifecycle flag: true = active, false = stale/retired. Live-only hosts are always active. */
  isActive: boolean;
  /** True when the host is a user-documented record (documented_hosts row); false for live-observation-only hosts. */
  documented: boolean;
  /** All known IP addresses of this host (documented + observed, deduped). */
  addresses: InventoryHostAddress[];
  /** ISO timestamp when the host was last seen in the live inventory (null = never observed / documentation only). */
  lastSeenAt?: string | null;
}

/** The authoritative UNM host-inventory snapshot served by GET /plugin/inventory/hosts. */
export interface InventorySnapshot {
  /** ISO-8601 timestamp when the API assembled this snapshot. */
  collectedAt: string;
  /** All hosts matching the request filters (see InventoryHostsQuery). */
  hosts: InventoryHost[];
}

/** Query parameters of GET /plugin/inventory/hosts (all optional, AND-combined). */
export interface InventoryHostsQuery {
  /** Only documented hosts (documented_hosts rows); omit/false = include live observations too. */
  documentedOnly?: boolean;
  /** Only active hosts (isActive=true); omit/false = include inactive ones as well. */
  activeOnly?: boolean;
  /** Case-insensitive substring filter on name / DNS names / IPs. */
  search?: string;
}

/** Response of the API's internal GET /plugin/inventory/hosts endpoint. */
export interface InventoryHostsResponse {
  snapshot: InventorySnapshot;
}
