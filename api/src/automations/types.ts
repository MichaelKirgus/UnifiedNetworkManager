/**
 * Actions & Schedules (automation engine) — block types.
 *
 * A rule ("automation") is ITTT-shaped: a list of TRIGGER blocks and a list of
 * ACTION blocks. When any trigger fires, the actions run sequentially and one
 * `automation_runs` row records the outcome. The DB stores both lists as opaque
 * JSON TEXT (see schema.automations) so new block types can be added without a
 * migration — this module is the single source of truth for their shapes, and
 * `validateAutomationDraft()` in engine.ts enforces them at write time.
 */

/**
 * Which devices a trigger/action applies to. Same "any rule matches" semantics
 * as user deviceScope: a device qualifies when it matches ANY provided list —
 * by site id, tag (exact match on the device's tags array) or explicit id.
 * An empty scope `{}` = every device.
 */
export interface DeviceScope {
  siteIds?: string[];
  tags?: string[];
  deviceIds?: string[];
}

// ── Trigger blocks ───────────────────────────────────────────────────────────

/** Schedule kinds: cron expression, fixed interval or daily wall-clock time. */
export type ScheduleSpec =
  | { kind: 'cron'; expr: string }
  | { kind: 'interval'; everyMinutes: number }
  | { kind: 'dailyAt'; time: string }; // "HH:MM" (24h, server local time)

export interface ScheduleTrigger {
  id: string;
  type: 'schedule';
  schedule: ScheduleSpec;
}

/** Metric comparison operators (numeric). */
export const METRIC_COMPARATORS = ['>', '>=', '<', '<=', '=', '!='] as const;
export type MetricComparator = (typeof METRIC_COMPARATORS)[number];

/**
 * Fires when a telemetry metric of matching device/plugin assignments meets a
 * condition. Evaluated against the LATEST telemetry row per assignment on each
 * worker tick; `durationSec` > 0 requires the condition to hold continuously for
 * that long (sustained-condition window, tracked in automation_state).
 */
export interface MetricTrigger {
  id: string;
  type: 'metric';
  scope?: DeviceScope;
  pluginId?: string;
  /** Dot-notation metric key as it appears in the telemetry metrics blob. */
  metricKey: string;
  mode: 'compare' | 'regex';
  /** Required when mode = 'compare'. */
  comparator?: MetricComparator;
  /** Required when mode = 'compare' — numeric (or string for '='/'!='). */
  value?: number | string;
  /** Required when mode = 'regex' — JS regex source, search semantics. */
  pattern?: string;
  /** Seconds the condition must hold before firing (0/absent = immediate). */
  durationSec?: number;
}

/** Log levels a log trigger can filter on (plugin_logs.level values). */
export const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

/**
 * Fires when NEW log rows appear since the last evaluation (watermark in
 * automation_state) whose message matches `pattern` (JS regex, search).
 * source 'plugin' scans plugin_logs (emittedAt axis); 'firewall' scans
 * firewall_events (tsMs epoch-ms axis). Bounded to 5000 rows per tick.
 */
export interface LogTrigger {
  id: string;
  type: 'log';
  source: 'plugin' | 'firewall';
  scope?: DeviceScope;
  pluginId?: string;
  /** Only these levels (absent = all). */
  levels?: LogLevel[];
  pattern: string;
}

/** Device status values (devices.status — see telemetry.ts deriveDeviceStatus). */
export const DEVICE_STATUSES = ['unknown', 'online', 'degraded', 'critical', 'offline'] as const;
export type DeviceStatus = (typeof DEVICE_STATUSES)[number];

/**
 * Fires when a device in scope transitions INTO one of `toStatuses`. Hooked at
 * the commit point of updateDeviceStatus() (post-hysteresis), so it reflects
 * the settled status, not transient probe noise.
 */
export interface DeviceStatusTrigger {
  id: string;
  type: 'deviceStatus';
  scope?: DeviceScope;
  toStatuses: DeviceStatus[];
}

/**
 * Fires on UPDATE transitions in device_updates (the Updates page's data): a
 * row appearing (a new update became available), its latestVersion advancing,
 * or the row disappearing (update applied / withdrawn). Hooked at
 * ingestUpdates()' commit point, so it reflects the settled per-poll state —
 * transition-only firing, never re-firing on every poll while an update stays
 * listed. `condition` selects which transitions fire:
 *   - 'available' → a row appeared (or advanced while a deferred window is open)
 *   - 'resolved'  → a row disappeared (update applied or withdrawn)
 * `defer` optionally holds each firing until the next occurrence of its
 * schedule spec (e.g. a nightly maintenance window); `maxWaitHours` caps how
 * long an event waits before firing immediately. While an 'available' window is
 * pending, the row disappearing cancels it silently and a version advance
 * refreshes the stored snapshot without moving the window start.
 */
export interface UpdateTrigger {
  id: string;
  type: 'updateAvailable';
  scope?: DeviceScope;
  pluginId?: string;
  /** Only these device_updates.kind values (absent = all). Free-form — plugins may emit custom kinds. */
  kinds?: string[];
  /** Exact row names to match (absent/empty = all). */
  names?: string[];
  /** JS regex source matched against the row name (search semantics). */
  namePattern?: string;
  condition: 'available' | 'resolved';
  /** Only rows whose rebootRequired flag EQUALS this value (rows with a null flag never match a filter — unknown ≠ safe to auto-apply). */
  rebootRequired?: boolean;
  defer?: { schedule: ScheduleSpec; maxWaitHours?: number };
}

/** Flow direction a flow trigger watches (either endpoint of an observed tuple). */
export const FLOW_DIRECTIONS = ['any', 'src', 'dst'] as const;
export type FlowDirection = (typeof FLOW_DIRECTIONS)[number];

/** Endpoint classification filter for flow triggers (flow_agg_* "srcClass"/"dstClass"). */
export const FLOW_CLASSES = ['internal', 'internet', 'unknown'] as const;
export type FlowClass = (typeof FLOW_CLASSES)[number];

/**
 * Fires when network traffic observed by the flow collector crosses a threshold.
 * Evaluated against the AGGREGATE tables (flow_agg_5m / flow_agg_1h) over a
 * sliding window ending at each tick: `windowSec` of buckets are summed per
 * endpoint tuple and compared with `comparator`/`thresholdBytes`. The trigger
 * fires when ANY in-scope tuple meets the condition; `durationSec` > 0 requires
 * it to hold for that long (sustained window, same semantics as metric triggers).
 * Scope matches against whichever endpoint device is known (src preferred); a
 * tuple with no known device only matches an empty scope.
 */
export interface FlowTrigger {
  id: string;
  type: 'flow';
  scope?: DeviceScope;
  /** Which endpoint to measure ('any' = either side of the tuple). */
  direction?: FlowDirection;
  /** Only endpoints classified as this (absent = all classes). */
  endpointClass?: FlowClass;
  /** Optional exact-IP filter on the measured endpoint. */
  ip?: string;
  /** Sliding window length in seconds (default 300, capped at one hour). */
  windowSec?: number;
  comparator: MetricComparator;
  thresholdBytes: number;
  /** Seconds the condition must hold before firing (0/absent = immediate). */
  durationSec?: number;
}

/**
 * Fires when NEW lines appear in a container's log output. The worker tails the
 * app's containers through the plugin's `containers.logs.read` action (the same
 * read path the Containers page uses) and compares each line against the set of
 * previously-seen lines for this trigger (content hash, capped ring buffer in
 * automation_state). A null watermark = first run: only NEW lines after that are
 * considered, so a freshly created rule doesn't fire on the whole tail history.
 */
export interface ContainerLogTrigger {
  id: string;
  type: 'containerLog';
  scope?: DeviceScope;
  /** Plugin providing `containers.logs.read` (ix-truenas or docker). */
  pluginId: string;
  /** App / container name as it appears in the Containers page. */
  appName: string;
  /** Trailing lines to tail on each evaluation (20–5000, default 300). */
  tail?: number;
  /** JS regex source (search semantics) matched against each new line. */
  pattern: string;
}

export type TriggerBlock = ScheduleTrigger | MetricTrigger | LogTrigger | DeviceStatusTrigger | FlowTrigger | ContainerLogTrigger | UpdateTrigger;

// ── Action blocks ────────────────────────────────────────────────────────────

/** Notification severities (notifications.severity values). */
export const NOTIFICATION_SEVERITIES = ['info', 'warning', 'critical'] as const;
export type NotificationSeverity = (typeof NOTIFICATION_SEVERITIES)[number];

/**
 * Runs a plugin intent action on the resolved devices by creating + enqueuing a
 * plan (the same path the webapp's CreatePlan dialog uses — see
 * utils/createPlanCore.ts). `input` is validated against the catalog entry's
 * inputSchema in the UI; the engine passes it through verbatim.
 *
 * With `resolveFromTrigger: 'update'`, pluginId/actionId/input are filled at
 * fire time from the firing update row's apply path (device_updates.applyActionId
 * / applyInput) — for rules that react to updateAvailable triggers without
 * hardcoding a per-plugin action id. A row with no apply path skips the action
 * with a logged reason (never guessed). `requireNoReboot` additionally skips
 * execution when the firing row's rebootRequired flag is true.
 */
export interface IntentAction {
  id: string;
  type: 'intent';
  /** Required unless resolveFromTrigger fills it at fire time. */
  pluginId?: string;
  /** Catalog action id (plugins.actionDescriptors). Required unless resolveFromTrigger fills it. */
  actionId?: string;
  devices: { scope?: DeviceScope; deviceIds?: string[] };
  input?: Record<string, unknown>;
  /** Fill pluginId/actionId/input from the firing update row's apply path. */
  resolveFromTrigger?: 'update';
  /** Skip execution when the firing update row requires a reboot (default off). */
  requireNoReboot?: boolean;
}

/**
 * POSTs/GETs a JSON payload to an external endpoint. http(s) only, 10 s
 * timeout (see engine/webhook.ts). `bodyTemplate` supports {{…}} tokens and is
 * rendered as the request body (JSON object or raw string); headers are static
 * in v1 — no secret refs yet.
 */
export interface WebhookAction {
  id: string;
  type: 'webhook';
  url: string;
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH';
  headers?: Record<string, string>;
  bodyTemplate?: string;
}

/**
 * Emits a UNM notification (bell + Notifications page). Templates support {{…}}
 * tokens. dedupeKey is fixed per rule+action so repeated firings update the
 * same open notification instead of spamming one row per firing.
 */
export interface NotificationAction {
  id: string;
  type: 'notification';
  severity: NotificationSeverity;
  titleTemplate: string;
  messageTemplate: string;
}

/** Backup presets (must stay in sync with PRESETS in backup.ts). */
export const BACKUP_PRESETS = ['config', 'planned', 'all'] as const;
export type BackupPreset = (typeof BACKUP_PRESETS)[number];

/**
 * Runs an internal UNM operation: a section-based backup of this instance's own
 * database, or a sync push to one replication target. No 2FA gate — these are
 * read-only-from-the-fleet operations on UNM itself, same class as the
 * auto-backup worker.
 */
export interface InternalAction {
  id: string;
  type: 'internal';
  kind: 'backup' | 'replicationSync';
  /** backup only: preset (default 'config') or explicit section list. */
  preset?: BackupPreset;
  sections?: string[];
  /** backup only: 'local' (default) or 'repo'. */
  destination?: 'local' | 'repo';
  /** replicationSync only: replication_targets.id. */
  targetId?: string;
}

export type ActionBlock = IntentAction | WebhookAction | NotificationAction | InternalAction;

// ── Rule + run shapes (as stored / as served by the API) ─────────────────────

/** A rule as persisted in automations (triggers/actions are parsed JSON). */
export interface Automation {
  id: string;
  name: string;
  description?: string | null;
  enabled: boolean;
  triggers: TriggerBlock[];
  actions: ActionBlock[];
  cooldownSec: number;
  lastFiredAt: string | null; // ISO timestamp (null = never fired)
  createdBy?: string | null;
  createdAt: string;
  updatedAt: string;
}

/** Payload accepted by POST /automations and PATCH /automations/:id. */
export interface AutomationDraft {
  name: string;
  description?: string | null;
  enabled?: boolean;
  triggers: TriggerBlock[];
  actions: ActionBlock[];
  cooldownSec?: number;
}

/** One row per firing (automation_runs). */
export interface AutomationRun {
  id: string;
  automationId: string;
  firedAt: string; // ISO timestamp
  triggerType: TriggerBlock['type'];
  /** Trigger context at firing time — device/metric/log details for display. */
  context: Record<string, unknown>;
  /** 'skipped' = every action was deliberately skipped (e.g. requireNoReboot guard). */
  status: 'succeeded' | 'failed' | 'partial' | 'skipped';
  error?: string | null;
  planIds: string[];
}

/** Context passed to action execution when a trigger fires (template vars). */
export interface TriggerContext {
  /** The block that fired. */
  trigger: TriggerBlock;
  /** Device the event was about, when applicable (name/address for templates). */
  device?: { id: string; name: string; address?: string | null } | null;
  /** Metric key/value snapshot, for metric triggers. */
  metric?: { key: string; value: number | string | boolean | null } | null;
  /** Log message, for log triggers (and container-log triggers). */
  logMessage?: string | null;
  /** Flow tuple + measured bytes, for flow triggers. */
  flow?: { ip: string; estBytes: number; windowSec: number; direction: string } | null;
  /** Update row snapshot at firing time, for updateAvailable triggers ({{update.*}} tokens). */
  update?: {
    kind: string;
    name: string;
    currentVersion: string | null;
    latestVersion: string | null;
    rebootRequired: boolean | null;
    /** The row's owning assignment — intent actions target exactly this device. */
    deviceId: string;
    pluginId: string;
    /** Apply path declared by the plugin (null/absent = manual on device, never guessed). Absent for 'resolved' firings of rows that are already gone. */
    applyActionId?: string | null;
    applyInput?: Record<string, unknown>;
  } | null;
}
