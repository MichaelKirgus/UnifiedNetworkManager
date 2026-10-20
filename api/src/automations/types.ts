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

export type TriggerBlock = ScheduleTrigger | MetricTrigger | LogTrigger | DeviceStatusTrigger;

// ── Action blocks ────────────────────────────────────────────────────────────

/** Notification severities (notifications.severity values). */
export const NOTIFICATION_SEVERITIES = ['info', 'warning', 'critical'] as const;
export type NotificationSeverity = (typeof NOTIFICATION_SEVERITIES)[number];

/**
 * Runs a plugin intent action on the resolved devices by creating + enqueuing a
 * plan (the same path the webapp's CreatePlan dialog uses — see
 * utils/createPlanCore.ts). `input` is validated against the catalog entry's
 * inputSchema in the UI; the engine passes it through verbatim.
 */
export interface IntentAction {
  id: string;
  type: 'intent';
  pluginId: string;
  /** Catalog action id (plugins.actionDescriptors). */
  actionId: string;
  devices: { scope?: DeviceScope; deviceIds?: string[] };
  input?: Record<string, unknown>;
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
  status: 'succeeded' | 'failed' | 'partial';
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
  /** Log message, for log triggers. */
  logMessage?: string | null;
}
