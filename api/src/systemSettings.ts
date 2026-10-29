import { db, pool } from './db';
import { parseCidrList } from './utils/ipClassification';

/**
 * Central registry of runtime-tunable system settings (the Settings page).
 *
 * These are the app-wide knobs that are NOT plugin- or device-specific: data
 * retention windows, session/timeout behaviour, worker cadence and execution
 * budgets. Values live in the `system_settings` table as key/value rows so they
 * survive restarts and are shared across API replicas. A stored value always
 * wins over the env default for that knob; workers read them through a short-TTL
 * cache on every beat, so changes take effect without a restart.
 *
 * The registry (SETTING_DESCRIPTORS) is the single source of truth: it drives
 * validation/clamping, the Settings page UI (labels, help text, limits), and —
 * for entries flagged `exposeToPlugins` — the values injected into plugins via
 * the `x-unm-global-settings` header.
 */

export type SettingType = 'integer' | 'string' | 'boolean';
export type SettingValue = number | string | boolean;

/** One tunable setting, fully described for validation + UI rendering. */
export interface SettingDescriptor {
  /** Stable key — the `system_settings.key` column and the wire name. */
  key: string;
  /** Human-friendly display name shown in the Settings page. */
  label: string;
  type: SettingType;
  /** Grouping used to order/section the Settings table (e.g. "Retention"). */
  category: string;
  /** Help text describing what the setting does — shown when a row is expanded. */
  help: string;
  /** Fallback value when no env var or stored override applies. */
  default: number | string | boolean;
  /** Optional deployment-level default (env var name); wins over `default`. */
  envVar?: string;
  min?: number;
  max?: number;
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  /** Display unit hint for the UI ("ms", "s", "days", "%"). */
  unit?: string;
  /** When true, this value is injected into plugins via x-unm-global-settings. */
  exposeToPlugins?: boolean;
  /**
   * Optional side-effect hook fired AFTER a successful update/reset of THIS
   * setting (e.g. re-rendering the CA config from the new values). Failures are
   * logged, never propagated — the settings write itself already succeeded.
   */
  onChange?: () => Promise<void> | void;
  /**
   * Optional structured validation for string settings that a regex cannot
   * express (e.g. comma-separated CIDR lists). Called with the coerced value
   * AFTER pattern/length checks; throwing rejects the update with a 400.
   */
  validate?: (value: string) => void;
}

/** A setting as presented to the Settings page (effective value + metadata). */
export interface SettingView {
  key: string;
  label: string;
  type: SettingType;
  category: string;
  help: string;
  unit?: string;
  /** Effective value (stored override ⊕ env default), already clamped. */
  value: SettingValue;
  /** What the value reverts to on reset — i.e. the env/default baseline. */
  defaultValue: SettingValue;
  /** True when a stored override differs from the baseline. */
  isModified: boolean;
  min?: number;
  max?: number;
  pattern?: string;
}

// --- The registry -----------------------------------------------------------

export const SETTING_DESCRIPTORS: SettingDescriptor[] = [
  // Instance identity.
  {
    key: 'instanceName',
    label: 'Instance name',
    type: 'string',
    category: 'General',
    default: 'UnifiedNetworkManager',
    envVar: 'UNM_INSTANCE_NAME',
    minLength: 1,
    maxLength: 64,
    help:
      'Display name for this UNM instance. Shown in the webapp window title (browser tab) and on the login page — useful when several instances are open side by side.',
  },

  // Scheduled auto-backup (leader-gated worker; see api/src/workers/autoBackup.ts).
  {
    key: 'autoBackupEnabled',
    label: 'Auto-backup enabled',
    type: 'boolean',
    category: 'General',
    default: false,
    help:
      'When on, the instance creates a backup automatically at the configured interval (leader-gated worker). The archive is named auto-backup-<preset>-<date> and appears in the Backups list like any manual one. Off by default — enable it from Settings or the first-run wizard.',
  },
  {
    key: 'autoBackupIntervalMinutes',
    label: 'Auto-backup interval',
    type: 'integer',
    category: 'General',
    unit: 'min',
    min: 15,
    max: 7 * 24 * 60,
    default: 24 * 60,
    help:
      'How often the auto-backup worker creates a new archive (minimum 15 minutes, maximum one week). A backup is due when no auto-backup-<preset>-* row exists from within this window — so it self-heals after downtime or manual deletes.',
  },
  {
    key: 'autoBackupPreset',
    label: 'Auto-backup preset',
    type: 'string',
    category: 'General',
    default: 'config',
    pattern: '^(config|planned|all)$',
    help:
      'Which sections the scheduled backup archives. config = identity+settings+devices, planned = documented networks/hosts + plans, all = everything including live inventory.',
  },
  {
    key: 'autoBackupDestination',
    label: 'Auto-backup destination',
    type: 'string',
    category: 'General',
    default: 'local',
    pattern: '^(local|repo)$',
    help:
      'Where scheduled backups are stored: the local docker volume (unm-backups) or a file-repo plugin instance (see autoBackupProviderId).',
  },
  {
    key: 'autoBackupProviderId',
    label: 'Auto-backup file-repo instance',
    type: 'string',
    category: 'General',
    default: '',
    maxLength: 128,
    help:
      'Full plugin id of the file-repo instance that receives scheduled backups — only used when autoBackupDestination is "repo". Empty = local volume.',
  },

  // Actions & Schedules (automation engine; see workers/automations.ts). Master
  // switch for the whole feature — off = no trigger evaluation at all.
  {
    key: 'automationsEnabled',
    label: 'Actions & Schedules enabled',
    type: 'boolean',
    category: 'General',
    default: true,
    help:
      'Master switch for the automation engine (the Actions & Schedules page). When off, no triggers are evaluated and no rules fire — existing rules keep their state and resume when re-enabled.',
  },

  // Telemetry / worker cadence (previously the only tunable knobs, on the Workers page).
  {
    key: 'telemetryPollIntervalMs',
    label: 'Metrics poll window',
    type: 'integer',
    category: 'Telemetry',
    unit: 'ms',
    min: 5_000,
    max: 3_600_000,
    default: 30_000,
    envVar: 'TELEMETRY_POLL_INTERVAL_MS',
    exposeToPlugins: true,
    help:
      'How often each device is polled for live metrics (/monitoring). Every device is polled at least once within this window — deadlines are staggered so polls spread out instead of bursting. Takes effect on the next beat; no restart.',
  },
  {
    key: 'telemetryInventoryWindowMs',
    label: 'Inventory refresh window',
    type: 'integer',
    category: 'Telemetry',
    unit: 'ms',
    min: 30_000,
    max: 12 * 60 * 60_000,
    default: 15 * 60_000,
    envVar: 'TELEMETRY_INVENTORY_WINDOW_MS',
    help:
      'How often the slow/static collection (networks, routes, WiFi clients, storage, …) runs. Metrics-only polls in between are cheap; raise this to reduce load on busy appliances.',
  },
  {
    key: 'telemetryMaxConcurrency',
    label: 'Max concurrent polls',
    type: 'integer',
    category: 'Telemetry',
    min: 1,
    max: 2_000,
    default: 64,
    envVar: 'TELEMETRY_MAX_CONCURRENCY',
    help:
      'Global in-flight /monitoring budget across all devices. Keeps the burst flat regardless of fleet size; raise for fast fleets or lower to be gentler on appliances.',
  },
  {
    key: 'telemetryJitterPercent',
    label: 'Deadline jitter',
    type: 'integer',
    category: 'Telemetry',
    unit: '%',
    min: 0,
    max: 90,
    default: 20,
    envVar: 'TELEMETRY_JITTER_PERCENT',
    help:
      'Random spread (±%) applied to each rescheduled poll deadline so devices do not re-align into synchronized bursts.',
  },

  // Data retention.
  {
    key: 'logRetentionDays',
    label: 'Log retention',
    type: 'integer',
    category: 'Retention',
    unit: 'days',
    min: 1,
    max: 365,
    default: 7,
    envVar: 'LOG_RETENTION_DAYS',
    help:
      'How many days of plugin log entries are kept before the hourly retention sweep deletes them. Self-metrics samples share this window.',
  },
  {
    key: 'telemetryRetentionDays',
    label: 'Telemetry retention',
    type: 'integer',
    category: 'Retention',
    unit: 'days',
    min: 1,
    max: 365,
    default: 7,
    envVar: 'TELEMETRY_RETENTION_DAYS',
    help:
      'How many days of raw telemetry snapshots are kept. At a 30 s beat this table grows fast (≈1M rows/day per 200 devices), so keep it as short as your history needs allow.',
  },
  {
    key: 'firewallEventRetentionDays',
    label: 'Firewall event retention',
    type: 'integer',
    category: 'Retention',
    unit: 'days',
    min: 1,
    max: 365,
    default: 7,
    envVar: 'FIREWALL_EVENT_RETENTION_DAYS',
    help:
      'How many days of firewall event-log rows (blocked/allowed traffic events pushed by plugins) are kept before the hourly retention sweep deletes them.',
  },
  {
    key: 'hostStateRetentionDays',
    label: 'Host state snapshot retention',
    type: 'integer',
    category: 'Retention',
    unit: 'days',
    min: 1,
    max: 365,
    default: 7,
    envVar: 'HOST_STATE_RETENTION_DAYS',
    help:
      'How many days of per-host firewall state snapshots (open states + created/destroyed churn pushed by plugins) are kept before the hourly retention sweep deletes them. The Hosts/Networks pages show a 24h churn window, so 7 days leaves a week of history.',
  },
  {
    key: 'notificationRetentionDays',
    label: 'Notification retention',
    type: 'integer',
    category: 'Retention',
    unit: 'days',
    min: 1,
    max: 365,
    default: 30,
    envVar: 'NOTIFICATION_RETENTION_DAYS',
    help:
      'How many days terminal (resolved/closed) notifications are kept before the sweep prunes them. Active notifications are never pruned.',
  },
  {
    key: 'flowMicroRetentionDays',
    label: 'Flow micro retention',
    type: 'integer',
    category: 'Retention',
    unit: 'days',
    min: 1,
    max: 90,
    default: 7,
    envVar: 'FLOW_MICRO_RETENTION_DAYS',
    help:
      'How many days of raw (per-5s pre-aggregated) flow tuples are kept. Older weekly partitions are dropped instantly by the flows worker.',
  },
  {
    key: 'flowAgg5mRetentionDays',
    label: 'Flow 5-min aggregate retention',
    type: 'integer',
    category: 'Retention',
    unit: 'days',
    min: 1,
    max: 365,
    default: 30,
    envVar: 'FLOW_AGG_5M_RETENTION_DAYS',
    help:
      'How many days of enriched 5-minute flow aggregates are kept. These power the Flows page for recent history.',
  },
  {
    key: 'flowAgg1hRetentionDays',
    label: 'Flow hourly aggregate retention',
    type: 'integer',
    category: 'Retention',
    unit: 'days',
    min: 1,
    max: 730,
    default: 180,
    envVar: 'FLOW_AGG_1H_RETENTION_DAYS',
    help:
      'How many days of hourly flow aggregates are kept — the long-term trend tier.',
  },

  // Flow IP classification (Flows page). The internal/external range lists
  // replace the hardcoded RFC 1918 assumption so each deployment can define
  // its own "inside" (e.g. a CGNAT range, or a public block that is actually
  // your own infrastructure).
  {
    key: 'flowInternalRanges',
    label: 'Flow internal IP ranges',
    type: 'string',
    category: 'Flows',
    default: '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16',
    envVar: 'UNM_FLOW_INTERNAL_RANGES',
    maxLength: 4096,
    validate: (v) => { parseCidrList(v); }, // throws on a malformed CIDR → 400
    help:
      'Comma-separated IPv4 CIDR blocks classified as INTERNAL on the Flows page (default: RFC 1918 private space). Longest prefix wins; an IP matching a known device or network is always internal regardless of these lists. Add your own ranges here — e.g. "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10" for CGNAT space.',
  },
  {
    key: 'flowExternalRanges',
    label: 'Flow external IP ranges',
    type: 'string',
    category: 'Flows',
    default: '',
    envVar: 'UNM_FLOW_EXTERNAL_RANGES',
    maxLength: 4096,
    validate: (v) => { parseCidrList(v); }, // throws on a malformed CIDR → 400
    help:
      'Optional comma-separated IPv4 CIDR blocks classified as EXTERNAL (internet) even when they fall inside "Flow internal IP ranges" or an inventoried network — e.g. a public block you own but want counted as egress ("203.0.113.0/24"). Carve-outs beat the broad range/network matches, but an IP that is a known device (exact inventory hit) still counts as internal. Empty = no carve-outs.',
  },

  // Certificate monitoring (Certificates page).
  {
    key: 'certExpiryWarnDays',
    label: 'Certificate expiry warning window',
    type: 'integer',
    category: 'Security',
    unit: 'days',
    min: 1,
    max: 365,
    default: 30,
    envVar: 'CERT_EXPIRY_WARN_DAYS',
    help:
      'A certificate expiring within this many days raises a warning notification; an already-expired cert (or one whose issuer is expired) raises a critical one. The condition auto-resolves once the renewed cert is collected.',
  },
  {
    key: 'certPinningMode',
    label: 'Certificate pinning mode',
    type: 'string',
    category: 'Security',
    default: 'strict',
    envVar: 'CERT_PINNING_MODE',
    pattern: '^(strict|ignore)$',
    exposeToPlugins: true,
    help:
      'How plugins react when a device presents a DIFFERENT certificate or SSH host key than UNM has in its inventory. "strict" (default): the connection is refused and NO credentials are transmitted — a mismatch means re-keying OR an active man-in-the-middle; unknown endpoints are accepted once (TOFU) and pinned from then on. "ignore": legacy behavior, certificates are not verified against the inventory.',
  },

  // Security / session behaviour.
  {
    key: 'sessionTimeoutSeconds',
    label: 'Session timeout',
    type: 'integer',
    category: 'Security',
    unit: 's',
    min: 300,
    max: 604_800,
    default: 3_600,
    help:
      'How long a signed-in session (JWT) stays valid before the user must authenticate again. Applies to new logins; existing sessions keep their original expiry.',
  },
  {
    key: 'sessionWarnSeconds',
    label: 'Session warning lead time',
    type: 'integer',
    category: 'Security',
    unit: 's',
    min: 0,
    max: 3_600,
    default: 120,
    help:
      'How long BEFORE a session expires the web UI starts warning the user (amber banner with an "Extend" button). Set to 0 to disable the warning — the session then ends silently at its expiry. The countdown chip in the top bar is always shown.',
  },
  {
    key: 'apiRateLimitPerMinute',
    label: 'API rate limit (per client)',
    type: 'integer',
    category: 'Security',
    unit: 'req/min',
    min: 1,
    max: 10_000,
    default: 300,
    envVar: 'UNM_API_RATE_LIMIT_PER_MINUTE',
    help:
      'How many /v1 API requests one client (IP address) may make per rolling minute before the API answers 429 Too Many Requests. The webapp polls most pages every ~30 s, so several users behind one NAT share this budget — raise it if legitimate use trips the limit; lower it to be stricter against abuse. Login attempts have their own fixed, tighter limiter and are NOT affected by this setting. Takes effect immediately (5 s cache); no restart.',
  },
  {
    key: 'consoleTicketTtlMs',
    label: 'Console ticket lifetime',
    type: 'integer',
    category: 'Security',
    unit: 'ms',
    min: 10_000,
    max: 600_000,
    default: 60_000,
    help:
      'How long a single-use SSH console ticket stays valid before it is swept and rejected. Tickets are minted when the console opens; keep this short so an abandoned ticket cannot be replayed.',
  },

  // Execution budgets (also exposed to plugins).
  {
    key: 'planStepTimeoutMs',
    label: 'Plan step timeout',
    type: 'integer',
    category: 'Execution',
    unit: 'ms',
    min: 5_000,
    max: 3_600_000,
    default: 60_000,
    exposeToPlugins: true,
    help:
      'Default per-step dispatch timeout when a plan step runs against a plugin. Individual catalog actions may override this with their own timeoutMs.',
  },
  {
    key: 'planStepRetryMaxAttempts',
    label: 'Plan step retries (default)',
    type: 'integer',
    category: 'Execution',
    min: 0,
    max: 10,
    default: 2,
    exposeToPlugins: true,
    help:
      'Total dispatch attempts per FAILED plan step by default (initial + retries — e.g. 2 = one initial attempt plus one retry), applied only when the failure is TRANSIENT (the plugin reports retryable=true, or the dispatch itself timed out / could not reach the plugin). A hard failure (validation error, missing object, …) always fails the plan immediately. Individual plans can override this with their own retry policy; 1 disables step retries globally.',
  },
  {
    key: 'planStepRetryWaitMs',
    label: 'Plan step retry wait (default)',
    type: 'integer',
    category: 'Execution',
    unit: 'ms',
    min: 1_000,
    max: 3_600_000,
    default: 15_000,
    exposeToPlugins: true,
    help:
      'How long the executor waits between two attempts of a failed plan step (default policy). A plugin can suggest a longer wait per failure via ActionResult.waitMs — e.g. when an appliance needs minutes to settle after an update — and that hint wins over this value for that attempt.',
  },
  {
    key: 'pluginDispatchTimeoutMs',
    label: 'Plugin action timeout',
    type: 'integer',
    category: 'Execution',
    unit: 'ms',
    min: 5_000,
    max: 3_600_000,
    default: 30_000,
    help:
      'Timeout for ad-hoc single-device action dispatches (e.g. a notification "dismiss alert" button). Longer-running plan steps use the plan step timeout instead.',
  },

  // Discovery cadence.
  {
    key: 'discoveryPollIntervalMs',
    label: 'Plugin discovery interval',
    type: 'integer',
    category: 'Discovery',
    unit: 'ms',
    min: 10_000,
    max: 3_600_000,
    default: 60_000,
    envVar: 'PLUGIN_POLL_INTERVAL_MS',
    help:
      'How often the API polls configured plugin endpoints for discovery (the mDNS/DNS-SD fallback). A new or restarted plugin appears within one interval.',
  },

  // Stack self-update feed (Updates page "UNM itself" card + row). Defaults to
  // the official public GitHub releases endpoint so a fresh install checks for
  // UNM updates out of the box; set empty to disable, or point at your own
  // manifest. Accepts a bare manifest ({latestVersion, notesUrl}), a GitHub
  // /releases array, or a single GitHub release object (/releases/latest).
  {
    key: 'updateFeedUrl',
    label: 'Update feed URL',
    type: 'string',
    category: 'Updates',
    default: 'https://api.github.com/repos/MichaelKirgus/UnifiedNetworkManager/releases/latest',
    envVar: 'UNM_UPDATE_FEED_URL',
    maxLength: 2048,
    help:
      'HTTPS URL of a JSON release manifest for UNM itself. Defaults to the official public GitHub releases endpoint (…/releases/latest) so new installs check for updates automatically. Accepts a bare manifest {"latestVersion":"1.2.3","notesUrl":"https://…"}, a GitHub /releases array, or a single GitHub release object. Set empty to disable — then only current versions are shown and no update notification is raised.',
  },
  {
    key: 'updateFeedCheckIntervalMs',
    label: 'Update check interval',
    type: 'integer',
    category: 'Updates',
    unit: 'ms',
    min: 60_000,
    max: 86_400_000,
    default: 900_000,
    envVar: 'UNM_UPDATE_FEED_CHECK_INTERVAL_MS',
    help:
      'How often the API actively re-checks the update feed and raises/clears the "UnifiedNetworkManager update available" notification. The Updates page itself refreshes on its own 30 s cadence; this only controls how promptly the admin is NOTIFIED (bell + badge) when a new release appears. Takes effect on the next beat; no restart.',
  },
  {
    key: 'updateFeedWebFetchProviderId',
    label: 'Update feed web-fetch instance',
    type: 'string',
    category: 'Updates',
    default: '',
    envVar: 'UNM_UPDATE_FEED_WEBFETCH_PROVIDER_ID',
    maxLength: 128,
    help:
      'The web-fetch plugin instance (capability `webFetch`) that downloads the update feed — the API itself never opens outbound internet connections. Empty = auto-resolve: the built-in Web Fetch plugin if online, otherwise any registered online web-fetch provider. Set a specific plugin id to pin the check to one instance (e.g. an egress proxy in another network segment).',
  },

  // Central file repository — which file-repo plugin stores NEW uploads by default.
  {
    key: 'fileRepoDefaultProviderId',
    label: 'Default file repository',
    type: 'string',
    category: 'Files',
    default: '',
    envVar: 'FILE_REPO_PLUGIN_ID',
    maxLength: 128,
    help:
      'The file-repo plugin (capability `fileRepo`) that stores new uploads by default — the Files page preselects it so you normally never have to pick a repo per upload. Empty = auto-resolve (the built-in local-storage repo, or the first online provider). Individual uploads can still override this from the Files page.',
  },

  // Certificate Authority (the unm-ca service — step-ca, see api/src/ca/).
  // These knobs are rendered into the CA's ca.json by writeStepCaConfig() and
  // hot-applied via SIGHUP; they do NOT take effect on already-issued leaves.
  {
    key: 'caLeafMinDays',
    label: 'CA leaf minimum lifetime',
    type: 'integer',
    category: 'Certificate Authority',
    unit: 'days',
    min: 1,
    max: 3650,
    default: 7,
    envVar: 'UNM_CA_LEAF_MIN_DAYS',
    onChange: () => require('./ca/stepCaConfig').writeStepCaConfig(),
    help:
      'Shortest validity the CA will issue for a plugin/API leaf certificate. Requests below this are clamped up. Keep short so revoked or leaked leaves die quickly.',
  },
  {
    key: 'caLeafMaxDays',
    label: 'CA leaf maximum lifetime',
    type: 'integer',
    category: 'Certificate Authority',
    unit: 'days',
    min: 1,
    max: 3650,
    default: 365,
    envVar: 'UNM_CA_LEAF_MAX_DAYS',
    onChange: () => require('./ca/stepCaConfig').writeStepCaConfig(),
    help:
      'Longest validity the CA will issue for a leaf certificate. Requests above this are clamped down.',
  },
  {
    key: 'caLeafDefaultDays',
    label: 'CA leaf default lifetime',
    type: 'integer',
    category: 'Certificate Authority',
    unit: 'days',
    min: 1,
    max: 3650,
    default: 90,
    envVar: 'UNM_CA_LEAF_DEFAULT_DAYS',
    onChange: () => require('./ca/stepCaConfig').writeStepCaConfig(),
    help:
      'Validity used when a client does not request a specific one. Clients renew at ~2/3 of their leaf lifetime, so this also sets the renewal cadence.',
  },
  {
    key: 'caAcmeEnrollmentPolicy',
    label: 'ACME enrollment policy',
    type: 'string',
    category: 'Certificate Authority',
    default: 'any',
    envVar: 'UNM_CA_ACME_ENROLLMENT_POLICY',
    pattern: '^(deny|allowlist|any)$',
    onChange: () => require('./ca/stepCaConfig').writeStepCaConfig(),
    help:
      'Who may request a certificate from the CA over ACME. "any" (default) — any name that passes its http-01 challenge is issued, so new plugins enroll without extra setup. "allowlist" — only names in "CA allowed DNS names" are issued. "deny" — no ACME enrollment at all (the CA stays manageable via its admin credential). Hot-applied to the running CA.',
  },
  {
    key: 'caAllowedDnsNames',
    label: 'CA allowed DNS names (SAN allow-list)',
    type: 'string',
    category: 'Certificate Authority',
    // Core UNM service names only — NO plugin catalog here. Every registered
    // plugin's advertised host is appended automatically at render time
    // (stepCaConfig.collectAllowedDnsNames), so third-party plugins enroll in
    // allowlist mode without anyone editing this list.
    default: 'unm-ca,localhost,api,mcp',
    envVar: 'UNM_CA_ALLOWED_DNS_NAMES',
    maxLength: 8192,
    onChange: () => require('./ca/stepCaConfig').writeStepCaConfig(),
    help:
      'Comma-separated DNS names the CA may put into leaf certificates. Only enforced when "ACME enrollment policy" is set to allowlist — in any mode this list is ignored, and in deny mode no ACME enrollment happens at all. The hosts of every registered plugin are added automatically on top of this list.',
  },
  {
    key: 'caAcmeChallenges',
    label: 'CA ACME challenge types',
    type: 'string',
    category: 'Certificate Authority',
    default: 'http-01',
    envVar: 'UNM_CA_ACME_CHALLENGES',
    pattern: '^(http-01|dns-01|tls-alpn-01)(,(http-01|dns-01|tls-alpn-01))*$',
    onChange: () => require('./ca/stepCaConfig').writeStepCaConfig(),
    help:
      'Which RFC 8555 challenge types the ACME provisioner accepts. http-01 (default) is what UNM plugins use — the CA fetches a token from the plugin over the compose network. dns-01 / tls-alpn-01 are opt-in for future remote-instance topologies.',
  },
  {
    key: 'caTlsMinVersion',
    label: 'CA minimum TLS version',
    type: 'string',
    category: 'Certificate Authority',
    default: '1.2',
    envVar: 'UNM_CA_TLS_MIN_VERSION',
    // Double-escape: the string literal must contain a backslash so that
    // `new RegExp(pattern)` sees `\.` (literal dot) rather than `.` (any char).
    pattern: '^(1\\.2|1\\.3)$',
    onChange: () => require('./ca/stepCaConfig').writeStepCaConfig(),
    help:
      'Minimum TLS version the CA\'s own listener negotiates (and the floor UNM documents for plugin listeners). 1.2 is the default; 1.3 requires all clients to support it.',
  },

  // Fleet rollout safety net (network.create plans).
  {
    key: 'rolloutOverlapMode',
    label: 'Rollout overlap mode',
    type: 'string',
    category: 'Execution',
    default: 'warn',
    envVar: 'UNM_ROLLOUT_OVERLAP_MODE',
    pattern: '^(warn|block)$',
    help:
      'How the server-side network-overlap check treats a rollout whose name, subnet or VLAN ID collides with an already-detected live network. "warn" (default): plan creation proceeds — NAT\'d remote sites and multi-site designs legitimately reuse names/subnets/VLAN ids. "block": such rollouts are REJECTED at plan creation until the overlap is resolved or this setting is switched back to warn.',
  },

  // Public NTP reference monitoring (Time page "Time base" card). The ntpReferences
  // worker polls each configured public server and compares its served instant
  // against UNM's own clock — a large |drift| means the fleet's time base is off.
  {
    key: 'ntpReferenceServers',
    label: 'NTP reference servers',
    type: 'string',
    category: 'Time',
    default: 'pool.ntp.org:123,time.google.com:123',
    envVar: 'UNM_NTP_REFERENCE_SERVERS',
    maxLength: 500,
    help:
      'Comma-separated list of public NTP servers (host or IP, optional :port — default 123) polled by the time-base worker. Each server is queried with a single SNTP request; the median drift across healthy references is shown as "UNM clock vs international consensus" on the Time page. Use at least two independent sources so one bad reference cannot skew the verdict.',
  },
  {
    key: 'ntpReferencePollIntervalMs',
    label: 'NTP reference poll window',
    type: 'integer',
    category: 'Time',
    unit: 'ms',
    min: 60_000,
    max: 3_600_000,
    default: 300_000,
    envVar: 'UNM_NTP_REFERENCE_POLL_INTERVAL_MS',
    help:
      'How often the time-base worker re-queries every configured public NTP reference. One lightweight SNTP request per server — keep it at or above one minute to stay a polite client of public pools.',
  },

  // Web fetch (the web-fetch plugin, capability `webFetch`) — outbound internet
  // egress for UNM: the GeoIP worker and any future web-data feature download
  // through this plugin instead of from the API container itself.
  {
    key: 'webFetchProxyUrl',
    label: 'Egress proxy URL',
    type: 'string',
    category: 'Web Fetch',
    default: '',
    envVar: 'WEBFETCH_PROXY_URL',
    maxLength: 500,
    help:
      'Optional forward proxy every web fetch goes through — required in enterprise environments where plain egress TLS is not allowed. Format: scheme://[user:pass@]host:port (e.g. http://proxy.corp.example.com:3128). HTTPS targets are tunneled with CONNECT, so the proxy never sees the URL or payload. Empty = direct connection. The web-fetch plugin\'s own WEBFETCH_PROXY_URL env acts as a deployment-level default when this setting is empty.',
  },
  {
    key: 'webFetchTimeoutMs',
    label: 'Fetch timeout',
    type: 'integer',
    category: 'Web Fetch',
    unit: 'ms',
    min: 5_000,
    max: 600_000,
    default: 120_000,
    envVar: 'WEBFETCH_TIMEOUT_MS',
    help:
      'Maximum time a single web fetch may take (connect + download). Large GeoIP databases through a slow corporate proxy can need several minutes — raise this if refreshes time out.',
  },
  {
    key: 'webFetchMaxBytes',
    label: 'Max download size',
    type: 'integer',
    category: 'Web Fetch',
    unit: 'bytes',
    min: 1_048_576,
    max: 2_147_483_648,
    default: 536_870_912,
    envVar: 'WEBFETCH_MAX_BYTES',
    help:
      'Hard ceiling for a single download (default 512 MiB). Responses larger than this are aborted — GeoIP databases are well under 100 MiB, so keep the default unless you fetch something bigger.',
  },

  // GeoIP enrichment (Flows page "Location" column) — the geoip worker pulls a
  // database file through the web-fetch plugin into the central file repository
  // and the lookup engine resolves external IPs at request time.
  {
    key: 'geoipEnabled',
    label: 'GeoIP enrichment',
    type: 'boolean',
    category: 'GeoIP',
    default: true,
    help:
      'Master switch for GeoIP database fetching + IP location lookups on the Flows page. Disable to stop periodic downloads and hide country/city from top talkers (existing files are kept).',
  },
  {
    key: 'geoipSource',
    label: 'Database source',
    type: 'string',
    category: 'GeoIP',
    default: 'maxmind',
    pattern: '^(maxmind|dpip|ip2location-lite|ipinfo|custom)$',
    help:
      'Where the GeoIP database comes from. "maxmind" — MaxMind GeoLite2-City (MMDB, needs a free license key in the custom URL); "dpip" — dp-ip.com free CSV; "ip2location-lite" — IP2Location LITE zip (CSV inside); "ipinfo" — ipinfo.io mmdb-lite; "custom" — any direct file/archive URL you provide. The source presets the download URL only when "Custom download URL" is empty.',
  },
  {
    key: 'geoipCustomUrl',
    label: 'Custom download URL',
    type: 'string',
    category: 'GeoIP',
    default: '',
    maxLength: 2048,
    help:
      'Full HTTPS/HTTP URL of the database file or archive (.mmdb / .csv / .tar.gz / .zip) — wins over the source preset. For MaxMind use their download endpoint with your license key in the query string (https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=…&type=tar.gz&suf=tar.gz). Archives are opened automatically and the first .mmdb/.csv member is stored.',
  },
  {
    key: 'geoipAuthHeader',
    label: 'Authorization header',
    type: 'string',
    category: 'GeoIP',
    default: '',
    maxLength: 500,
    help:
      'Optional raw HTTP header sent with the download request — e.g. "Authorization: Bearer <token>" for ipinfo.io or a private mirror. Leave empty when the URL itself carries all credentials.',
  },
  {
    key: 'geoipFetchIntervalHours',
    label: 'Refresh interval',
    type: 'integer',
    category: 'GeoIP',
    unit: 'h',
    min: 1,
    max: 8_760,
    default: 720,
    help:
      'How often the worker re-downloads the database (default 720 h = monthly — GeoLite2 is updated monthly). The manual "Refresh now" button on this page bypasses the interval.',
  },
  {
    key: 'geoipDeleteOldFiles',
    label: 'Delete old files after refresh',
    type: 'boolean',
    category: 'GeoIP',
    default: true,
    help:
      'When a new database file is stored successfully, delete the previous GeoIP file(s) from the central file repository (up to the last 5). Disable to keep history — useful when several consumers might still reference an older snapshot.',
  },
  {
    key: 'geoipCsvFormat',
    label: 'CSV format',
    type: 'string',
    category: 'GeoIP',
    default: 'auto',
    pattern: '^(auto|dpip|ip2location-lite)$',
    help:
      'Column layout for CSV databases (MMDB sources ignore this). "auto" sniffs the header row — FromIP/ToIP columns → IP2Location LITE, otherwise dp-ip single-IP rows. Set explicitly only if a custom CSV uses one of these layouts.',
  },
  {
    key: 'geoipActiveFileId',
    label: 'Active database file (managed)',
    type: 'string',
    category: 'GeoIP',
    default: '',
    maxLength: 128,
    help:
      'Internal pointer to the currently active GeoIP file in the central repository — written by the geoip worker after each successful refresh. Do not edit manually; clear it to force a re-download on the next cycle.',
  },

  // CVE vulnerability tracking (Security page) — the cve worker queries an OSINT
  // provider (OSV.dev today, commercial providers later via the CveProvider
  // interface) for every distinct package installed in the fleet and matches
  // the advisories against each device's versions. Egress goes through the same
  // web-fetch plugin as GeoIP (webFetchProxyUrl/TimeoutMs/MaxBytes apply).
  {
    key: 'cveEnabled',
    label: 'CVE vulnerability tracking',
    type: 'boolean',
    category: 'CVE Tracking',
    default: true,
    help:
      'Master switch for the CVE worker. When enabled it periodically fetches advisories (OSV.dev) for every package installed on your devices and matches them against the installed versions — results appear on the Security page. Disable to stop fetching; existing findings stay in place.',
  },
  {
    key: 'cveFetchIntervalHours',
    label: 'Advisory refresh interval',
    type: 'integer',
    category: 'CVE Tracking',
    unit: 'h',
    min: 1,
    max: 8_760,
    default: 24,
    help:
      'How often the worker re-queries the advisory provider (default 24 h — OSV.dev publishes new advisories continuously). The manual "Refresh now" button on the Security page bypasses the interval. Device-side matching is recomputed on every beat regardless, so a package upgrade clears its findings without waiting for the next fetch.',
  },
];

const BY_KEY: Record<string, SettingDescriptor> = Object.fromEntries(
  SETTING_DESCRIPTORS.map((d) => [d.key, d])
);

// --- Typed view over the telemetry knobs (backward-compatible API) -----------
// The Workers page + telemetry worker consume this narrower shape; it is a
// projection of the registry so both stay in lockstep with the Settings page.

export interface SystemSettings {
  /** Metrics poll window in ms (env: TELEMETRY_POLL_INTERVAL_MS, min 5000). */
  telemetryPollIntervalMs: number;
  /** Inventory refresh window in ms (env: TELEMETRY_INVENTORY_WINDOW_MS, default 15 min). */
  telemetryInventoryWindowMs: number;
  /** Max concurrent /monitoring calls in flight (env: TELEMETRY_MAX_CONCURRENCY, min 1). */
  telemetryMaxConcurrency: number;
  /** Random spread applied to each rescheduled deadline, percent of the window (0–90). */
  telemetryJitterPercent: number;
}

const TELEMETRY_KEYS = [
  'telemetryPollIntervalMs',
  'telemetryInventoryWindowMs',
  'telemetryMaxConcurrency',
  'telemetryJitterPercent',
] as const;

/** Projects the full effective-values map onto the narrow telemetry shape. */
function projectTelemetry(values: Record<string, SettingValue>): SystemSettings {
  return {
    telemetryPollIntervalMs: Number(values.telemetryPollIntervalMs),
    telemetryInventoryWindowMs: Number(values.telemetryInventoryWindowMs),
    telemetryMaxConcurrency: Number(values.telemetryMaxConcurrency),
    telemetryJitterPercent: Number(values.telemetryJitterPercent),
  };
}

function clampInt(v: number, min: number, max: number): number {
  if (!Number.isFinite(v)) return min;
  return Math.min(max, Math.max(min, Math.round(v)));
}

/** Coerces an unknown raw value into the descriptor's type + range. */
function coerceRaw(desc: SettingDescriptor, raw: unknown): SettingValue {
  if (desc.type === 'integer') {
    const n = Number(raw);
    if (!Number.isFinite(n)) return desc.default as number;
    let v = Math.round(n);
    if (desc.min !== undefined) v = Math.max(desc.min, v);
    if (desc.max !== undefined) v = Math.min(desc.max, v);
    return v;
  }
  if (desc.type === 'boolean') {
    if (typeof raw === 'boolean') return raw;
    const s = String(raw).trim().toLowerCase();
    return s === 'true' || s === '1';
  }
  // string
  let s = typeof raw === 'string' ? raw : String(raw ?? '');
  if (desc.minLength !== undefined && s.length < desc.minLength) return desc.default as string;
  if (desc.maxLength !== undefined && s.length > desc.maxLength) s = s.slice(0, desc.maxLength);
  if (desc.pattern && !new RegExp(desc.pattern).test(s)) return desc.default as string;
  return s;
}

/** Deployment-level default: env var (if set + valid) else the descriptor default. */
function envDefault(desc: SettingDescriptor): SettingValue {
  if (desc.envVar) {
    const raw = process.env[desc.envVar];
    if (raw !== undefined && raw.trim() !== '') return coerceRaw(desc, raw);
  }
  return desc.default;
}

// --- Effective-values cache -------------------------------------------------
// One short-TTL snapshot of ALL effective values. Workers read it every beat; a
// write busts the local cache so this replica reflects its own change at once,
// and the TTL bounds how long OTHER replicas keep serving pre-change values.

let cache: { values: Record<string, SettingValue>; cachedAt: number } | null = null;
const CACHE_TTL_MS = 5_000; // one beat of staleness is fine for cadence knobs

async function loadEffectiveValues(): Promise<Record<string, SettingValue>> {
  const values: Record<string, SettingValue> = {};
  for (const d of SETTING_DESCRIPTORS) values[d.key] = envDefault(d);
  try {
    const rows = await db.query.systemSettings.findMany();
    for (const row of rows) {
      const d = BY_KEY[row.key];
      if (!d) continue; // unknown/foreign key — ignore rather than fail the beat
      values[d.key] = coerceRaw(d, row.value);
    }
  } catch {
    // Table missing / DB hiccup — fall back to env defaults.
  }
  return values;
}

export async function getEffectiveValues(): Promise<Record<string, SettingValue>> {
  const now = Date.now();
  if (cache && now - cache.cachedAt < CACHE_TTL_MS) return cache.values;
  const values = await loadEffectiveValues();
  cache = { values, cachedAt: now };
  return values;
}

/** Drops the local cache after a write from ANY replica. */
export function invalidateSystemSettingsCache(): void {
  cache = null;
}

/**
 * Synchronous read of one setting for callers that cannot await (e.g. console
 * ticket minting). Returns the last cached effective value, or the deployment
 * default when nothing is cached yet — a few seconds of staleness is acceptable
 * here since these knobs are not latency-critical.
 */
export function getCachedSettingValue(key: string): SettingValue {
  const d = BY_KEY[key];
  if (!d) return undefined as never;
  if (cache && cache.values[key] !== undefined) return cache.values[key];
  return envDefault(d);
}

/**
 * Validates + clamps a partial telemetry update. Unsent fields keep their
 * CURRENT value (base), so a one-field PUT never resets the other knob to its
 * default. Throws on bad types (route maps to 400).
 */
export function validateSettingsUpdate(body: Partial<SystemSettings>, base?: SystemSettings): SystemSettings {
  const out: SystemSettings = { ...(base ?? currentDefaults()) };
  for (const key of TELEMETRY_KEYS) {
    const raw = (body as Record<string, unknown>)[key];
    if (raw === undefined) continue;
    const d = BY_KEY[key];
    const n = Number(raw);
    if (!Number.isFinite(n)) throw new Error(`"${key}" must be a number`);
    (out as unknown as Record<string, number>)[key] = clampInt(n, d.min ?? 0, d.max ?? Number.MAX_SAFE_INTEGER);
  }
  return out;
}

function currentDefaults(): SystemSettings {
  const values: Record<string, SettingValue> = {};
  for (const k of TELEMETRY_KEYS) values[k] = envDefault(BY_KEY[k]);
  return projectTelemetry(values);
}

/** Effective settings: stored overrides ⊕ env defaults. Cached for CACHE_TTL_MS. */
export async function getSystemSettings(): Promise<SystemSettings> {
  return projectTelemetry(await getEffectiveValues());
}

/** Persists the telemetry settings object (all-or-nothing) and busts the cache. */
export async function saveSystemSettings(values: SystemSettings): Promise<SystemSettings> {
  const now = new Date().toISOString();
  for (const key of TELEMETRY_KEYS) {
    await pool.query(
      `INSERT INTO system_settings ("key", value, "updatedAt") VALUES ($1, $2, $3)
       ON CONFLICT ("key") DO UPDATE SET value = EXCLUDED.value, "updatedAt" = EXCLUDED."updatedAt"`,
      [key, String(values[key]), now]
    );
  }
  cache = null;
  return values;
}

// --- Generic Settings-page API ----------------------------------------------

function viewFor(d: SettingDescriptor, values: Record<string, SettingValue>): SettingView {
  const value = values[d.key];
  const defaultValue = envDefault(d);
  return {
    key: d.key,
    label: d.label,
    type: d.type,
    category: d.category,
    help: d.help,
    unit: d.unit,
    min: d.min,
    max: d.max,
    pattern: d.pattern,
    value,
    defaultValue,
    isModified: value !== defaultValue,
  };
}

/** Every setting with its effective value + metadata (for the Settings page). */
export async function listAllSettings(): Promise<SettingView[]> {
  const values = await getEffectiveValues();
  return SETTING_DESCRIPTORS.map((d) => viewFor(d, values));
}

function badType(key: string, expected: string): Error & { status?: number } {
  const e = new Error(`"${key}" must be a ${expected}`);
  (e as { status?: number }).status = 400;
  return e;
}

/** Validates + clamps one setting and persists it. Returns the updated view. */
export async function updateSetting(key: string, rawValue: unknown): Promise<SettingView> {
  const d = BY_KEY[key];
  if (!d) {
    const e = new Error(`Unknown setting "${key}"`);
    (e as { status?: number }).status = 404;
    throw e;
  }

  let value: SettingValue;
  if (d.type === 'integer') {
    const n = Number(rawValue);
    if (!Number.isFinite(n)) throw badType(key, 'number');
    value = clampInt(n, d.min ?? -Infinity, d.max ?? Infinity);
  } else if (d.type === 'boolean') {
    if (typeof rawValue === 'boolean') value = rawValue;
    else if (['true', 'false'].includes(String(rawValue).trim().toLowerCase()))
      value = String(rawValue).trim().toLowerCase() === 'true';
    else throw badType(key, 'boolean');
  } else {
    const s = typeof rawValue === 'string' ? rawValue : rawValue == null ? '' : String(rawValue);
    if (d.minLength !== undefined && s.length < d.minLength)
      throw new Error(`"${key}" must be at least ${d.minLength} characters`);
    if (d.maxLength !== undefined && s.length > d.maxLength)
      throw new Error(`"${key}" must be at most ${d.maxLength} characters`);
    if (d.pattern && !new RegExp(d.pattern).test(s))
      throw new Error(`"${key}" does not match the required pattern`);
    d.validate?.(s); // structured check (e.g. CIDR list) — throws → 400
    value = s;
  }

  const now = new Date().toISOString();
  await pool.query(
    `INSERT INTO system_settings ("key", value, "updatedAt") VALUES ($1, $2, $3)
     ON CONFLICT ("key") DO UPDATE SET value = EXCLUDED.value, "updatedAt" = EXCLUDED."updatedAt"`,
    [key, String(value), now]
  );
  cache = null;
  if (d.onChange) {
    try {
      await d.onChange();
    } catch (err) {
      console.error(`[settings] onChange hook for "${key}" failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return viewFor(d, await getEffectiveValues());
}

/** Deletes a stored override so the setting reverts to its env/default baseline. */
export async function resetSetting(key: string): Promise<SettingView> {
  const d = BY_KEY[key];
  if (!d) {
    const e = new Error(`Unknown setting "${key}"`);
    (e as { status?: number }).status = 404;
    throw e;
  }
  await pool.query(`DELETE FROM system_settings WHERE "key" = $1`, [key]);
  cache = null;
  if (d.onChange) {
    try {
      await d.onChange();
    } catch (err) {
      console.error(`[settings] onChange hook for "${key}" failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return viewFor(d, await getEffectiveValues());
}

/** The subset of settings plugins may read via the x-unm-global-settings header. */
export async function getPluginGlobalSettings(): Promise<Record<string, SettingValue>> {
  const values = await getEffectiveValues();
  const out: Record<string, SettingValue> = {};
  for (const d of SETTING_DESCRIPTORS) if (d.exposeToPlugins) out[d.key] = values[d.key];
  return out;
}

/** Effective value of one setting by key (for workers/consumers). Undefined if unknown. */
export async function getEffectiveSettingValue(key: string): Promise<SettingValue | undefined> {
  const d = BY_KEY[key];
  if (!d) return undefined;
  const values = await getEffectiveValues();
  return values[key];
}

// Re-export for the route's error mapping convenience.
export const SETTINGS_LIMITS = {
  MIN_POLL_INTERVAL_MS: BY_KEY.telemetryPollIntervalMs.min!,
  MAX_POLL_INTERVAL_MS: BY_KEY.telemetryPollIntervalMs.max!,
  MIN_INVENTORY_WINDOW_MS: BY_KEY.telemetryInventoryWindowMs.min!,
  MAX_INVENTORY_WINDOW_MS: BY_KEY.telemetryInventoryWindowMs.max!,
  MIN_CONCURRENCY: BY_KEY.telemetryMaxConcurrency.min!,
  MAX_CONCURRENCY: BY_KEY.telemetryMaxConcurrency.max!,
  MIN_JITTER_PERCENT: BY_KEY.telemetryJitterPercent.min!,
  MAX_JITTER_PERCENT: BY_KEY.telemetryJitterPercent.max!,
};
