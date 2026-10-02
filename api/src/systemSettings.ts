import { db, pool } from './db';

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

  // Stack self-update feed (Updates page "UNM itself" card). Empty = disabled —
  // the card then shows current versions without a latest-version comparison.
  {
    key: 'updateFeedUrl',
    label: 'Update feed URL',
    type: 'string',
    category: 'Updates',
    default: '',
    envVar: 'UNM_UPDATE_FEED_URL',
    maxLength: 2048,
    help:
      'Optional HTTPS URL of a JSON release manifest for UNM itself (e.g. a GitHub releases asset). Expected shape: {"latestVersion":"1.2.3","notesUrl":"https://…"}. When set, the Updates page compares it against the running API version and shows an "update available" state; when empty, only current versions are shown.',
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
    default:
      'unm-ca,localhost,api,mcp,basic-auth-plugin,secrets-provider-plugin,file-repo-plugin,opnsense-plugin,icmp-plugin,generic-snmp-plugin,lancom-lx-plugin,lancom-lcos-plugin,mikrotik-swos-plugin,lancom-sx-plugin,fbox-plugin,ix-truenas-plugin,mikrotik-routeros-plugin,docker-plugin,openwrt-plugin,generic-ssh-plugin,generic-http-plugin,generic-ntp-plugin,mailcow-plugin,zabbix-plugin',
    envVar: 'UNM_CA_ALLOWED_DNS_NAMES',
    maxLength: 8192,
    onChange: () => require('./ca/stepCaConfig').writeStepCaConfig(),
    help:
      'Comma-separated DNS names the CA may put into leaf certificates. Only enforced when "ACME enrollment policy" is set to allowlist — in any mode this list is ignored, and in deny mode no ACME enrollment happens at all. Defaults to every UNM compose service name + localhost.',
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
    pattern: '^(1\.2|1\.3)$',
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
      console.error(`[settings] onChange hook for "${key}" failed:`, err);
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
      console.error(`[settings] onChange hook for "${key}" failed:`, err);
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
