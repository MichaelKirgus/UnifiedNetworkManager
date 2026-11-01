import { pgTable, text, boolean, integer, bigint, doublePrecision, jsonb, index, uniqueIndex, primaryKey } from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

export const users = pgTable('users', {
  id: text('id').primaryKey(),
  username: text('username').notNull().unique(),
  passwordHash: text('passwordHash').notNull(),
  totpSecret: text('totpSecret'),
  roles: text('roles').notNull().default('[]'),
  permissions: text('permissions').notNull().default('[]'),
  createdAt: text('createdAt').notNull(),
  // Credential-policy state (see credentialPolicies below):
  //   disabled — set by the inactivity sweep when a user has not logged on for
  //     `inactiveDisableAfterDays`; also settable manually. Disabled users are
  //     rejected at login AND their live sessions are terminated (401).
  //   lastLoginAt — ISO timestamp of the most recent successful authentication
  //     (login or in-session revalidation); drives the inactivity sweep.
  //   passwordChangedAt — ISO timestamp of the most recent password set/reset;
  //     drives forced rotation when `passwordMaxAgeDays` is enabled. NULL =
  //     unknown age (treated as "just changed" so existing accounts are not
  //     locked out on first deploy).
  disabled: boolean('disabled').notNull().default(false),
  lastLoginAt: text('lastLoginAt'),
  passwordChangedAt: text('passwordChangedAt'),
  // Device-level access control (see deviceAccess.ts). JSON object
  // {siteIds?: string[], tags?: string[], deviceIds?: string[]} — a user may
  // see any device matching ANY of the listed rules. '{}' = unrestricted.
  // Only enforced when the user's effective permissions lack 'devices:all'.
  deviceScope: text('deviceScope').notNull().default('{}'),
  // First-run onboarding (see routes/auth.ts POST /auth/onboarding/complete).
  // NULL until the initial admin has finished or skipped the setup wizard —
  // the webapp redirects them there on their very first login.
  onboardedAt: text('onboardedAt'),
});

// Long-lived bearer tokens for agents/scripts (e.g. the MCP server). The raw
// token value is shown exactly once at creation; only its SHA-256 hash is
// stored. `permissions` holds the granted set (a subset of the creator's
// effective permissions at creation time); an empty list means "inherit the
// creator's full current effective set". Enforcement intersects with the
// user's CURRENT effective permissions on every request, so demotions apply
// immediately without revoking tokens.
export const apiTokens = pgTable('api_tokens', {
  id: text('id').primaryKey(),
  userId: text('userId').notNull(),
  label: text('label'),
  // SHA-256 hex of the raw token value (the only stored form).
  tokenHash: text('tokenHash').notNull().unique(),
  // First characters of the raw value, for display in lists ("unm_abc1…").
  tokenPrefix: text('tokenPrefix'),
  // JSON string array of granted permission ids ([] = inherit all effective).
  permissions: text('permissions').notNull().default('[]'),
  expiresAt: text('expiresAt'),
  lastUsedAt: text('lastUsedAt'),
  createdAt: text('createdAt').notNull(),
});

// Named bundles of permissions. Roles are NOT evaluated at enforcement time —
// a user's effective permission set is the union of their explicit `users.permissions`
// and the permissions of every role they carry, computed when the JWT is minted
// (see expandRolePermissions() in routes/roles.ts). The built-in `admin` role
// carries all catalog permissions and cannot be deleted.
export const roles = pgTable('roles', {
  name: text('name').primaryKey(),
  description: text('description'),
  // JSON string array of permission ids (validated against the catalog).
  permissions: text('permissions').notNull().default('[]'),
  createdAt: text('createdAt').notNull(),
  // Device-level access control — group-level default scope for every member
  // carrying this role. Same shape as users.deviceScope; a user's own rules
  // are UNIONED on top of their roles' rules (union model, see deviceAccess.ts).
  deviceScope: text('deviceScope').notNull().default('{}'),
});

// Sites are first-class objects (name + description + address/country/timezone)
// that devices reference via `devices.siteId`. Replaces the old free-text
// `site` column — see backfillDeviceSites() in db.ts for the one-time migration.
export const sites = pgTable('sites', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  description: text('description'),
  address: text('address'),
  // ISO-3166-1 alpha-2 country code (e.g. "DE"), validated server-side.
  country: text('country'),
  // IANA timezone identifier (e.g. "Europe/Berlin"), validated server-side.
  timezone: text('timezone'),
  // GPS location of the site (WGS84 decimal degrees) — stored for a future
  // map view; both must be set together or both stay null.
  latitude: doublePrecision('latitude'),
  longitude: doublePrecision('longitude'),
  createdAt: text('createdAt').notNull(),
});

export const devices = pgTable('devices', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  vendor: text('vendor').notNull(),
  // Legacy single type string — kept for backward compatibility with older
  // clients; new code uses `deviceTypes` (array). Migrated from here on boot.
  deviceType: text('deviceType'),
  // Multiple roles a device fulfills, e.g. ["router", "firewall"] for an
  // OPNsense box or ["switch", "router"] for a routed switch. Free-form,
  // lowercase-normalized; the webapp offers common suggestions.
  deviceTypes: text('deviceTypes').notNull().default('[]'),
  // User-assigned free-form tags (e.g. "dmz", "lab") — future filter/plan targeting.
  tags: text('tags').notNull().default('[]'),
  managementAddress: text('managementAddress').notNull(),
  // Reference to the site this device lives at (NULL = unassigned).
  siteId: text('siteId'),
  status: text('status').notNull().default('unknown'),
  // Human-readable reasons for a non-ok status (JSON array of
  // {pluginId, pluginName, severity, message}), derived worst-wins from the
  // last poll outcomes — persisted so the webapp can show them in a badge
  // tooltip without re-deriving. NULL when online/unknown or no reasons yet.
  healthReasons: text('healthReasons'),
  // User-selected hardware model, chosen from a plugin's advertised catalog
  // (/discover `deviceModels`). NULL when no catalog applies or the user skipped it.
  // Forwarded to every /monitoring call so vendor plugins can adapt their data gathering.
  model: text('model'),
  // Firmware version for this device (from the selected model's firmwareVersions list).
  firmwareVersion: text('firmwareVersion'),
  // Manual topology-layer override (network_layers.id). NULL = auto-classify
  // (plugin-suggested default → type/vendor/port heuristic → 'access').
  layerOverride: text('layerOverride'),
  // Per-device metrics poll window in ms (window-based telemetry scheduling).
  // NULL = inherit the plugin's global option / system setting. Overrides the
  // METRICS window only; the inventory window is clamped to at least this value.
  pollIntervalMs: integer('pollIntervalMs'),
  // Disabled devices are NOT polled by the telemetry worker; their historical
  // data and last metrics stay preserved. Default enabled.
  enabled: boolean('enabled').notNull().default(true),
  createdAt: text('createdAt').notNull(),
});

// Device ↔ plugin assignments (many-to-many). Each row binds one plugin to a
// device with its own credential source (`secretId`), so a single device can
// be served by several plugins at once (e.g. OPNsense API + SNMP + SSH), each
// providing different data and using different secrets. Exactly one assignment
// per device is marked primary — the default target for config jobs.
export const devicePlugins = pgTable(
  'device_plugins',
  {
    id: text('id').primaryKey(),
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Credential source for THIS assignment (each plugin may use a different
    // secret). NULL = the plugin is called without credentials.
    secretId: text('secretId'),
    // Additional named credential slots declared by the plugin in /discover
    // (`credentialSlots`), e.g. { "web": "<secretId>" }. JSON object mapping
    // slot name → secrets.id; NULL/{} = no extra slots bound. Lets one device
    // assignment carry several distinct credentials (e.g. SNMP + web UI).
    extraCredentials: text('extraCredentials'),
    isPrimary: boolean('isPrimary').notNull().default(false),
    // Position of this plugin within its device's ordered list (0-based, dense).
    // The FIRST row is the primary plugin — drag & drop in the webapp rewrites
    // these values. Also defines the fallback order for future failover logic.
    order: integer('order').notNull().default(0),
    createdAt: text('createdAt').notNull(),
  },
  (table) => {
    return {
      uqDevicePlugins: uniqueIndex('uq_device_plugins').on(table.deviceId, table.pluginId),
    };
  }
);

// Network layers for the topology view's horizontal bands (core / distribution /
// access / endpoint by default). Layers are DATA, not constants: users can add
// custom ones (name + color + order) and re-color/reorder built-ins. Built-in ids
// are stable strings referenced by the classification heuristic in utils/topology.ts;
// custom layers are reachable via a device's manual override or a plugin-suggested
// default only.
export const networkLayers = pgTable('network_layers', {
  id: text('id').primaryKey(),
  name: text('name').notNull().unique(),
  // Display order of the bands (1 = topmost). New custom layers append after all.
  sort: integer('sort').notNull().default(0),
  // Band accent color (hex, e.g. "#e11d48") — used for band headers + device chips.
  color: text('color').notNull(),
  isBuiltin: boolean('is_builtin').notNull().default(false),
});

// Secondary IP addresses for a device. The PRIMARY address is the device's
// `managementAddress` column (validated to IPv4/IPv6/DNS name); these rows are
// additional targets plugins may reach (e.g. a public interface, a second
// management VLAN). Exactly one "primary" per device — always the
// managementAddress itself, so no isPrimary flag is needed here.
export const deviceIps = pgTable(
  'device_ips',
  {
    id: text('id').primaryKey(),
    deviceId: text('deviceId').notNull(),
    // Bare address literal or DNS name (validated in api/src/utils/address.ts).
    address: text('address').notNull(),
    createdAt: text('createdAt').notNull(),
  },
  (table) => {
    return {
      uqDeviceIps: uniqueIndex('uq_device_ips').on(table.deviceId, table.address),
      idxDeviceIpsDevice: index('idx_device_ips_device').on(table.deviceId),
    };
  }
);

export const secrets = pgTable('secrets', {
  id: text('id').primaryKey(),
  label: text('label'),
  // The secret type (e.g. 'apiKey', 'usernamePassword', 'snmp'). Declared by
  // the secrets provider that serves it; drives the field schema + UX.
  type: text('type').notNull().default('apiKey'),
  // The secrets provider plugin that serves (encrypts/decrypts) this secret.
  // Per-secret binding so different providers (with different keys) can coexist.
  providerId: text('providerId'),
  encryptedValue: text('encryptedValue').notNull(),
  userId: text('userId').notNull(),
  expiresAt: text('expiresAt'),
  // Interactive-session usage flags. A secret is only OFFERED as a credential for
  // an interactive SSH console / SFTP file session when the matching flag is set
  // (see sessionCredentials.ts). Both default FALSE — opt-in per secret, so no
  // existing secret suddenly becomes usable for live logins/file access.
  interactiveLoginAllowed: boolean('interactiveLoginAllowed').notNull().default(false),
  fileAccessAllowed: boolean('fileAccessAllowed').notNull().default(false),
  createdAt: text('createdAt').notNull(),
});

// Per-user, per-device session-credential defaults (SSH console / SFTP). Lets a
// user rank WHICH of their eligible secrets is used when an interactive session
// opens on a device — without prompting. `secretIds` is an ORDERED list: the
// first entry is auto-used; the rest stay available for re-picking. Missing row
// = no stored preference (the session flow falls back to "single candidate" or
// prompts). One row per (user, device, purpose) — purpose ∈ 'console' | 'filesystem'.
export const deviceSessionCredentials = pgTable(
  'device_session_credentials',
  {
    id: text('id').primaryKey(),
    userId: text('userId').notNull(),
    deviceId: text('deviceId').notNull(),
    // Which interactive session kind this preference applies to.
    purpose: text('purpose').notNull(),
    // Ordered secret ids (JSON array) — first = default, rest = alternatives.
    secretIds: text('secretIds').notNull().default('[]'),
    updatedAt: text('updatedAt').notNull(),
  },
  (table) => {
    return {
      uqDeviceSessionCreds: uniqueIndex('uq_device_session_credentials').on(table.userId, table.deviceId, table.purpose),
      idxDeviceSessionCredsUser: index('idx_device_session_creds_user').on(table.userId),
    };
  }
);

export const plugins = pgTable('plugins', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  // Short human-readable description of what the plugin manages, advertised in
  // /discover. Drives the webapp's plugin catalog picker (card subtitle). NULL
  // = not declared — the card simply shows no description line.
  description: text('description'),
  version: text('version').notNull(),
  vendors: text('vendors').notNull().default('[]'),
  capabilities: text('capabilities').notNull().default('[]'),
  endpoint: text('endpoint').notNull(),
  authType: text('authType').notNull().default('none'),
  // Build tag baked into the plugin image at CI build time (branch name or
  // release tag; empty for local/dev builds). Surfaced via /discover → this
  // column → GET /plugins. NULL = not advertised (mDNS-only discovery, or an
  // image built without UNM_BUILD_TAG set).
  buildTag: text('buildTag'),
  // Metric descriptors declared by the plugin in /discover (JSON array).
  // Drives the webapp's visualization (gauge/plot/text/table) without any
  // webapp code changes per plugin.
  metricDescriptors: text('metricDescriptors'),
  // Option descriptors declared by the plugin in /discover (JSON array of
  // PluginOptionDescriptor). The API persists user-set values for these in
  // `plugin_settings` and validates them; the webapp renders a generic form.
  optionDescriptors: text('optionDescriptors'),
  // Action catalog declared by the plugin in /discover (JSON array of
  // CatalogEntry: { id, label, description?, module, riskLevel,
  // deviceCount: number|'N', beOnly?, inputSchema }). Drives plan creation:
  // the webapp renders intent/step forms from it and the API validates
  // plan step inputs against it.
  actionDescriptors: text('actionDescriptors'),
  // Icon path relative to the plugin root (e.g. "/icons/lancom.svg"), declared
  // in /discover. Served to the webapp via GET /plugins/:pluginId/icon, which
  // proxies the bytes from the plugin — no icon data is stored here or in the DB.
  iconUrl: text('iconUrl'),
  // Supported device model catalog (JSON array of { vendor, model, iconPath?,
  // firmwareVersions? }), declared in /discover. Drives the Model/Firmware
  // dropdowns in the webapp's device create/edit form. NULL = no catalog
  // (e.g. generic plugins like ICMP where a model list makes no sense).
  deviceModels: text('deviceModels'),
  // Named credential slots declared by the plugin in /discover (JSON array of
  // { name, secretType, required?, description? }). Drives per-slot credential
  // pickers in the webapp's assignment builder; bound secrets live on
  // device_plugins.extraCredentials. NULL = no extra slots (primary secret only).
  credentialSlots: text('credentialSlots'),
  // Quick actions declared by the plugin in /discover (JSON array of
  // { id, label, description?, kind: 'url'|'shell'|'files'|'action', url?{
  // path?}, actionId?, prefill? }). Drives the Devices page "Device Actions"
  // column. NULL = no quick actions advertised.
  quickActions: text('quickActions'),
  // Device support metadata declared by the plugin in /discover (JSON object:
  // { license?: { name, url?, file? }, helpUrl?, docPath?, defaultCapabilities?,
  // profiles: [{ vendor?, model?, minFirmware?, maxFirmware?, capabilities[],
  // intents[] }] }). Drives the Plugins page metadata row and the per-device
  // effective-capability evaluation (see types/deviceSupport.ts). NULL = no
  // support matrix advertised.
  deviceSupport: text('deviceSupport'),
  // Ready-made automation rule drafts declared by the plugin in /discover (JSON
  // array of { id, name, description?, draft }). Served by GET /automations/
  // templates alongside the API's built-in templates; the webapp opens the rule
  // builder pre-filled from one. NULL = none advertised.
  automationTemplates: text('automationTemplates'),
  // mTLS state (Stage 1): true when discovery last confirmed this plugin is
  // serving TLS with a CA-signed leaf on its conventional port. The API's
  // pluginHttp factory uses https+client-cert for these, plain http otherwise.
  // NULL/absent = unknown → treated as plain http until proven otherwise.
  tlsLive: boolean('tlsLive'),
  createdAt: text('createdAt').notNull(),
  lastSeenAt: text('lastSeenAt'),
});

// Issued-leaf registry for UNM's OWN certificate authority (the unm-ca /
// step-ca service). step-ca keeps its authoritative issuance state in its own
// embedded DB; this table is UNM's operational mirror — written by the ACME
// enrollment flow (Stage 1) and updated on revocation (POST /ca/revoke) — so
// the webapp can show per-plugin cert status/expiry badges and the notification
// worker can raise expiry warnings without parsing step-ca internals.
export const caCertificates = pgTable(
  'ca_certificates',
  {
    id: text('id').primaryKey(),
    // Hex serial number (no 0x prefix) — unique per issued leaf; revocation is
    // addressed by this value.
    serial: text('serial').notNull().unique(),
    // Identity the leaf was issued for: the plugin instance / api / mcp.
    subject: text('subject').notNull(),
    // SANs on the leaf (JSON array of DNS names).
    dnsNames: text('dnsNames').notNull().default('[]'),
    // Which UNM service holds this leaf — 'api', 'mcp' or a plugin name.
    source: text('source').notNull().default('plugin'),
    // Issuer DN of the leaf (the CA that signed it) — display only.
    issuer: text('issuer').notNull().default(''),
    notBefore: text('notBefore').notNull(),
    notAfter: text('notAfter').notNull(),
    // issued | revoked. Revocation is PASSIVE in step-ca (no CRL/OCSP): the CA
    // refuses renewals for a revoked serial, and existing leaves die at expiry —
    // hence the short default leaf lifetime (caLeafDefaultDays).
    status: text('status').notNull().default('issued'),
    revokedAt: text('revokedAt'),
    createdAt: text('createdAt').notNull(),
  },
  (table) => ({
    idxCaCertificatesSubject: index('idx_ca_certificates_subject').on(table.subject),
  })
);

// User-set plugin option values, owned by the API (plugins never store their
// own settings). `value` is JSON-encoded so any future option type fits.
// Global rows have device_id = NULL; per-device override rows carry a
// device_id (reserved for later — indexes already support both shapes).
export const pluginSettings = pgTable(
  'plugin_settings',
  {
    id: text('id').primaryKey(),
    pluginId: text('pluginId').notNull(),
    // NULL = global setting; set = per-device override (reserved for later).
    deviceId: text('deviceId'),
    optionKey: text('optionKey').notNull(),
    value: text('value').notNull(),
    updatedAt: text('updatedAt').notNull(),
  },
  (table) => {
    return {
      uqPluginSettingsGlobal: uniqueIndex('uq_plugin_settings_global')
        .on(table.pluginId, table.optionKey)
        .where(sql`${table.deviceId} IS NULL`),
      uqPluginSettingsDevice: uniqueIndex('uq_plugin_settings_device')
        .on(table.pluginId, table.deviceId, table.optionKey)
        .where(sql`${table.deviceId} IS NOT NULL`),
    };
  }
);

export const configJobs = pgTable('config_jobs', {
  id: text('id').primaryKey(),
  deviceId: text('deviceId').notNull(),
  // The specific plugin assignment that executes this job (a device can be
  // served by several plugins; the caller picks which one applies the change).
  pluginId: text('pluginId'),
  action: text('action').notNull(),
  status: text('status').notNull().default('queued'),
  payload: text('payload').notNull().default('{}'),
  result: text('result'),
  // Traceability: set when this job was dispatched as part of a plan step.
  planId: text('planId'),
  createdAt: text('createdAt').notNull(),
  finishedAt: text('finishedAt'),
}, (table) => {
  return {
    idxConfigJobsDevice: index('idx_config_jobs_device').on(table.deviceId, table.createdAt),
  };
});

export const telemetry = pgTable('telemetry', {
  id: text('id').primaryKey(),
  deviceId: text('deviceId').notNull(),
  // Which plugin produced this snapshot (a device can have several plugins
  // reporting independently; rows are attributed per assignment).
  pluginId: text('pluginId'),
  collectedAt: text('collectedAt').notNull(),
  health: text('health').notNull().default('unknown'),
  // Optional plugin-reported reasons for a non-ok health (JSON array of
  // {severity, message}) — surfaced in the webapp's status-badge tooltip.
  healthReasons: text('healthReasons'),
  metrics: text('metrics').notNull().default('{}'),
  metricDescriptors: text('metricDescriptors'),
}, (table) => {
  return {
    idxTelemetryDevicePluginCollected: index('idx_telemetry_device_plugin_collected')
      .on(table.deviceId, table.pluginId, table.collectedAt),    // Plain timestamp index for the retention sweep (DELETE WHERE collectedAt < cutoff).
    idxTelemetryCollectedAt: index('idx_telemetry_collected_at').on(table.collectedAt),  };
});

// Structured log entries emitted by plugins via POST /plugin/logs (see
// routes/internal.ts). Plugins batch their console-worthy events and push them
// to the API; a retention worker deletes rows older than LOG_RETENTION_DAYS.
// Powers the per-device Logs section in DeviceDetail and the global Logs page.
export const pluginLogs = pgTable(
  'plugin_logs',
  {
    id: text('id').primaryKey(),
    // Self-reported by the sender (its effectiveUuid); validated against the
    // plugins table at ingest — unknown ids are rejected with a 400.
    pluginId: text('pluginId').notNull(),
    // Device the entry relates to, when known (null for plugin-level events).
    deviceId: text('deviceId'),
    // debug | info | warn | error
    level: text('level').notNull().default('info'),
    message: text('message').notNull(),
    // JSON object with structured details ({endpoint, httpStatus, oid, ...}).
    context: text('context'),
    // ISO-8601 timestamp from the plugin's clock (stored as received).
    emittedAt: text('emittedAt').notNull(),
  },
  (table) => {
    return {
      idxPluginLogsDeviceEmittedAt: index('idx_plugin_logs_device_emitted_at')
        .on(table.deviceId, table.emittedAt),
      idxPluginLogsPluginEmittedAt: index('idx_plugin_logs_plugin_emitted_at')
        .on(table.pluginId, table.emittedAt),
      // Plain emittedAt index for the retention sweep (DELETE WHERE emittedAt < cutoff).
      idxPluginLogsEmittedAt: index('idx_plugin_logs_emitted_at').on(table.emittedAt),
    };
  }
);

// Firewall event-log rows pushed by plugins via POST /plugin/firewall-events
// (see routes/internal.ts) — append-only traffic events (blocked/allowed/NAT)
// from the appliance's firewall log. Powers the cross-device "Firewall Events"
// page. Unlike inventory tables this is a LOG: rows are never upserted or
// deleted-on-absent; growth is bounded by the retention worker after
// FIREWALL_EVENT_RETENTION_DAYS (see workers/firewallEventRetention.ts).
// `ts` is the appliance-local timestamp verbatim ("YYYY-MM-DDTHH:MM:SS", no TZ)
// — lexicographic ordering matches chronological order, so the cutoff DELETE
// works like telemetry's. Dedupe key = vendorEventId (the appliance's per-row
// __digest__), unique per device+plugin; ingest uses on-conflict-ignore.
export const firewallEvents = pgTable(
  'firewall_events',
  {
    id: text('id').primaryKey(),
    // Self-reported by the sender (its effectiveUuid); validated against the
    // plugins table at ingest — unknown ids are rejected with a 400.
    pluginId: text('pluginId').notNull(),
    deviceId: text('deviceId').notNull(),
    // Appliance-local event timestamp, verbatim from the appliance (no TZ).
    ts: text('ts').notNull(),
    // Epoch ms of `ts` parsed as UTC at ingest — the queryable time axis. The
    // raw string is appliance-LOCAL (no offset), so lexicographic comparison
    // against a UTC cutoff would skew by the device's offset; tsMs gives range
    // queries + retention one sane numeric column. NULL when unparseable.
    tsMs: bigint('tsMs', { mode: 'number' }),
    // pass | block | rdr | nat | binat (vendor-specific; 'unknown' fallback).
    action: text('action').notNull().default('unknown'),
    reason: text('reason'),
    interfaceName: text('interfaceName').notNull().default(''),
    srcIp: text('srcIp').notNull().default(''),
    dstIp: text('dstIp').notNull().default(''),
    proto: text('proto'),
    srcPort: integer('srcPort'),
    dstPort: integer('dstPort'),
    // Rule uuid on the appliance (null when the event matched no rule).
    ruleId: text('ruleId'),
    // The rule's description text as reported by the appliance.
    ruleName: text('ruleName'),
    // The appliance's per-row unique id (__digest__) — dedupe key at ingest.
    vendorEventId: text('vendorEventId').notNull(),
  },
  (table) => {
    return {
      uqFirewallEventsVendor: uniqueIndex('uq_firewall_events_vendor').on(
        table.deviceId,
        table.pluginId,
        table.vendorEventId,
      ),
      idxFirewallEventsDeviceTsMs: index('idx_firewall_events_device_ts_ms').on(table.deviceId, table.tsMs),
      // Epoch-ms index for the retention sweep (DELETE WHERE tsMs < cutoff).
      idxFirewallEventsTsMs: index('idx_firewall_events_ts_ms').on(table.tsMs),
    };
  }
);

// Per-host firewall state-table snapshots pushed by plugins via POST
// /plugin/host-states (see routes/internal.ts) — one row per (device, host IP)
// per state-table walk. Powers the "States" columns on the Hosts + Networks
// pages: open states now = latest snapshot; created/destroyed over a window =
// SUM of the per-walk deltas inside that window. Append-only like
// firewall_events — growth is bounded by the retention worker after
// hostStateRetentionDays (see workers/hostStateRetention.ts). The churn deltas
// are NULL on a device's FIRST walk (no previous snapshot to diff against) and
// after plugin restarts — consumers must skip nulls, never treat them as 0.
export const hostStates = pgTable(
  'host_states',
  {
    id: text('id').primaryKey(),
    // Self-reported by the sender (its effectiveUuid); validated against the
    // plugins table at ingest — unknown ids are rejected with a 400.
    pluginId: text('pluginId').notNull(),
    deviceId: text('deviceId').notNull(),
    // One endpoint address of the state (src_addr or dst_addr on OPNsense,
    // src-address/dst-address on RouterOS). A single state contributes to TWO
    // rows — one per endpoint — so "open states" is a per-endpoint view.
    hostIp: text('hostIp').notNull(),
    // Epoch ms of the walk, stamped by the API at ingest (the plugin clock is
    // not trusted). The queryable time axis for window sums + retention.
    walkedAtMs: bigint('walkedAtMs', { mode: 'number' }).notNull(),
    // Open states touching this endpoint in THIS snapshot.
    openStates: integer('openStates').notNull().default(0),
    // States created since the previous walk (NULL = no baseline).
    createdSinceLastWalk: integer('createdSinceLastWalk'),
    // States destroyed since the previous walk (NULL = no baseline).
    destroyedSinceLastWalk: integer('destroyedSinceLastWalk'),
  },
  (table) => {
    return {
      idxHostStatesDeviceIpWalkedAt: index('idx_host_states_device_ip_walked_at').on(
        table.deviceId,
        table.hostIp,
        table.walkedAtMs,
      ),
      // Epoch-ms index for the retention sweep (DELETE WHERE walkedAtMs < cutoff).
      idxHostStatesWalkedAt: index('idx_host_states_walked_at').on(table.walkedAtMs),
    };
  }
);

// Self-metrics samples of the plugin processes themselves (see workers/pluginMetrics.ts).
// The API polls each registered plugin's GET /metrics endpoint (auto-mounted by
// @unm/plugin-sdk) and stores one row per sample. Powers the per-plugin health
// view in the webapp (CPU/memory/event-loop lag/poll duration/error rate).
export const pluginMetrics = pgTable(
  'plugin_metrics',
  {
    id: text('id').primaryKey(),
    pluginId: text('pluginId').notNull(),
    // Seconds since the plugin process started.
    uptimeSeconds: integer('uptimeSeconds'),
    heapUsedBytes: bigint('heapUsedBytes', { mode: 'number' }),
    heapTotalBytes: bigint('heapTotalBytes', { mode: 'number' }),
    rssBytes: bigint('rssBytes', { mode: 'number' }),
    // % of one core over the plugin's own sample window (can exceed 100).
    cpuPercent: doublePrecision('cpuPercent'),
    // Moving-average event-loop lag in ms.
    eventLoopLagMs: doublePrecision('eventLoopLagMs'),
    // Work requests (/monitoring, /config, /plan) being handled at sample time.
    inFlight: integer('inFlight'),
    lastPollMs: doublePrecision('lastPollMs'),
    // Failure rate of the plugin's last N work requests (0-100).
    errorRatePercent: doublePrecision('errorRatePercent'),
    // Metric keys in the plugin's last /monitoring payload.
    emittedMetricsCount: integer('emittedMetricsCount'),
    // Pending entries in the plugin logger queue (null = no logger registered).
    logQueueDepth: integer('logQueueDepth'),
    // ISO-8601 sample time, stamped by the API at ingest (server clock).
    sampledAt: text('sampledAt').notNull(),
  },
  (table) => {
    return {
      idxPluginMetricsPluginSampledAt: index('idx_plugin_metrics_plugin_sampled_at')
        .on(table.pluginId, table.sampledAt),
      // Plain sampledAt index for the retention sweep.
      idxPluginMetricsSampledAt: index('idx_plugin_metrics_sampled_at').on(table.sampledAt),
    };
  }
);

// Normalized inventory tables — populated by the telemetry worker from the
// plugin's /monitoring metrics (see workers/telemetry.ts ingestInventory).
// They power the cross-device Networks and Hosts pages in the webapp. Rows are
// upserted per poll; a periodic sweep drops rows not refreshed within 24h so
// offline devices don't accumulate stale data.

// One row per configured network (interface IP address) as reported by a
// plugin's `networks` metric: { name, ip, prefix, version ('v4'|'v6'), vlanId?,
// mac?, status? }. Interfaces without an IP are stored with ip = '' so their
// MAC/name stay available for topology detection.
// One row per (device, plugin) that can read a wall clock — the Time page's
// fast path. Populated by the telemetry worker from each poll's `system.deviceTime`
// metric; ONLY clock-capable plugins ever write here, so "newest row per device"
// is always valid clock data and never masked by an ICMP/SNMP poll (those emit no
// such key). Drift is computed at read time against the reading's own timestamp.
export const deviceTimes = pgTable(
  'device_times',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Device's local wall clock as reported (ISO-8601, may carry an offset).
    localIso: text('localIso'),
    // IANA timezone identifier when known.
    timezone: text('timezone'),
    // Fixed UTC offset in minutes baked into the reading (when no IANA zone).
    utcOffsetMinutes: integer('utcOffsetMinutes'),
    // Absolute instant pre-computed by the plugin, epoch ms (null = derive at read).
    epochMs: bigint('epochMs', { mode: 'number' }),
    collectedAt: text('collectedAt').notNull(),
    // NTP-served time (generic-ntp plugin's `system.ntpServed` metric) — the
    // instant the device SERVES over its NTP service, distinct from its own
    // system clock. NULL for every non-NTP assignment.
    ntpTimeUtc: text('ntpTimeUtc'),
    ntpEpochMs: bigint('ntpEpochMs', { mode: 'number' }),
    ntpStratum: integer('ntpStratum'),
    ntpReferenceId: text('ntpReferenceId'),
  },
  (table) => {
    return {
      // Name matches Postgres' auto-generated <table>_pkey (see networks above).
      pkDeviceTimes: primaryKey({
        name: 'device_times_pkey',
        columns: [table.deviceId, table.pluginId],
      }),
      idxDeviceTimesDevice: index('idx_device_times_device').on(table.deviceId),
    };
  }
);

// One row per configured PUBLIC NTP reference (the fleet's time-base check —
// Time page "Time base" card). Populated by the ntpReferences worker, which
// polls each server in the `ntpReferenceServers` setting with the SDK's
// queryNtp() and upserts here. driftMs = served instant − UNM clock at read
// time (same semantics as generic-ntp's ntp.driftMs): a large |drift| means
// UNM's own clock — and therefore every device synced to it — is off relative
// to the international consensus. Consensus itself (median of healthy rows)
// is computed at read time, never stored.
export const ntpReferenceReadings = pgTable(
  'ntp_reference_readings',
  {
    // Hostname or IP literal of the reference (port kept separately so a
    // host:port change doesn't orphan the row).
    server: text('server').primaryKey(),
    port: integer('port'),
    // ok | unreachable (no reply / DNS failure) | unsynced (stratum 0/15 or leap alarm)
    status: text('status').notNull().default('ok'),
    error: text('error').notNull().default(''),
    rttMs: integer('rttMs'),
    // Served instant − Date.now() at read time, ms (negative = UNM clock ahead).
    driftMs: bigint('driftMs', { mode: 'number' }),
    stratum: integer('stratum'),
    precision: integer('precision'),
    rootDelaySeconds: doublePrecision('rootDelaySeconds'),
    rootDispersionSeconds: doublePrecision('rootDispersionSeconds'),
    referenceId: text('referenceId').notNull().default(''),
    timeUtc: text('timeUtc').notNull().default(''),
    collectedAt: text('collectedAt').notNull(),
  }
);

export const networks = pgTable(
  'networks',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Interface name on the device (e.g. "lan", "vlan100").
    name: text('name').notNull(),
    // IP address; '' = interface without an IP (kept for topology detection).
    ip: text('ip').notNull().default(''),
    prefix: integer('prefix'),
    version: text('version'),
    vlanId: integer('vlanId'),
    mac: text('mac'),
    status: text('status'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      // Real composite PK — initDb() creates the table with this PRIMARY KEY,
      // so it MUST be declared here too or drizzle-kit push tries to delete it
      // and crashes on the diff. The name must match what Postgres auto-generates
      // (<table>_pkey) because drizzle-kit matches composite PKs by constraint
      // name; any other name makes push plan a drop+recreate of every PK.
      pkNetworks: primaryKey({
        name: 'networks_pkey',
        columns: [table.deviceId, table.pluginId, table.name, table.ip],
      }),
      uqNetworks: uniqueIndex('uq_networks')
        .on(table.deviceId, table.pluginId, table.name, table.ip),
      idxNetworksDevice: index('idx_networks_device').on(table.deviceId),
    };
  }
);

// One row per discovered host (neighbor/lease/client) as reported by a
// plugin's `arp` / `ndp` / `dhcpLeases` / `wlanClients` metrics. A host seen
// via several sources gets one row per source (the DHCP row carries
// hostname/expiry, ARP rows carry manufacturer). `lastSeenAt` drives the 24h
// stale sweep.
export const hosts = pgTable(
  'hosts',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    mac: text('mac').notNull(),
    ip: text('ip').notNull(),
    // arp | ndp | dhcp | wlan | mac — which table/lease source reported this
    // host ('mac' = switch MAC table, IP-less rows).
    source: text('source').notNull(),
    hostname: text('hostname'),
    manufacturer: text('manufacturer'),
    intf: text('intf'),
    expiry: text('expiry'),
    lastSeenAt: text('lastSeenAt').notNull(),
  },
  (table) => {
    return {
      // Name matches Postgres' auto-generated <table>_pkey (see networks above).
      pkHosts: primaryKey({
        name: 'hosts_pkey',
        columns: [table.deviceId, table.pluginId, table.mac, table.ip, table.source],
      }),
      uqHosts: uniqueIndex('uq_hosts')
        .on(table.deviceId, table.pluginId, table.mac, table.ip, table.source),
      idxHostsDevice: index('idx_hosts_device').on(table.deviceId),
      // For the future topology view: "which devices see this MAC / IP".
      idxHostsMac: index('idx_hosts_mac').on(table.mac),
      idxHostsIp: index('idx_hosts_ip').on(table.ip),
    };
  }
);

// One row per configured tunnel (WireGuard/OpenVPN/IPsec/PPPoE/GRE) as reported
// by a plugin's `tunnels` metric. Powers the cross-device Tunnels page, same
// upsert-per-poll + 24h-sweep lifecycle as networks/hosts. A device without any
// tunnels simply contributes no rows (switches/APs never emit this key).
export const tunnels = pgTable(
  'tunnels',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Tunnel/interface name on the device (e.g. "wg0", "IPSEC-1", "gre1").
    name: text('name').notNull(),
    // wireguard | openvpn | ipsec | pppoe | gre — normalized to lowercase at ingest.
    type: text('type').notNull(),
    // Remote endpoint (peer IP/FQDN, remote gateway, GRE destination). '' = unknown.
    peerAddress: text('peerAddress').notNull().default(''),
    // Local side of the tunnel (WG server IP, local gateway, PPPoE WAN IP). '' = unknown.
    localAddress: text('localAddress').notNull().default(''),
    // Tunnel subnet / assigned network (e.g. "10.99.0.0/24"). null = n/a.
    subnet: text('subnet'),
    // up | down | enabled | disabled — plugins report what they can observe.
    status: text('status').notNull().default('unknown'),
    // Live session uptime in seconds (null when not a live-session metric).
    uptimeSeconds: doublePrecision('uptimeSeconds'),
    // Seconds since the last handshake (WireGuard peers; null = no live data).
    lastHandshakeSeconds: doublePrecision('lastHandshakeSeconds'),
    // Kernel interface carrying the tunnel traffic (display + rate context).
    interfaceName: text('interfaceName'),
    // Per-tunnel traffic rates (bytes/s), computed plugin-side as counter deltas.
    rxRate: doublePrecision('rxRate'),
    txRate: doublePrecision('txRate'),
    // Type-specific extras (JSON object): ikeType, cryptAlg, mode, allowedIPs, ...
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      // Name matches Postgres' auto-generated <table>_pkey (see networks above).
      pkTunnels: primaryKey({
        name: 'tunnels_pkey',
        columns: [table.deviceId, table.pluginId, table.name, table.type],
      }),
      idxTunnelsDevice: index('idx_tunnels_device').on(table.deviceId),
    };
  }
);

// One row per route entry on one device, as reported by a plugin's `routes`
// metric. Powers the cross-device Routes page, same upsert-per-poll + 24h-sweep
// lifecycle as networks/hosts/tunnels. A device without routing data (e.g. an AP)
// simply contributes no rows. `protocol` is part of the PK so static and
// dynamically-learned routes to the same destination coexist.
export const routes = pgTable(
  'routes',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Destination network as CIDR (e.g. "10.25.0.0/16", "default" → "0.0.0.0/0").
    destination: text('destination').notNull(),
    // Next-hop gateway address or name ('' = directly connected / unknown).
    gateway: text('gateway').notNull().default(''),
    // static | connected | ospf | bgp | rip | other — normalized at ingest.
    protocol: text('protocol').notNull().default('static'),
    // Administrative distance (null when the source doesn't expose it).
    distance: doublePrecision('distance'),
    // Route metric / cost (null when n/a).
    metric: doublePrecision('metric'),
    mtu: integer('mtu'),
    // active | inactive | unknown — plugins report what they can observe.
    status: text('status').notNull().default('unknown'),
    // Protocol-specific extras (JSON object): uuid, description,
    // gatewayStatus/gatewayLatencyMs (OPNsense), rtgTag/peer/rawType (LCOS) …
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      // Name matches Postgres' auto-generated <table>_pkey (see networks above).
      pkRoutes: primaryKey({
        name: 'routes_pkey',
        columns: [table.deviceId, table.pluginId, table.destination, table.protocol],
      }),
      idxRoutesDevice: index('idx_routes_device').on(table.deviceId),
    };
  }
);

// One row per static DNS host entry (hostname → address) on one device, as
// reported by a plugin's `dnsEntries` metric. Powers the cross-device DNS page
// with the same upsert-per-poll + delete-on-absent + 24h-sweep lifecycle as
// tunnels/routes. Vendors normalize to {name, ip} at collection time (OPNsense
// dnsmasq/unbound host records; OpenWrt uci dhcp @host/@map; RouterOS
// /ip/dns/static; LCOS Setup/DNS/DNS-List). `name` is lowercased at ingest so
// the page groups case-insensitively; one row per (device, name, ip) — a name
// with several addresses yields multiple rows.
export const deviceDnsEntries = pgTable(
  'device_dns_entries',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Hostname as configured on the device, lowercased at ingest (grouping key).
    name: text('name').notNull(),
    // IPv4 or IPv6 address the hostname resolves to. Record type (A/AAAA) is
    // derived from the address shape — no separate column needed.
    ip: text('ip').notNull(),
    // Optional domain suffix as configured on the device. Only vendors that
    // split a record into bare-hostname + domain emit it (OPNsense unbound
    // host overrides); for them `name` is the bare hostname and the full name
    // is `name`.`domain`. NULL = vendor has no separate domain field (the name
    // already IS the full name — LCOS, RouterOS, OpenWrt).
    domain: text('domain'),
    // Optional free-text note as configured on the device (e.g. RouterOS
    // /ip/dns/static `comment`). NULL = vendor has no native field for it.
    description: text('description'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkDnsEntries: primaryKey({
        name: 'device_dns_entries_pkey',
        columns: [table.deviceId, table.pluginId, table.name, table.ip],
      }),
      idxDnsEntriesDevice: index('idx_device_dns_entries_device').on(table.deviceId),
    };
  }
);

// One row per configured DHCP server network/pool on one device, as reported by a
// plugin's `dhcpNetworks` metric. Powers the cross-device DHCP page with the same
// upsert-per-poll + delete-on-absent + 24h-sweep lifecycle as tunnels/routes/dns.
// Vendors normalize to {name, rangeStart, rangeEnd, …} at collection time (RouterOS
// /ip/pool + /ip/dhcp-server/network; OPNsense Kea subnets or dnsmasq ranges; OpenWrt
// uci dhcp .option=range). One row per (device, plugin, name, rangeStart) — a named
// scope with several ranges yields multiple rows.
export const deviceDhcpNetworks = pgTable(
  'device_dhcp_networks',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Network/scope name as configured, or the serving interface when the vendor has no name.
    name: text('name').notNull(),
    // Serving interface (e.g. `bridge1`, `lan`). NULL = vendor doesn't expose it.
    iface: text('iface'),
    // First address of the lease range. Part of the PK — a scope with several ranges yields rows.
    rangeStart: text('rangeStart').notNull(),
    // Last address of the lease range.
    rangeEnd: text('rangeEnd').notNull(),
    // Subnet CIDR covering the range (derived by the plugin when known). NULL = unknown.
    cidr: text('cidr'),
    // Lease time in seconds as configured on the device. NULL = vendor default / not exposed.
    leaseTimeSeconds: integer('leaseTimeSeconds'),
    // Gateway address handed out to clients. NULL = not exposed.
    gateway: text('gateway'),
    // DNS servers handed out to clients (comma-joined). NULL = not exposed.
    dnsServers: text('dnsServers'),
    // Vendor-side row identity used for deletion (dnsmasq range uuid, Kea subnet id…). NULL = no stable handle.
    refId: text('refId'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkDhcpNetworks: primaryKey({
        name: 'device_dhcp_networks_pkey',
        columns: [table.deviceId, table.pluginId, table.name, table.rangeStart],
      }),
      idxDhcpNetworksDevice: index('idx_device_dhcp_networks_device').on(table.deviceId),
    };
  }
);

// One row per static DHCP reservation (MAC → fixed IP) on one device, as reported by a
// plugin's `dhcpReservations` metric. Same lifecycle as the other inventory tables.
// Vendors normalize to {mac, ip?, hostname?} at collection time (RouterOS
// /ip/dhcp-server/lease static; OPNsense Kea reservations or dnsmasq staticmaps; OpenWrt
// uci dhcp @host/@map). `refId` is the vendor-side row identity used for deletion
// (OPNsense uuid, …); NULL = delete by MAC. One row per (device, plugin, mac) — a MAC
// with several fixed IPs on one device collapses to the last-seen IP (rare; vendors
// key reservations by MAC).
export const deviceDhcpReservations = pgTable(
  'device_dhcp_reservations',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Client MAC address, lowercase colon form. Part of the PK.
    mac: text('mac').notNull(),
    // Fixed IP the client always receives. NULL = name-only mapping (no fixed IP).
    ip: text('ip'),
    // Hostname bound to the reservation (when the vendor has one).
    hostname: text('hostname'),
    // Serving interface the mapping is scoped to (OPNsense staticmaps are per-interface). NULL = not exposed.
    iface: text('iface'),
    // Vendor-specific row identifier used for deletion (OPNsense uuid, …). NULL = delete by MAC.
    refId: text('refId'),
    // Vendor lease status when exposed (e.g. RouterOS 'bound'/'free') — some vendors keep
    // static bindings and active dynamic leases in one table; the page badges live rows.
    status: text('status'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkDhcpReservations: primaryKey({
        name: 'device_dhcp_reservations_pkey',
        columns: [table.deviceId, table.pluginId, table.mac],
      }),
      idxDhcpReservationsDevice: index('idx_device_dhcp_reservations_device').on(table.deviceId),
    };
  }
);

// One row per firewall rule (filter + NAT kinds) on one device, as reported by a
// plugin's `firewallRules` metric. Powers the cross-device Firewall page with the
// same upsert-per-poll + delete-on-absent + 24h-sweep lifecycle as tunnels/routes.
// Vendors normalize to this unified shape at collection time (OPNsense filter/
// dnat/snat/one-to-one/npt; RouterOS filter + nat chains). `vendorRuleId` is the
// stable identity (OPNsense uuid / RouterOS .id); `position` is display data only,
// so reordering rules on a device never churns rows.
export const firewallRules = pgTable(
  'firewall_rules',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // filter | dnat | snat | one-to-one | npt — normalized to lowercase at ingest.
    ruleType: text('ruleType').notNull(),
    // Stable vendor-side identity (OPNsense uuid, RouterOS .id). Part of the PK.
    vendorRuleId: text('vendorRuleId').notNull(),
    // Order within its rule set on the device (0-based array index at collection).
    position: integer('position').notNull().default(0),
    // IP family the rule applies to — v4 | v6 | both. OPNsense reports it directly
    // (family/ipprotocol); RouterOS derives it from the address text.
    ipVersion: text('ipVersion').notNull().default('v4'),
    // Normalized protocol name ('tcp', 'udp', 'icmp', …; '' = any/unknown).
    protocol: text('protocol').notNull().default(''),
    // Source network/CIDR or alias name as configured. '' = any.
    sourceIp: text('sourceIp').notNull().default(''),
    // Destination network/CIDR or alias name as configured. '' = any.
    destIp: text('destIp').notNull().default(''),
    // Source port(s) — single port or range string (null when n/a).
    sourcePort: text('sourcePort'),
    // Destination port(s) — single port or range string (null when n/a).
    destPort: text('destPort'),
    // allow | deny | other — normalized at ingest (NAT actions map to 'other').
    action: text('action').notNull().default('other'),
    enabled: boolean('enabled').notNull().default(true),
    // Rule description / comment ('' = none).
    description: text('description').notNull().default(''),
    // Where the rule applies (OPNsense interface, RouterOS chain + iface lists).
    scope: text('scope').notNull().default(''),
    // Live per-rule traffic counters (null when the vendor doesn't expose them):
    // packets/bytes matched by this rule since boot; states = active pf states
    // (OPNsense only — RouterOS/LCOS have no stateful counter).
    packets: doublePrecision('packets'),
    bytes: doublePrecision('bytes'),
    states: integer('states'),
    // Vendor-specific extras (JSON object): uuid, family, log, tag, quick, state,
    // resolvedSource/resolvedDest (alias expansion), connection-state, time,
    // address-list, to-addresses/to-ports …
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkFirewallRules: primaryKey({
        name: 'firewall_rules_pkey',
        columns: [table.deviceId, table.pluginId, table.ruleType, table.vendorRuleId],
      }),
      idxFirewallRulesDevice: index('idx_firewall_rules_device').on(table.deviceId),
    };
  }
);

// One row per service on one device, as reported by a plugin's `services`
// metric. Powers the cross-device Services page with the same upsert-per-poll +
// delete-on-absent + 24h-sweep lifecycle as tunnels/routes. Vendors normalize to
// this unified shape at collection time (OPNsense rc services, TrueNAS middleware
// services, generic Linux systemd/OpenRC/runit/SysVinit). `type` is part of the
// PK so a service managed by two frameworks on one box coexists.
export const deviceServices = pgTable(
  'device_services',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Service name on the device ("sshd", "smb", "unbound", "nginx.service").
    name: text('name').notNull(),
    // systemd | openrc | runit | sysvinit | freebsd-rc | truenas — normalized
    // to lowercase at ingest; unknown labels are kept as-is (free-form).
    type: text('type').notNull().default('unknown'),
    // running | stopped | failed | unknown — plugins report what they can observe.
    status: text('status').notNull().default('unknown'),
    // True when the service is enabled to start on boot (null = not observable).
    enabled: boolean('enabled'),
    // Main process id (null when stopped or not a live-process metric).
    pid: integer('pid'),
    // Human description from the vendor ('' = none).
    description: text('description').notNull().default(''),
    // Vendor-specific extras (JSON object): systemd sub-state, TrueNAS matched
    // process command line, rcctl status detail …
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkDeviceServices: primaryKey({
        name: 'device_services_pkey',
        columns: [table.deviceId, table.pluginId, table.name, table.type],
      }),
      idxDeviceServicesDevice: index('idx_device_services_device').on(table.deviceId),
    };
  }
);

// One row per mail domain on one device, as reported by a plugin's `mailDomains`
// metric (mailcow today). Powers the cross-device Mail page with the same
// upsert-per-poll + delete-on-absent + 24h-sweep lifecycle as services. Identity
// is the domain name; quota columns are bytes in double precision (they exceed
// int32 for anything beyond ~2 GB).
export const mailDomains = pgTable(
  'mail_domains',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // FQDN of the domain ("example.com"). Part of PK.
    domain: text('domain').notNull(),
    active: boolean('active').notNull().default(false),
    description: text('description').notNull().default(''),
    // Total quota for all mailboxes in this domain, bytes (null = unlimited/unknown).
    quotaBytes: doublePrecision('quotaBytes'),
    // Per-mailbox quota ceiling within the domain, bytes.
    maxQuotaPerMailboxBytes: doublePrecision('maxQuotaPerMailboxBytes'),
    // Default quota applied to new mailboxes in this domain, bytes.
    defaultQuotaBytes: doublePrecision('defaultQuotaBytes'),
    mailboxCount: integer('mailboxCount'),
    aliasCount: integer('aliasCount'),
    backupMx: boolean('backupMx').notNull().default(false),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkMailDomains: primaryKey({
        name: 'mail_domains_pkey',
        columns: [table.deviceId, table.pluginId, table.domain],
      }),
      idxMailDomainsDevice: index('idx_mail_domains_device').on(table.deviceId),
    };
  }
);

// One row per mailbox on one device, as reported by a plugin's `mailMailboxes`
// metric. Same lifecycle as mailDomains; identity is the full username (email).
export const mailMailboxes = pgTable(
  'mail_mailboxes',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Full address ("user@example.com"). Part of PK.
    username: text('username').notNull(),
    domain: text('domain').notNull().default(''),
    localPart: text('localPart').notNull().default(''),
    name: text('name').notNull().default(''),
    active: boolean('active').notNull().default(false),
    quotaBytes: doublePrecision('quotaBytes'),
    quotaUsedBytes: doublePrecision('quotaUsedBytes'),
    messageCount: integer('messageCount'),
    forcePwUpdate: boolean('forcePwUpdate').notNull().default(false),
    forceTfa: boolean('forceTfa').notNull().default(false),
    sogoAccess: boolean('sogoAccess').notNull().default(false),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkMailMailboxes: primaryKey({
        name: 'mail_mailboxes_pkey',
        columns: [table.deviceId, table.pluginId, table.username],
      }),
      idxMailMailboxesDevice: index('idx_mail_mailboxes_device').on(table.deviceId),
    };
  }
);

// One row per alias on one device, as reported by a plugin's `mailAliases`
// metric. Same lifecycle; identity is the address (catch-all = "@domain.tld").
// mailcowId is the numeric id mailcow's edit/delete API requires — without it
// the webapp must refuse to offer update/delete for that row.
export const mailAliases = pgTable(
  'mail_aliases',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Alias address ("alias@example.com", catch-all "@example.com"). Part of PK.
    address: text('address').notNull(),
    domain: text('domain').notNull().default(''),
    // Comma-separated list of forwarding targets.
    goto: text('goto').notNull().default(''),
    active: boolean('active').notNull().default(false),
    isCatchAll: boolean('isCatchAll').notNull().default(false),
    // Mailbox-bound ("internal") alias — the address is attached to a specific
    // mailbox (mailcow's per-mailbox "Aliases" tab) instead of pure forwarding.
    isMailboxBound: boolean('isMailboxBound').notNull().default(false),
    // Whether the bound mailbox may send as this alias (false = receive-only).
    senderAllowed: boolean('senderAllowed').notNull().default(true),
    mailcowId: integer('mailcowId'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkMailAliases: primaryKey({
        name: 'mail_aliases_pkey',
        columns: [table.deviceId, table.pluginId, table.address],
      }),
      idxMailAliasesDevice: index('idx_mail_aliases_device').on(table.deviceId),
    };
  }
);

// One row per certificate endpoint on one device, as reported by a plugin's
// `certificates` metric. Powers the cross-device Certificates page with the same
// upsert-per-poll + delete-on-absent + 24h-sweep lifecycle as tunnels/routes.
// A device contributes an https row (the TLS cert served by its management
// endpoint) and/or an ssh row (the SSH host key on port 22). `name` is the stable
// identity ("https:443" / "ssh:22") so re-probes never churn rows. For ssh rows
// the X.509 fields are synthetic (no issuer/expiry) — only fingerprint + key
// algorithm/size are meaningful; `valid` reflects that a host key was read.
export const certificates = pgTable(
  'certificates',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Stable endpoint identity on the device, e.g. "https:443", "ssh:22". Part of PK.
    name: text('name').notNull(),
    // https | ssh — normalized to lowercase at ingest.
    type: text('type').notNull().default('https'),
    // Hostname/IP probed (the management address). '' = unknown.
    host: text('host').notNull().default(''),
    port: integer('port'),
    // SHA-256 fingerprint of the leaf cert / SSH host key ("SHA256:<base64>").
    fingerprint: text('fingerprint'),
    // The TRUSTED (pinned) fingerprint — what plugins verify against before
    // transmitting credentials. Seeded from `fingerprint` on first observation
    // (TOFU) and changed ONLY by explicit user acceptance (POST /certificates/accept).
    // A row where fingerprint !== trustedFingerprint is a live mismatch: strict
    // pinning refuses the connection until the new key is accepted or rolled back.
    trustedFingerprint: text('trustedFingerprint'),
    // Subject Common Name (ssh rows carry a synthetic label like "SSH Host Key").
    commonName: text('commonName').notNull().default(''),
    subject: text('subject').notNull().default(''),
    issuer: text('issuer').notNull().default(''),
    selfSigned: boolean('selfSigned').notNull().default(false),
    // Validity window (ISO). Empty for ssh host keys.
    notBefore: text('notBefore').notNull().default(''),
    notAfter: text('notAfter').notNull().default(''),
    keyAlgorithm: text('keyAlgorithm').notNull().default(''),
    keySizeBits: integer('keySizeBits'),
    curveName: text('curveName'),
    signatureAlgorithm: text('signatureAlgorithm').notNull().default(''),
    // SAN DNS names + IPs (JSON array). Empty for ssh rows.
    sanNames: text('sanNames').notNull().default('[]'),
    serialNumber: text('serialNumber').notNull().default(''),
    // Chain-validation verdict (null = unknown / not a cert, e.g. some ssh rows).
    valid: boolean('valid'),
    invalidReason: text('invalidReason'),
    // Days until the LEAF expires (negative = expired); null when n/a.
    daysToExpiry: integer('daysToExpiry'),
    // Days until the EARLIEST chain element expires — an issuer expiring before
    // its leaf is a real break even though the leaf itself is still valid.
    chainDaysToExpiry: integer('chainDaysToExpiry'),
    // Full served chain (leaf first) as JSON array of CertificateInfo objects.
    chain: text('chain').notNull().default('[]'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkCertificates: primaryKey({
        name: 'certificates_pkey',
        columns: [table.deviceId, table.pluginId, table.name],
      }),
      idxCertificatesDevice: index('idx_certificates_device').on(table.deviceId),
    };
  }
);

/**
 * Append-only history of certificate endpoints — one row per DISTINCT
 * fingerprint observed on an endpoint. The telemetry worker inserts a row when
 * an endpoint's fingerprint CHANGES (or first appears), so the Certificates page
 * can show "which key was used when" and users can audit re-keying events.
 * Identity is (deviceId, pluginId, name, fingerprint) — re-observing the same
 * key only refreshes `lastSeenAt`; a new key adds a row (the old one stays).
 */
export const certificateHistory = pgTable(
  'certificate_history',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Stable endpoint identity on the device, e.g. "https:443", "ssh:22". Part of PK.
    name: text('name').notNull(),
    // https | ssh — normalized to lowercase at ingest.
    type: text('type').notNull().default('https'),
    // SHA-256 fingerprint ("SHA256:<base64>"). Part of the PK — one row per key.
    fingerprint: text('fingerprint').notNull(),
    commonName: text('commonName').notNull().default(''),
    subject: text('subject').notNull().default(''),
    issuer: text('issuer').notNull().default(''),
    selfSigned: boolean('selfSigned').notNull().default(false),
    notBefore: text('notBefore').notNull().default(''),
    notAfter: text('notAfter').notNull().default(''),
    keyAlgorithm: text('keyAlgorithm').notNull().default(''),
    keySizeBits: integer('keySizeBits'),
    curveName: text('curveName'),
    signatureAlgorithm: text('signatureAlgorithm').notNull().default(''),
    // First time this fingerprint was observed on the endpoint.
    firstSeenAt: text('firstSeenAt').notNull(),
    // Last time it was still the current key (refreshed while unchanged).
    lastSeenAt: text('lastSeenAt').notNull(),
  },
  (table) => {
    return {
      pkCertificateHistory: primaryKey({
        name: 'certificate_history_pkey',
        columns: [table.deviceId, table.pluginId, table.name, table.fingerprint],
      }),
      idxCertHistoryDevice: index('idx_certificate_history_device').on(table.deviceId),
    };
  }
);

// One row per SSID×band as reported by a plugin's `wifiNetworks` metric.
// Powers the cross-device WiFi page (grouped by SSID name across devices).
export const wifiSsids = pgTable(
  'wifi_ssids',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // SSID / network name as broadcast.
    name: text('name').notNull(),
    // '2.4' | '5' | '6' — '' when the device cannot say which band (e.g. a
    // dual-band radio with one channel value). Rows with '' stay in the table
    // but are excluded from the spectrum view.
    band: text('band').notNull().default(''),
    // Channel number on this band (null when unknown).
    channel: integer('channel'),
    bssid: text('bssid'),
    // Security/encryption as reported ('WPA2-PSK' …); null = not exposed.
    encryption: text('encryption'),
    vlanId: integer('vlanId'),
    // Radio interface broadcasting this SSID (e.g. "WLAN-1") — shown on the
    // device chip in the webapp.
    ifc: text('ifc'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      // Name matches Postgres' auto-generated <table>_pkey (see networks above).
      pkWifiSsids: primaryKey({
        name: 'wifi_ssids_pkey',
        columns: [table.deviceId, table.pluginId, table.name, table.band],
      }),
      idxWifiSsidsDevice: index('idx_wifi_ssids_device').on(table.deviceId),
    };
  }
);

// One row per channel with an airtime-utilization sample (`wifiAirtime`
// metric). LX APs report a true per-channel table; LCOS routers emit their
// radio's utilization at the radio's own channel.
export const wifiChannels = pgTable(
  'wifi_channels',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    channel: integer('channel').notNull(),
    // Airtime utilization in percent (0–100); null when the device reports no
    // value for this channel.
    utilizationPct: doublePrecision('utilizationPct'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      // Name matches Postgres' auto-generated <table>_pkey (see networks above).
      pkWifiChannels: primaryKey({
        name: 'wifi_channels_pkey',
        columns: [table.deviceId, table.pluginId, table.channel],
      }),
      idxWifiChannelsDevice: index('idx_wifi_channels_device').on(table.deviceId),
    };
  }
);

// One row per radio as reported by a plugin's `wifiRadios` metric — powers the
// spectrum view's noise-floor line and bandwidth context on the WiFi page.
export const wifiRadios = pgTable(
  'wifi_radios',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Radio interface (e.g. "WLAN-1"); '' when the device does not name it —
    // NOT NULL so the conflict key stays reliable (NULLs are distinct in PG).
    ifc: text('ifc').notNull().default(''),
    // '2.4' | '5' | '6' — '' when the device cannot say which band (dual-band).
    band: text('band').notNull().default(''),
    channel: integer('channel'),
    bandwidthMhz: integer('bandwidthMhz'), // 20/40/80; null when unknown
    noiseFloorDbm: doublePrecision('noiseFloorDbm'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      // Name matches Postgres' auto-generated <table>_pkey (see networks above).
      pkWifiRadios: primaryKey({
        name: 'wifi_radios_pkey',
        columns: [table.deviceId, table.pluginId, table.ifc],
      }),
      idxWifiRadiosDevice: index('idx_wifi_radios_device').on(table.deviceId),
    };
  }
);

// One row per neighbor network seen by a device's scan engine (`wifiNeighbors`
// metric) — powers the scanner-style network list on the WiFi page. Upserted
// by BSSID; rows for networks that disappeared are dropped each snapshot.
export const wifiNeighbors = pgTable(
  'wifi_neighbors',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    bssid: text('bssid').notNull(),
    ssid: text('ssid'), // '' when hidden/unknown
    band: text('band').notNull().default(''),
    channel: integer('channel'),
    signalDbm: doublePrecision('signalDbm'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      // Name matches Postgres' auto-generated <table>_pkey (see networks above).
      pkWifiNeighbors: primaryKey({
        name: 'wifi_neighbors_pkey',
        columns: [table.deviceId, table.pluginId, table.bssid],
      }),
      idxWifiNeighborsDevice: index('idx_wifi_neighbors_device').on(table.deviceId),
    };
  }
);

// One row per associated WLAN client (`wlanClients` metric) — powers the
// per-SSID connected-client counts on the WiFi page. Upserted by MAC, so a
// roaming client keeps its latest SSID/radio.
export const wifiClients = pgTable(
  'wifi_clients',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    mac: text('mac').notNull(),
    ssid: text('ssid'),
    ip: text('ip'), // '' when the client has no address yet (counted, not joinable)
    hostname: text('hostname'),
    intf: text('intf'), // radio interface (e.g. "WLAN-1")
    signalDbm: doublePrecision('signalDbm'),
    txRateMbps: doublePrecision('txRateMbps'),
    rxRateMbps: doublePrecision('rxRateMbps'),
    vlanId: integer('vlanId'),
    lastSeenAt: text('lastSeenAt').notNull(),
  },
  (table) => {
    return {
      // Name matches Postgres' auto-generated <table>_pkey (see networks above).
      pkWifiClients: primaryKey({
        name: 'wifi_clients_pkey',
        columns: [table.deviceId, table.pluginId, table.mac],
      }),
      idxWifiClientsDevice: index('idx_wifi_clients_device').on(table.deviceId),
    };
  }
);

// One row per network port/interface as reported by a plugin's `ports` metric.
// Powers the per-device Config page (and future cross-device port views). Same
// upsert-per-poll + delete-on-absent lifecycle as tunnels/routes: ports are
// config objects, so a removed interface must vanish from the table, not linger
// until the 24h sweep. `name` is part of the PK — one row per (device, plugin,
// port-name). A device without port data contributes no rows.
export const devicePorts = pgTable(
  'device_ports',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Port/interface label on the device (e.g. "P1", "opt0", "port 4").
    name: text('name').notNull(),
    // up | down | enabled | disabled | unknown — normalized to lowercase at ingest.
    status: text('status').notNull().default('unknown'),
    speed: text('speed'),
    duplex: text('duplex'),
    vlanId: integer('vlanId'),
    poe: text('poe'),
    // Port-specific extras (JSON object): allowedVlans, lacpKey, macs[], ...
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      // Name matches Postgres' auto-generated <table>_pkey (see networks above).
      pkDevicePorts: primaryKey({
        name: 'device_ports_pkey',
        columns: [table.deviceId, table.pluginId, table.name],
      }),
      idxDevicePortsDevice: index('idx_device_ports_device').on(table.deviceId),
    };
  }
);

// User-assigned port roles (uplink / trunk) — persistent, per device+plugin+port.
// Complements the LIVE trunk detection from preflight: a marked-uplink port is
// always offered in the rollout dialog's "Uplinks" quick-select even when the
// live probe cannot see multi-VLAN tagging. One role per port (uplink implies
// trunk for selection purposes).
export const devicePortRoles = pgTable(
  'device_port_roles',
  {
    id: text('id').primaryKey(),
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Port/interface label on the device (matches preflight port names).
    portName: text('portName').notNull(),
    role: text('role').notNull(), // 'uplink' | 'trunk'
    note: text('note'),
    createdAt: text('createdAt').notNull(),
  },
  (table) => {
    return {
      uqDevicePortRoles: uniqueIndex('uq_device_port_roles').on(table.deviceId, table.pluginId, table.portName),
    };
  }
);

// One row per filesystem/pool/dataset as reported by a plugin's `filesystems`
// metric. Powers the top table of the cross-device Storage page. Same
// upsert-per-poll + delete-on-absent lifecycle as tunnels/routes: filesystems
// are config objects, so a removed dataset must vanish from the table, not
// linger until the 24h sweep. `name` is part of the PK — one row per
// (device, plugin, filesystem-name). A device without storage data contributes
// no rows.
export const storageFilesystems = pgTable(
  'storage_filesystems',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Filesystem/pool/dataset name as reported (e.g. "DATA01", "/mnt/tank/vm").
    name: text('name').notNull(),
    // zfs-pool | zfs-dataset | ext4 | squashfs | usb | other — normalized to
    // lowercase at ingest; 'other' when the plugin does not classify.
    type: text('type').notNull().default('other'),
    // Mountpoint (null for unmounted datasets / pools without a mount).
    mountpoint: text('mountpoint'),
    sizeBytes: doublePrecision('sizeBytes'),
    usedBytes: doublePrecision('usedBytes'),
    freeBytes: doublePrecision('freeBytes'),
    // ONLINE | DEGRADED | OFFLINE | ... (ZFS) or up/down/unknown — normalized
    // to lowercase at ingest.
    status: text('status').notNull().default('unknown'),
    // Parent pool name for datasets (null for top-level pools/filesystems).
    parent: text('parent'),
    // Plugin-specific details (JSON object): ZFS dataset props (quota, used-bytes,
    // compression, mount options), disk extras, ... — consumed by the webapp's
    // expandable rows and later config/state endpoints. Never validated beyond
    // being a JSON object; plugins evolve independently of the API.
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkStorageFilesystems: primaryKey({
        name: 'storage_filesystems_pkey',
        columns: [table.deviceId, table.pluginId, table.name],
      }),
      idxStorageFilesystemsDevice: index('idx_storage_filesystems_device').on(table.deviceId),
    };
  }
);

// One row per physical disk/flash device as reported by a plugin's `disks`
// metric. Powers the bottom table of the cross-device Storage page (the media
// the filesystems above are stored on). Same lifecycle as storage_filesystems.
export const storageDisks = pgTable(
  'storage_disks',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Disk name/identifier (e.g. "da0", "sda", serial-based id).
    name: text('name').notNull(),
    model: text('model'),
    serial: text('serial'),
    capacityBytes: doublePrecision('capacityBytes'),
    // hdd | ssd | flash | unknown — rotation-rate class.
    rotationRate: text('rotationRate').notNull().default('unknown'),
    // healthy | degraded | failed | unknown (lowercase at ingest).
    health: text('health').notNull().default('unknown'),
    // Pool this disk belongs to (null for unassigned/boot disks).
    poolName: text('poolName'),
    // Plugin-specific details (JSON object): temperature, power state, ... —
    // same contract as storage_filesystems.extra.
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkStorageDisks: primaryKey({
        name: 'storage_disks_pkey',
        columns: [table.deviceId, table.pluginId, table.name],
      }),
      idxStorageDisksDevice: index('idx_storage_disks_device').on(table.deviceId),
    };
  }
);

// One row per file-share export on one device, as reported by a plugin's
// `shares` metric. Powers the cross-device Shares page (SMB/CIFS, NFS, iSCSI and
// NVMe-oF shares). Same upsert-per-poll + delete-on-absent lifecycle as
// storage_filesystems: a share removed on the device must vanish from the table,
// not linger until the 24h sweep. `type` is part of the PK so two protocols that
// happen to reuse a name (e.g. an SMB and an NFS export both called "tank") can
// coexist on one device. A device without share data contributes no rows.
export const shares = pgTable(
  'shares',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Share/export name as reported (e.g. "tank", "public", "iscsi0").
    name: text('name').notNull(),
    // smb | nfs | iscsi | nvmeof — normalized to lowercase at ingest.
    type: text('type').notNull().default('other'),
    // The dataset/path backing the share (e.g. "/mnt/tank", "tank/public").
    path: text('path'),
    // up | down | enabled | disabled | unknown — plugins report what they can observe.
    status: text('status').notNull().default('unknown'),
    // Number of active client sessions on this share (null when not observable).
    sessionCount: integer('sessionCount'),
    // Type-specific extras (JSON object): smb {comment, users[], acl}, nfs {hosts[],
    // read-only flag}, iscsi {target, luns[]}, nvmeof {subsystem, namespaces[]} — same
    // contract as storage_filesystems.extra.
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkShares: primaryKey({
        name: 'shares_pkey',
        columns: [table.deviceId, table.pluginId, table.name, table.type],
      }),
      idxSharesDevice: index('idx_shares_device').on(table.deviceId),
    };
  }
);

// One row per ACTIVE file-share client session on one device, as reported by a
// plugin's `shareSessions` metric. Powers the bottom panel of the Shares page —
// live CIFS/SMB and NFS connections (who is connected to which share right now).
// These are LIVE state, not config: they change every poll, so the table is
// REPLACED wholesale per device+plugin each cycle (delete-all-then-insert) rather
// than upserted — a session that closed simply does not reappear. A device whose
// plugin reports no sessions contributes an empty set (authoritative wipe).
export const shareSessions = pgTable(
  'share_sessions',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // smb | nfs — the protocol of this session.
    type: text('type').notNull().default('smb'),
    // Share/export name the client is connected to (e.g. "tank").
    shareName: text('shareName').notNull(),
    // Client host address (IP or hostname as reported). '' = unknown.
    clientAddress: text('clientAddress').notNull().default(''),
    // Client username (SMB); null for NFS (no per-user identity in the session table).
    user: text('user'),
    // Seconds this session has been open (null when not observable).
    uptimeSeconds: doublePrecision('uptimeSeconds'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      idxShareSessionsDevice: index('idx_share_sessions_device').on(table.deviceId),
    };
  }
);

// One row per App/container workload as reported by a plugin's `containers`
// metric. Powers the cross-device Containers page (TrueNAS SCALE Apps today;
// any plugin may emit the generic key). Same upsert-per-poll + delete-on-absent
// lifecycle as storage_filesystems: an uninstalled app must vanish from the
// table, not linger until the 24h sweep. `name` is part of the PK — one row per
// (device, plugin, app-name). A device without container data contributes no rows.
export const containers = pgTable(
  'containers',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // App/container name as reported (e.g. "radius05", "zabbix05-proxy12").
    name: text('name').notNull(),
    // RUNNING | STOPPED | ... — normalized to uppercase at emit, kept verbatim.
    state: text('state').notNull().default('UNKNOWN'),
    // Container image (single-container apps; null for multi-service workloads).
    image: text('image'),
    // Human version string from the app catalog ("1.0.0_custom").
    version: text('version'),
    // True when an app or image update is available on the appliance.
    upgradeAvailable: boolean('upgradeAvailable'),
    // UNM-observed start of the current RUNNING period (ISO-8601). The TrueNAS
    // public API exposes NO container start-time, so this is tracked by the
    // telemetry worker from state transitions: stamped when a row first appears
    // RUNNING and cleared when it leaves RUNNING. NULL for non-RUNNING rows or
    // apps observed already-running (true uptime unknown — UI shows "≥ X").
    startedAt: text('startedAt'),
    // Plugin-specific details (JSON object): networks[] {name, driver?, subnets?},
    // ips[], ports[], containerCount, containers[] per-service detail, volumeMounts[].
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkContainers: primaryKey({
        name: 'containers_pkey',
        columns: [table.deviceId, table.pluginId, table.name],
      }),
      idxContainersDevice: index('idx_containers_device').on(table.deviceId),
    };
  }
);

// One row per docker image as reported by a plugin's `images` metric. Powers
// the collapsible "Docker images" panel on the Containers page (same layout
// pattern as storage_disks under the Storage page). Same upsert-per-poll +
// delete-on-absent lifecycle as containers: an image removed from the host must
// vanish, not linger until the 24h sweep. `name` is part of the PK — one row
// per (device, plugin, image-name); a device without image data contributes no rows.
export const dockerImages = pgTable(
  'docker_images',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Full image reference (e.g. "nginx:1.27-alpine", "ghcr.io/x/y@sha256:...").
    name: text('name').notNull(),
    // Image size in bytes (compressed on the registry / unpacked on disk,
    // depending on source — plugins report what their API exposes).
    sizeBytes: doublePrecision('sizeBytes'),
    // ISO-8601 creation timestamp of the image.
    createdAt: text('createdAt'),
    // True when a newer version is available (TrueNAS app.image.update_available;
    // always null for plain Docker hosts — no registry check).
    updateAvailable: boolean('updateAvailable'),
    // True for dangling images (<none>:<none> / unreferenced layers).
    dangling: boolean('dangling').notNull().default(false),
    // Plugin-specific details (JSON object) stored verbatim.
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkDockerImages: primaryKey({
        name: 'docker_images_pkey',
        columns: [table.deviceId, table.pluginId, table.name],
      }),
      idxDockerImagesDevice: index('idx_docker_images_device').on(table.deviceId),
    };
  }
);

// One row per GPU as reported by a plugin's `gpus` metric. Powers the
// per-device GPU cards on DeviceDetail (rendered via the generic table
// MetricView — no dedicated page yet). Same upsert-per-poll + delete-on-absent
// lifecycle as containers/vms: a removed card must vanish, not linger until the
// 24h sweep. `slot` is part of the PK — one row per (device, plugin, PCI slot);
// a device without GPU data contributes no rows.
export const gpus = pgTable(
  'gpus',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Human-readable card name (e.g. "NVIDIA GeForce RTX 3080", "AMD Radeon RX 6800",
    // "Intel UHD Graphics 770"). Falls back to the PCI slot when unknown.
    name: text('name').notNull(),
    // NVIDIA | AMD | INTEL | UNKNOWN — vendor family (case-insensitive at emit).
    vendor: text('vendor').notNull().default('UNKNOWN'),
    // PCI address, e.g. "0000:41:00.0" — the stable identity of a card.
    slot: text('slot').notNull(),
    // Kernel driver bound to the device (nvidia, amdgpu, i915, xe, ...).
    driver: text('driver'),
    // Driver version string when the vendor tool reports one (e.g. nvidia-smi's
    // "Driver Version: 550.90.07"); null for sysfs-only detection.
    driverVersion: text('driverVersion'),
    // Total VRAM in bytes (null = unknown / no dedicated memory).
    vramBytes: doublePrecision('vramBytes'),
    // Live utilization % (GPU core) — null when the vendor tool is unavailable
    // or the card has no such counter.
    utilPercent: integer('utilPercent'),
    // VRAM utilization % (NVIDIA only; AMD/Intel expose no equivalent).
    memUtilPercent: integer('memUtilPercent'),
    // Temperature in °C.
    tempCelsius: integer('tempCelsius'),
    // Power draw in watts.
    powerWatts: doublePrecision('powerWatts'),
    // Current core clock in MHz (null = not reported / iGPU).
    coreClockMhz: integer('coreClockMhz'),
    // Max supported core clock in MHz.
    maxCoreClockMhz: integer('maxCoreClockMhz'),
    // Plugin-specific details (JSON object) stored verbatim — e.g. TrueNAS's
    // available_to_host / uses_system_critical_devices, per-container device requests.
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkGpus: primaryKey({
        name: 'gpus_pkey',
        columns: [table.deviceId, table.pluginId, table.slot],
      }),
      idxGpusDevice: index('idx_gpus_device').on(table.deviceId),
    };
  }
);

// One row per virtual machine as reported by a plugin's `vms` metric. Powers
// the cross-device VMs page (TrueNAS SCALE VMs today; any plugin may emit the
// generic key — e.g. a future Proxmox plugin). Same upsert-per-poll +
// delete-on-absent lifecycle as containers: a deleted VM must vanish from the
// table, not linger until the 24h sweep. `name` is part of the PK — one row
// per (device, plugin, vm-name). A device without VM data contributes no rows.
export const vms = pgTable(
  'vms',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // VM name as reported (e.g. "win11-01").
    name: text('name').notNull(),
    // RUNNING | STOPPED | SUSPENDED | ... — normalized to uppercase at emit, kept verbatim.
    state: text('state').notNull().default('UNKNOWN'),
    // Number of virtual CPUs allocated to the VM.
    vcpus: integer('vcpus'),
    // Memory allocated in MiB (TrueNAS reports MiB; plugins convert as needed).
    memoryMiB: doublePrecision('memoryMiB'),
    // Guest architecture / machine type when reported (e.g. "x86_64", "q35").
    archType: text('archType'),
    // UNM-observed start of the current RUNNING period (ISO-8601) — tracked by
    // the telemetry worker from state transitions, same contract as containers.
    startedAt: text('startedAt'),
    // Plugin-specific details (JSON object): nics[] {mac, type?, nicAttach?},
    // disks[], description, uuid, autostart, ...
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkVms: primaryKey({
        name: 'vms_pkey',
        columns: [table.deviceId, table.pluginId, table.name],
      }),
      idxVmsDevice: index('idx_vms_device').on(table.deviceId),
    };
  }
);

// One row per available update as reported by a plugin's `updates` metric
// (capability 'updates'). Powers the cross-device Updates page. Same upsert +
// delete-on-absent lifecycle as containers: an update that is no longer
// reported (applied, or the package manager found nothing) must vanish on the
// next inventory poll, not linger until the 24h sweep. `name` is part of the PK
// — one row per (device, plugin, kind, name): "os" for firmware, a package
// name for os-package rows, an app/image name otherwise. Rows with available=
// false are dropped at ingest time; only genuinely available updates persist.
export const deviceUpdates = pgTable(
  'device_updates',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // firmware | os-package | docker-image | app (plugins may emit custom kinds).
    kind: text('kind').notNull().default('firmware'),
    // Stable identity within (device, plugin, kind): "os", package name, ...
    name: text('name').notNull(),
    currentVersion: text('currentVersion'),
    latestVersion: text('latestVersion'),
    rebootRequired: boolean('rebootRequired'),
    sizeBytes: doublePrecision('sizeBytes'),
    // Vendor release-notes URL for this update (changelog page, docs anchor).
    releaseNotesUrl: text('releaseNotesUrl'),
    // Release-notes TEXT propagated from the device's own update feed
    // (e.g. TrueNAS `update.available_versions`) — rendered inline in the UI.
    releaseNotes: text('releaseNotes'),
    // The device's current update branch/channel (TrueNAS profile, distro line,
    // vendor firmware track) — shown in the Updates page Branch column.
    branch: text('branch'),
    // Catalog action id (of THIS plugin) that applies this row — the webapp's
    // Update button fires it through the plan workflow. NULL = no apply path.
    applyActionId: text('applyActionId'),
    // Prefilled input for applyActionId (JSON object).
    applyInput: text('applyInput').notNull().default('{}'),
    // Plugin-specific details (JSON object) stored verbatim.
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkDeviceUpdates: primaryKey({
        name: 'device_updates_pkey',
        columns: [table.deviceId, table.pluginId, table.kind, table.name],
      }),
      idxDeviceUpdatesDevice: index('idx_device_updates_device').on(table.deviceId),
    };
  }
);

// One row per ACTIONABLE security finding as reported by a plugin's
// `securityChecks` metric (capability 'securityChecks'). Powers the cross-device
// Security page. Same upsert + delete-on-absent lifecycle as device_updates: a
// check that is no longer flagged (resolved, or renamed) must vanish on the next
// inventory poll. Rows with status='ok' are dropped at ingest time — only
// warning/critical findings persist, so a clean device has zero rows here.
export const deviceSecurityChecks = pgTable(
  'device_security_checks',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // auth-failures | file-integrity | rate-limiting | account | service-exposure | other.
    kind: text('kind').notNull().default('other'),
    // Stable identity within (device, plugin, kind): "auth-failures", "/etc/passwd", …
    name: text('name').notNull(),
    status: text('status').notNull().default('warning'),
    detail: text('detail'),
    count: integer('count'),
    // Plugin-specific details (JSON object) stored verbatim.
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkDeviceSecurityChecks: primaryKey({
        name: 'device_security_checks_pkey',
        columns: [table.deviceId, table.pluginId, table.kind, table.name],
      }),
      idxDeviceSecurityChecksDevice: index('idx_device_security_checks_device').on(table.deviceId),
    };
  }
);

// Generic per-plugin persistent state (see routes/internal.ts /plugin/state/*).
// Plugins that need to remember something ACROSS polls and container restarts —
// e.g. file-integrity baselines keyed by host+path, last-seen counters, TOFU
// fingerprints — store it here instead of owning a database connection or a local
// volume. The API owns the storage; plugins read/write through the internal
// `x-plugin-api-key` routes (SDK createPluginStateStore). The natural key is
// (pluginId, namespace, key): `namespace` groups a feature's state ("file-integrity"),
// and `key` is the plugin-chosen stable identity within it ("<host>|/etc/passwd").
// `value` is an opaque JSON blob owned entirely by the plugin — the API never
// interprets it. `deviceId` (optional) scopes rows to a device so DELETE /devices
// cascades them; state not tied to one device leaves it null.
export const pluginState = pgTable(
  'plugin_state',
  {
    pluginId: text('pluginId').notNull(),
    // Optional device scope — set when the state belongs to one device so a
    // device deletion cascades its rows; null for global/plugin-wide state.
    deviceId: text('deviceId'),
    namespace: text('namespace').notNull(),
    key: text('key').notNull(),
    value: text('value').notNull().default('{}'),
    updatedAt: text('updatedAt').notNull(),
  },
  (table) => {
    return {
      pkPluginState: primaryKey({
        name: 'plugin_state_pkey',
        columns: [table.pluginId, table.namespace, table.key],
      }),
      idxPluginStateDevice: index('idx_plugin_state_device').on(table.deviceId),
    };
  }
);

// Execution plans produced by a plugin's /plan endpoint (e.g. an OPNsense
// WireGuard tunnel spanning two firewalls). The API persists the plan and its
// steps, fulfils the plan's provisionRequests via the secrets provider at
// creation time, and executes the steps in dependency order through the
// plugin's /config endpoint (see workers/planExecutor.ts).
export const plans = pgTable(
  'plans',
  {
    id: text('id').primaryKey(),
    // The plugin whose action catalog produced this plan.
    pluginId: text('pluginId').notNull(),
    // Catalog entry the user started from (e.g. wireguard.tunnel.create).
    intentActionId: text('intentActionId').notNull(),
    // JSON object — the raw intent inputs as submitted by the creator. Kept on
    // the plan row so the payload of every execution is transparent, including
    // re-runs and retries (which duplicate the plan with the same inputs).
    intentInputs: text('intentInputs').notNull().default('{}'),
    // draft | ready | scheduled | executing | succeeded | failed | cancelled | skipped
    status: text('status').notNull().default('ready'),
    // JSON object mapping provisionRequest ref -> created secret id.
    provisionedSecrets: text('provisionedSecrets').notNull().default('{}'),
    error: text('error'),
    // JWT sub of the user who created the plan (also owns its secrets).
    createdBy: text('createdBy').notNull(),
    // JWT sub of the user who started the CURRENT execution (set on execute;
    // may differ from createdBy when someone else re-runs or retries it).
    executedBy: text('executedBy'),
    // Set when a cancel is requested; the executor checks it between steps.
    cancelledAt: text('cancelledAt'),
    createdAt: text('createdAt').notNull(),
    updatedAt: text('updatedAt').notNull(),
    // When the CURRENT execution actually started (set by the executor on its
    // first step; null until then). Distinct from finishedAt, which is cleared
    // when the plan is re-executed.
    startedAt: text('startedAt'),
    // Set on plans created via POST /plans/:id/retry — the id of the plan this
    // one duplicates (same payload + provisioned secrets). Null otherwise.
    retriedFrom: text('retriedFrom'),
    // Scheduling (see workers/planScheduler.ts): when set, the scheduler worker
    // flips this plan to 'executing' at or after this instant (ISO 8601 UTC).
    scheduledAt: text('scheduledAt'),
    // What to do when a due execution cannot reach its plugin (stack down /
    // plugin not responding): 'run-asap' keeps retrying with backoff until it
    // succeeds; 'skip' marks the plan skipped after one failed attempt.
    schedulePolicy: text('schedulePolicy'),
    // The status the plan had when it was scheduled — restored on unschedule,
    // so a succeeded plan can be re-scheduled and later returned to succeeded.
    preScheduleStatus: text('preScheduleStatus'),
    // How many times the scheduler has already attempted this schedule (drives
    // the run-asap backoff; reset on every fresh execution).
    scheduleAttempts: integer('scheduleAttempts').notNull().default(0),
    // JSON object — per-plan retry policy for FAILED steps, overriding the global
    // defaults (planStepRetryMaxAttempts / planStepRetryWaitMs):
    //   { maxAttempts?: number, waitMs?: number }  — partial override; missing keys inherit.
    //   null (column NULL) = use the global settings. A plugin may also set this on
    //   the plan it returns from /plan (e.g. to DISABLE retries for a critical intent).
    retryPolicy: text('retryPolicy'),
    finishedAt: text('finishedAt'),
    // Last time this plan reached a terminal status (succeeded/failed/cancelled).
    // Distinct from finishedAt, which is cleared when the plan is re-executed —
    // the top-bar plans icon uses it to show a brief "recently done" tick.
    recentlyFinishedAt: text('recentlyFinishedAt'),
  },
  (table) => {
    return {
      idxPlansPluginCreated: index('idx_plans_plugin_created').on(table.pluginId, table.createdAt),
      // The scheduler worker scans due plans on every tick.
      idxPlansScheduledAt: index('idx_plans_scheduled_at').on(table.scheduledAt),
    };
  }
);

// One executable step of a plan. `stepIndex` is the final ordering (the
// plugin's planner already accounts for auto-prepended snapshot steps) and
// doubles as the topological order; `dependsOn` holds stepIndex values that
// must succeed first, and `secretRefs` names provisioned secrets whose
// decrypted fields are merged into this step's credentials under the ref key.
export const planSteps = pgTable(
  'plan_steps',
  {
    id: text('id').primaryKey(),
    planId: text('planId').notNull(),
    stepIndex: integer('stepIndex').notNull(),
    deviceId: text('deviceId').notNull(),
    actionId: text('actionId').notNull(),
    // JSON object — the action's input (may contain ${steps[N].result...} tokens).
    input: text('input').notNull().default('{}'),
    // JSON array of stepIndex numbers.
    dependsOn: text('dependsOn').notNull().default('[]'),
    // JSON array of provisionRequest refs.
    secretRefs: text('secretRefs').notNull().default('[]'),
    bestEffort: boolean('bestEffort').notNull().default(false),
    // pending | running | succeeded | failed | skipped
    status: text('status').notNull().default('pending'),
    result: text('result'),
    startedAt: text('startedAt'),
    finishedAt: text('finishedAt'),
  },
  (table) => {
    return {
      idxPlanStepsPlanIndex: index('idx_plan_steps_plan_index').on(table.planId, table.stepIndex),
    };
  }
);

// Runtime-tunable system settings (Workers page → HA & workers panel).
// Key/value rows; a stored value overrides the env default for that knob
// (see src/systemSettings.ts). Survives restarts and is shared across replicas.
export const systemSettings = pgTable('system_settings', {
  key: text('key').primaryKey(),
  value: text('value').notNull(),
  updatedAt: text('updatedAt').notNull(),
});

// WebAuthn passkeys enrolled per user (multiple allowed — one row per device).
// `credentialId` is the base64url-encoded credential identifier from the
// authenticator; `publicKey` stores the COSE public key as a JSON string.
// Verification happens in the basic-auth plugin via @simplewebauthn/server,
// which fetches these rows through the internal /plugin/webauthn/* routes.
export const webauthnCredentials = pgTable(
  'webauthn_credentials',
  {
    id: text('id').primaryKey(),
    userId: text('userId').notNull(),
    credentialId: text('credentialId').notNull().unique(),
    // COSE public key, serialized as a JSON string.
    publicKey: text('publicKey').notNull(),
    // Signature counter (clamped to 64-bit by WebAuthn); replay protection.
    counter: bigint('counter', { mode: 'number' }).notNull().default(0),
    // User-assigned label, e.g. "Michael's MacBook" — display only.
    label: text('label'),
    // JSON string array of transports (e.g. ["platform","hybrid"]).
    transports: text('transports'),
    createdAt: text('createdAt').notNull(),
  },
  (table) => {
    return {
      idxWebauthnCredsUser: index('idx_webauthn_credentials_user').on(table.userId),
    };
  }
);

// Credential policies. One GLOBAL row (`userId IS NULL`) acts as the default
// for everyone; a per-user row (unique on userId) OVERRIDES individual fields —
// each field is resolved independently, so an override only needs to carry the
// fields it wants to change (the rest inherit from global).
//   requiredMethods: which enrolled 2nd factors satisfy login step 2,
//     JSON array of 'totp' | 'webauthn'. Empty = no 2FA required at all.
//     If none of the allowed methods is enrolled, login is blocked with a
//     distinct error so the UI can point to enrollment.
//   gateAmrs: which JWT `amr` values satisfy require2FA (privileged endpoints
//     like config-job submission). Evaluated LIVE per request against this
//     table — admin changes apply immediately to existing sessions.
//   minPasswordLength: minimum characters for any new/reset password.
//   passwordMaxAgeDays / inactiveDisableAfterDays: optional day-counts; NULL =
//     the rule is OFF (no forced rotation / no auto-disable).
//   sessionTimeoutSeconds: optional per-user cap on the global session timeout
//     — a user's sessions expire at min(global, this) so an admin can force a
//     shorter lifetime for one account. NULL = inherit the global setting.
//   allowSessionExtension: whether the user may extend their own session via a
//     2FA revalidation (the web UI "Extend" button). FALSE = hardening kill
//     switch — sessions can never be extended and end at their expiry.
export const credentialPolicies = pgTable('credential_policies', {
  id: text('id').primaryKey(),
  // NULL = the global default policy; otherwise the user id it applies to.
  userId: text('userId').unique(),
  requiredMethods: text('requiredMethods').notNull().default('["totp"]'),
  gateAmrs: text('gateAmrs').notNull().default('["totp"]'),
  minPasswordLength: integer('minPasswordLength'),
  passwordMaxAgeDays: integer('passwordMaxAgeDays'),
  inactiveDisableAfterDays: integer('inactiveDisableAfterDays'),
  sessionTimeoutSeconds: integer('sessionTimeoutSeconds'),
  allowSessionExtension: boolean('allowSessionExtension'),
  updatedAt: text('updatedAt').notNull(),
});

// Notification center (see workers/notifications.ts + routes/notifications.ts).
// One row per distinct event. `dedupeKey` is the stable identity of an ongoing
// condition (e.g. "device-status:<deviceId>:offline") — while the condition
// persists, re-emissions UPSERT the existing row (occurrences++, lastSeenAt)
// instead of creating new ones; when it clears, the worker auto-resolves the
// row. One-off events (plan failed, plugin push) use a unique key and stay
// until acknowledged/closed or swept by retention.
export const notifications = pgTable(
  'notifications',
  {
    id: text('id').primaryKey(),
    // Stable identity of the condition — see dedupeKey above. NULL for rows
    // that can never recur (one-shot events).
    dedupeKey: text('dedupeKey'),
    // info | warning | critical
    severity: text('severity').notNull().default('info'),
    // Source category: system (API itself) | device (mirrored from a device's
    // state/telemetry) | plugin (pushed by a plugin via POST /plugin/notifications).
    source: text('source').notNull().default('system'),
    // The plugin instance that produced the notification (null for system/device).
    pluginId: text('pluginId'),
    // Device the notification relates to, when known.
    deviceId: text('deviceId'),
    title: text('title').notNull(),
    message: text('message').notNull().default(''),
    // JSON object with structured details (e.g. {from:'online',to:'offline'}).
    context: text('context'),
    createdAt: text('createdAt').notNull(),
    lastSeenAt: text('lastSeenAt').notNull(),
    occurrences: integer('occurrences').notNull().default(1),
    // open | acknowledged | resolved | closed. Open = counts toward the badge;
    // acknowledged = user saw it (stays in the list, no badge); resolved = the
    // condition cleared on its own (worker) or was dismissed as fixed; closed =
    // manually removed from view.
    status: text('status').notNull().default('open'),
    acknowledgedBy: text('acknowledgedBy'),
    acknowledgedAt: text('acknowledgedAt'),
    resolvedAt: text('resolvedAt'),
  },
  (table) => {
    return {
      // One live row per dedupe key — the upsert target. UNIQUE + partial so
      // resolved/closed rows never block a new occurrence of the same condition,
      // and only unresolved rows participate in dedup (matches initDb DDL).
      idxNotificationsDedupeKey: uniqueIndex('idx_notifications_dedupe_key')
        .on(table.dedupeKey)
        .where(sql`"status" IN ('open', 'acknowledged') AND "dedupeKey" IS NOT NULL`),
      idxNotificationsStatusCreated: index('idx_notifications_status_created').on(
        table.status,
        table.createdAt
      ),
      idxNotificationsDeviceId: index('idx_notifications_device_id').on(table.deviceId),
    };
  }
);

// Per-user notification preferences (fine-grained filtering of what shows up
// in the bell + dropdown). One row per user; missing row = defaults.
export const notificationPrefs = pgTable(
  'notification_prefs',
  {
    userId: text('userId').primaryKey(),
    // JSON object mapping source category -> allowed severities, e.g.
    // {"system":["info","warning","critical"],"device":[...],"plugin":[...]}.
    // A severity absent from a source's list is hidden for that user.
    visibility: text('visibility').notNull().default('{}'),
    updatedAt: text('updatedAt').notNull(),
  }
);

// Per-user UI preferences (navigation order + hidden pages). One row per user;
// missing row = defaults. Values are ADDITIVE over the webapp's NAV_ITEMS —
// only paths that exist in the client are honored, so adding/removing a page
// later needs no migration here.
export const userPreferences = pgTable(
  'user_preferences',
  {
    userId: text('userId').primaryKey(),
    // JSON array of nav path strings (e.g. ["/devices","/networks"]) in the
    // user's chosen order. Paths absent from NAV_ITEMS are ignored on merge.
    navOrder: text('navOrder').notNull().default('[]'),
    // JSON array of nav path strings the user has hidden from the sidebar.
    hiddenPages: text('hiddenPages').notNull().default('[]'),
    // Timezone for date/time display. 'browser' (or NULL) = use the browser's
    // local timezone; otherwise an IANA identifier like "Europe/Berlin" or "UTC".
    timezone: text('timezone'),
    // Date/time format preset: 'locale' (default, locale-aware), 'iso', 'us', 'eu'.
    dateFormat: text('dateFormat').notNull().default('locale'),
    // When true, append a short timezone label in parentheses after each
    // rendered timestamp, e.g. "19.09.2026 20:55 (CEST)".
    showTzSuffix: boolean('showTzSuffix').notNull().default(false),
    updatedAt: text('updatedAt').notNull(),
  }
);

// ---------------------------------------------------------------------------
// Documented hosts — a USER-MAINTAINED inventory (the "Hosts documentation"
// page). Unlike the normalized `hosts` table (live ARP/NDP/DHCP observations,
// swept after 24h), these rows are permanent records: one or more DNS names,
// an optional friendly name + description, an optional site/layer placement,
// and one or more IP addresses each with an optional MAC and network label.
// The API cross-references the live `hosts` table at read time to mark a
// documented host as "discovered" (a matching MAC or IP was observed recently)
// — later used for change detection such as MAC changes on known hosts.
export const documentedHosts = pgTable(
  'documented_hosts',
  {
    id: text('id').primaryKey(),
    // JSON string array of DNS names / FQDNs (validated RFC1123, lowercase).
    // The FIRST entry is the primary name — display label + import match key.
    dnsNames: text('dnsNames').notNull().default('[]'),
    friendlyName: text('friendlyName'),
    description: text('description'),
    // Optional placement (NULL = unassigned) — same registries as devices.
    siteId: text('siteId'),
    layerId: text('layerId'),
    // User-assigned free-form tags (same data basis as devices.tags, e.g. "vm",
    // "lab") — JSON string array; also auto-applied from a matching device on
    // inventory import when the host has none yet.
    tags: text('tags').notNull().default('[]'),
    // Additional known MAC addresses of this host (JSON string array, colon form)
    // — e.g. rotated container MACs or randomized client MACs synced from the live
    // inventory by the import wizard (macSyncPolicy='add'). The PRIMARY/expected
    // MAC per address lives in documented_host_ips.mac; these are extra identities
    // used for discovery + import matching so a re-keyed host stays one row.
    macs: text('macs').notNull().default('[]'),
    // User-maintained lifecycle flag: true = the host is in active use, false =
    // stale/retired (the row stays documented but is visually dimmed). Default
    // TRUE — every new or imported host starts active.
    isActive: boolean('isActive').notNull().default(true),
    createdAt: text('createdAt').notNull(),
    updatedAt: text('updatedAt').notNull(),
  },
  (table) => {
    return {
      idxDocumentedHostsSite: index('idx_documented_hosts_site').on(table.siteId),
      idxDocumentedHostsLayer: index('idx_documented_hosts_layer').on(table.layerId),
    };
  }
);

// One documented IP address of a documented host. `mac` is the DOCUMENTED (expected)
// MAC — auto-filled from live observations in the webapp but user-overridable; it
// is what future change-detection compares against. `networkLabel` references a
// known network by its canonical identity (subnet CIDR / "VLAN <id>" / interface
// name, see mergeNetworkRows) or holds a free-form label for networks not yet in
// the inventory — resolved to display data at read time.
export const documentedHostIps = pgTable(
  'documented_host_ips',
  {
    id: text('id').primaryKey(),
    hostId: text('hostId').notNull(),
    // Bare IPv4/IPv6 literal (validated; DNS names live on the parent row).
    address: text('address').notNull(),
    // Documented MAC ("aa:bb:cc:dd:ee:ff", lowercase); NULL = unknown.
    mac: text('mac'),
    networkLabel: text('networkLabel'),
    // VLAN id the address lives in (auto-filled from the inventory when known).
    vlanId: integer('vlanId'),
    createdAt: text('createdAt').notNull(),
  },
  (table) => {
    return {
      uqDocumentedHostIps: uniqueIndex('uq_documented_host_ips').on(table.hostId, table.address),
      idxDocumentedHostIpsMac: index('idx_documented_host_ips_mac').on(table.mac),
      idxDocumentedHostIpsAddress: index('idx_documented_host_ips_address').on(table.address),
    };
  }
);

// ---------------------------------------------------------------------------
// Documented networks — a USER-MAINTAINED network inventory (the "Networks
// documentation" page). The documented-network counterpart of documented_hosts:
// permanent records of what SHOULD exist on the network, cross-referenced at
// read time against the live `networks` table (merged logical networks) to
// mark a documented network as "discovered". Unlike hosts there is NO child
// table — subnets/gateways/DNS servers are JSON arrays because no per-subnet
// attributes exist (hosts need one row per address for its MAC + VLAN).
export const documentedNetworks = pgTable(
  'documented_networks',
  {
    id: text('id').primaryKey(),
    // Primary label / identity of the network ("VLAN 30", "10.40.0.0/16",
    // "Mgmt LAN"). UNIQUE (case-insensitive uniqueness enforced at the API
    // layer) — makes import matching deterministic and prevents duplicate rows
    // (the merge endpoint still handles subnet-overlap duplicates that carry
    // different names).
    name: text('name').notNull(),
    // JSON string array of validated CIDR blocks ("10.40.0.0/16", "fd00::/64").
    // May be empty — a name-only row (e.g. "VLAN 30" before the subnet is
    // known) mirrors the live inventory's VLAN-only/SSID groups.
    subnets: text('subnets').notNull().default('[]'),
    // VLAN id when the network lives in one (null = unknown / not VLAN-based).
    vlanId: integer('vlanId'),
    // JSON string arrays of bare IP literals — dual-stack networks carry both
    // families. Purely user-maintained (not observable from live inventory).
    gateways: text('gateways').notNull().default('[]'),
    dnsServers: text('dnsServers').notNull().default('[]'),
    ntpServers: text('ntpServers').notNull().default('[]'),
    friendlyName: text('friendlyName'),
    description: text('description'),
    // Optional placement (NULL = unassigned) — same registries as devices.
    siteId: text('siteId'),
    layerId: text('layerId'),
    // User-assigned free-form tags (same data basis as devices.tags).
    tags: text('tags').notNull().default('[]'),
    // Lifecycle flag: true = in active use, false = stale/retired (dimmed).
    isActive: boolean('isActive').notNull().default(true),
    createdAt: text('createdAt').notNull(),
    updatedAt: text('updatedAt').notNull(),
  },
  (table) => {
    return {
      // Name uniqueness — the identity key of a documented network. Case-
      // INSENSITIVE uniqueness is enforced at the API layer (the router compares
      // with toLowerCase() and returns 409); every write goes through that check.
      uqDocumentedNetworksName: uniqueIndex('uq_documented_networks_name').on(table.name),
      idxDocumentedNetworksSite: index('idx_documented_networks_site').on(table.siteId),
      idxDocumentedNetworksLayer: index('idx_documented_networks_layer').on(table.layerId),
    };
  }
);

// Central file repository (see src/fileRepo.ts + src/fileRepoBroker.ts). The API
// owns ALL metadata here; the BYTES live either on the api-local volume (legacy,
// `providerId` null) or in a file-repo plugin (capability `fileRepo`) named by
// `providerId`. Content identity is sha256 — it doubles as the content-addressed
// key inside a provider. `storagePath` is RELATIVE to the repo root and
// human-readable (`<category>/<YYYY-MM-DD>/<name>`) for local-volume rows; for
// provider-backed rows it records where the bytes would have lived (informational).
export const repoFiles = pgTable(
  'repo_files',
  {
    id: text('id').primaryKey(),
    // Original file name as uploaded (e.g. "debian-12.8.0-amd64-netinst.iso").
    name: text('name').notNull(),
    // Open category set, e.g. 'iso' | 'firmware' | 'config-backup' | 'script' | 'other'.
    category: text('category').notNull().default('other'),
    sizeBytes: bigint('sizeBytes', { mode: 'number' }).notNull().default(0),
    // SHA-256 hex of the stored content (integrity + dedupe; provider blob key).
    sha256: text('sha256').notNull(),
    // Relative path under the repo root (category/date/name) — human-readable.
    storagePath: text('storagePath').notNull(),
    // Username that uploaded it (null for plugin uploads without a user context).
    uploadedBy: text('uploadedBy'),
    createdAt: text('createdAt').notNull(),
    // The file-repo PLUGIN id that stores this file's bytes (capability `fileRepo`).
    // NULL = legacy row on the api-local volume (FILE_REPO_PATH) — read path falls
    // back to local storage. Set for every new upload when a provider is online.
    providerId: text('providerId'),
  },
  (table) => {
    return {
      uqRepoFilesSha256: uniqueIndex('uq_repo_files_sha256').on(table.sha256),
      idxRepoFilesCategory: index('idx_repo_files_category').on(table.category),
      idxRepoFilesProvider: index('idx_repo_files_provider').on(table.providerId),
    };
  }
);

// Audit trail for repo file usage — "which file was used, for what device, when".
// Written by plugins (via the internal /plugin/files/:id/use route) and by the
// API on download. Kept after a file is deleted (references it by id).
export const repoFileUses = pgTable(
  'repo_file_uses',
  {
    id: text('id').primaryKey(),
    fileId: text('fileId').notNull(),
    // The device the file was used on, when known (null for plain downloads).
    deviceId: text('deviceId'),
    // Free-form context (e.g. "installed as VM disk", "firmware update").
    note: text('note'),
    // Username or plugin id that triggered the use (null = unknown).
    usedBy: text('usedBy'),
    createdAt: text('createdAt').notNull(),
  },
  (table) => {
    return {
      idxRepoFileUsesFile: index('idx_repo_file_uses_file').on(table.fileId),
      idxRepoFileUsesDevice: index('idx_repo_file_uses_device').on(table.deviceId),
    };
  }
);

// Stored UNM backups (see src/backup.ts + routes/backups.ts). A backup is a
// section-based JSON archive (gzipped, `.unmbak.gz`) of this instance's own
// database — NOT device config files. The BYTES live either on the api-local
// volume (`source='local'`, `providerId` NULL → `${BACKUP_PATH}/<id>.unmbak.gz`)
// or in a file-repo plugin (`source='repo'`, content-addressed by sha256).
// Multi-instance note: several file-repo INSTANCES can be registered at once
// (plugin id `<base-uuid>:<instanceId>`); `providerId` binds the backup to
// EXACTLY ONE of them and is resolved strictly — never with fallback to a
// sibling instance.
export const backups = pgTable(
  'backups',
  {
    id: text('id').primaryKey(),
    // Human label (e.g. "prod before cutover"). Defaults to the scope + date.
    name: text('name').notNull(),
    // Preset that produced this backup ('config' | 'planned' | 'all') — display
    // only; `sections` is authoritative for what the archive actually holds.
    scope: text('scope').notNull().default('all'),
    // JSON string array of section keys present in the archive (see backup.ts
    // BACKUP_SECTIONS). Drives restore preview + per-section apply selection.
    sections: text('sections').notNull().default('[]'),
    sizeBytes: bigint('sizeBytes', { mode: 'number' }).notNull().default(0),
    // SHA-256 hex of the archive bytes — integrity check on download AND the
    // content-addressed blob key inside a file-repo provider.
    sha256: text('sha256').notNull(),
    // Where the bytes live: 'local' = api volume (BACKUP_PATH), 'repo' = plugin.
    source: text('source').notNull().default('local'),
    // File-repo PLUGIN id holding the bytes (capability `fileRepo`). NULL for
    // local-volume backups. Full instance id when multiple instances exist.
    providerId: text('providerId'),
    createdAt: text('createdAt').notNull(),
  },
  (table) => {
    return {
      idxBackupsSource: index('idx_backups_source').on(table.source, table.providerId),
    };
  }
);

// Replication targets — one-way sync peers of this UNM instance (see
// routes/backups.ts /replication/* + workers/replication.ts). A target is
// another UNM API reachable over HTTP; the peer authenticates with a long-lived
// bearer token that carries `instance:backup`. Direction 'push' = THIS instance
// exports and sends to the peer's POST /replication/inbound; 'pull' = this
// instance fetches the peer's GET /replication/export and applies it locally.
export const replicationTargets = pgTable(
  'replication_targets',
  {
    id: text('id').primaryKey(),
    // Human label (e.g. "prod").
    name: text('name').notNull(),
    // Peer API base URL, e.g. https://unm.example.com/v1 — must already include
    // the /v1 prefix; the sync job appends /replication/inbound or
    // /replication/export to it.
    baseUrl: text('baseUrl').notNull(),
    // Bearer token presented to the peer (plaintext — DB access already implies
    // admin trust; revisit with envelope encryption later).
    token: text('token').notNull(),
    direction: text('direction').notNull().default('push'),
    enabled: boolean('enabled').notNull().default(true),
    // Scheduled sync cadence in minutes. NULL = manual-only (Sync now button).
    intervalMinutes: integer('intervalMinutes'),
    // JSON string array of system_settings keys to EXCLUDE from the settings
    // section during sync — stack-dependent values that must stay per-instance
    // (instanceName, updateFeedUrl, …). Defaults are applied at creation time.
    excludeKeys: text('excludeKeys').notNull().default('[]'),
    lastSyncAt: text('lastSyncAt'),
    // 'ok' | 'error' — plus the human-readable failure in `lastError`.
    lastSyncStatus: text('lastSyncStatus'),
    lastError: text('lastError'),
    // JSON report of the last sync (per-section created/updated counts, or the
    // peer's error envelope) — rendered on the Backups page.
    lastReport: text('lastReport').notNull().default('{}'),
    createdAt: text('createdAt').notNull(),
  },
  (table) => {
    return {
      idxReplicationTargetsEnabled: index('idx_replication_targets_enabled').on(table.enabled),
    };
  }
);

// Add index for config_jobs
// Note: Drizzle's index definition inside the table definition is 
// usually the best way to handle this. I'll add it to configJobs.

// ── CVE vulnerability tracking (Security page) ───────────────────────────────
// One row per installed package as reported by a plugin's `installedPackages`
// metric — the fleet-wide inventory the CVE worker matches advisories against.
// Same upsert-per-poll + delete-on-absent lifecycle as containers: an uninstalled
// package must vanish on the next poll, not linger until the 24h sweep. PK is
// (device, plugin, name) so two plugins watching one device keep separate rows;
// a device without package data contributes no rows. Swept like other inventory.
export const devicePackages = pgTable(
  'device_packages',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    // Package name as reported (e.g. "openssl", "nginx", "node").
    name: text('name').notNull(),
    // Installed version string, verbatim ("1.1.1n-0ubuntu3.9", "2.4.5-r0", …).
    // NULL = unversioned (e.g. a binary with no readable version) — the CVE
    // worker treats it as "any version" for matching purposes.
    version: text('version'),
    // Ecosystem tag used to pick the advisory source + version comparator:
    // 'debian' | 'alpine' | 'npm' | … (plugins emit what their OS/package
    // manager is; the worker maps it onto provider ecosystems).
    ecosystem: text('ecosystem').notNull().default('unknown'),
    // Plugin-specific details (JSON object) stored verbatim.
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkDevicePackages: primaryKey({
        name: 'device_packages_pkey',
        columns: [table.deviceId, table.pluginId, table.name],
      }),
      idxDevicePackagesDevice: index('idx_device_packages_device').on(table.deviceId),
    };
  }
);

// One row per known advisory for a (ecosystem, package) pair — the fleet-wide
// vulnerability knowledge base. Worker-managed ONLY (never written by plugins):
// fetched from an OSINT provider (OSV.dev today; commercial providers later via
// the CveProvider interface), upserted on every fetch cycle and pruned for
// packages no longer installed anywhere in the fleet. NOT swept — advisories
// are global knowledge, not per-device inventory. `affectedRanges` is a JSONB
// array of { type: 'lt'|'gt', version } bounds (OSV "events" normalized): a
// package version matches when it falls inside any [introduced, fixed) range.
export const cveAdvisories = pgTable(
  'cve_advisories',
  {
    // Provider ecosystem tag ('DEBIAN', 'ALPINE_LINUX', 'npm', …). Part of the
    // PK — the same package name can carry different advisories per ecosystem.
    ecosystem: text('ecosystem').notNull(),
    packageName: text('packageName').notNull(),
    // Advisory id (e.g. "CVE-2024-1234", "GHSA-xxxx"). One row per advisory —
    // a package with several CVEs gets one row each, all sharing the ranges.
    id: text('id').notNull(),
    // CVSS base score 0–10 (null = unscored / provider gave none).
    severityScore: doublePrecision('severityScore'),
    // Derived bucket for cheap filtering/sorting: 'critical' | 'high' |
    // 'medium' | 'low' | 'unknown' — computed from the score at ingest.
    severityRank: text('severityRank').notNull().default('unknown'),
    // Affected version ranges (JSONB): [{ type: 'lt'|'gt', version }] — OSV
    // "events" normalized to bounds. Matching is done in TS (cve/match.ts),
    // not SQL, so the shape stays provider-flexible.
    affectedRanges: jsonb('affectedRanges').notNull().default([] as unknown[]),
    // Human summary of the vulnerability (first paragraph / description).
    summary: text('summary'),
    // Canonical advisory URL (NVD/GHSA/OSV page) for the UI's "details" link.
    url: text('url'),
    publishedAt: text('publishedAt'),
    // Provider id that last wrote this row ('osv' today).
    provider: text('provider').notNull().default('osv'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkCveAdvisories: primaryKey({
        name: 'cve_advisories_pkey',
        columns: [table.ecosystem, table.packageName, table.id],
      }),
      idxCveAdvisoriesPkg: index('idx_cve_advisories_pkg').on(table.ecosystem, table.packageName),
    };
  }
);

// One row per (device × vulnerable package) match — the join of device_packages
// with cve_advisories computed by the CVE worker on every fetch cycle. This is
// what the Security page renders: which devices are exposed to which CVEs, at
// what severity. Recomputed WHOLESALE each beat (delete-all + re-insert per
// device set) — the table is a pure derived view and must never drift from its
// inputs. Swept like other inventory so offline devices drop out of the views.
export const deviceCves = pgTable(
  'device_cves',
  {
    deviceId: text('deviceId').notNull(),
    pluginId: text('pluginId').notNull(),
    ecosystem: text('ecosystem').notNull(),
    packageName: text('packageName').notNull(),
    cveId: text('cveId').notNull(),
    // The installed version that matched (denormalized for display).
    installedVersion: text('installedVersion'),
    severityScore: doublePrecision('severityScore'),
    severityRank: text('severityRank').notNull().default('unknown'),
    summary: text('summary'),
    url: text('url'),
    // Provider-specific details (JSON object) stored verbatim.
    extra: text('extra').notNull().default('{}'),
    collectedAt: text('collectedAt').notNull(),
  },
  (table) => {
    return {
      pkDeviceCves: primaryKey({
        name: 'device_cves_pkey',
        columns: [table.deviceId, table.pluginId, table.ecosystem, table.packageName, table.cveId],
      }),
      idxDeviceCvesDevice: index('idx_device_cves_device').on(table.deviceId),
    };
  }
);

// ── Actions & Schedules (automation engine) ──────────────────────────────────
// ITTT-style rules: "IF <trigger> THEN <action…>". A rule is a list of trigger
// blocks AND a list of action blocks; the leader-gated automation worker
// (workers/automations.ts) evaluates triggers on every tick and runs the
// actions sequentially when one fires. Trigger/action shapes are validated in
// automations/types.ts — the DB stores them as opaque JSON TEXT so new block
// types can be added without a migration. See routes/automations.ts for the API.

export const automations = pgTable(
  'automations',
  {
    id: text('id').primaryKey(),
    name: text('name').notNull(),
    description: text('description'),
    enabled: boolean('enabled').notNull().default(true),
    // JSON array of trigger blocks (≥1): schedule | metric | log | deviceStatus | flow | containerLog.
    triggers: text('triggers').notNull().default('[]'),
    // JSON array of action blocks (≥1): intent | webhook | notification | internal.
    actions: text('actions').notNull().default('[]'),
    // Minimum seconds between two firings of this rule (event-trigger throttle).
    cooldownSec: integer('cooldownSec').notNull().default(0),
    // ISO timestamp of the most recent firing (any trigger) — drives cooldown.
    lastFiredAt: text('lastFiredAt'),
    createdBy: text('createdBy'),
    createdAt: text('createdAt').notNull(),
    updatedAt: text('updatedAt').notNull(),
  },
  (table) => {
    return {
      idxAutomationsEnabled: index('idx_automations_enabled').on(table.enabled),
    };
  }
);

// One row per rule firing — the audit trail behind the "Runs" view. `status`
// is 'succeeded' when every action succeeded, 'failed' when none did and
// 'partial' for mixed outcomes; `planIds` links intent actions to their plans.
export const automationRuns = pgTable(
  'automation_runs',
  {
    id: text('id').primaryKey(),
    automationId: text('automationId').notNull(),
    // ISO timestamp of the firing instant (denormalized for cheap retention sweeps).
    firedAt: text('firedAt').notNull(),
    // Which trigger block fired (free TEXT — any TriggerBlock type).
    triggerType: text('triggerType').notNull(),
    // Trigger context at firing time (JSON): device/metric/log details for display.
    context: text('context').notNull().default('{}'),
    status: text('status').notNull().default('succeeded'),
    error: text('error'),
    // JSON array of plan ids created by intent actions ([] when none).
    planIds: text('planIds').notNull().default('[]'),
  },
  (table) => {
    return {
      idxAutomationRunsAutomationId: index('idx_automation_runs_automation_id').on(table.automationId),
      idxAutomationRunsFiredAt: index('idx_automation_runs_fired_at').on(table.firedAt),
    };
  }
);

// Per-trigger evaluation state (JSON) — e.g. log-trigger watermarks and the
// sustained-condition window of metric triggers. Keyed by (rule, trigger block,
// state key) so each trigger keeps its own bookkeeping independently.
export const automationState = pgTable(
  'automation_state',
  {
    automationId: text('automationId').notNull(),
    triggerId: text('triggerId').notNull(),
    stateKey: text('stateKey').notNull(),
    value: text('value').notNull().default('{}'),
    updatedAt: text('updatedAt').notNull(),
  },
  (table) => {
    return {
      pkAutomationState: primaryKey({
        name: 'automation_state_pkey',
        columns: [table.automationId, table.triggerId, table.stateKey],
      }),
    };
  }
);