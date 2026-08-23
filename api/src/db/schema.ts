import { pgTable, text, boolean, integer, doublePrecision, index, uniqueIndex } from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

export const users = pgTable('users', {
  id: text('id').primaryKey(),
  username: text('username').notNull().unique(),
  passwordHash: text('passwordHash').notNull(),
  totpSecret: text('totpSecret'),
  roles: text('roles').notNull().default('[]'),
  permissions: text('permissions').notNull().default('[]'),
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
  deviceType: text('deviceType').notNull(),
  managementAddress: text('managementAddress').notNull(),
  // Reference to the site this device lives at (NULL = unassigned).
  siteId: text('siteId'),
  status: text('status').notNull().default('unknown'),
  // User-selected hardware model, chosen from a plugin's advertised catalog
  // (/discover `deviceModels`). NULL when no catalog applies or the user skipped it.
  // Forwarded to every /monitoring call so vendor plugins can adapt their data gathering.
  model: text('model'),
  // Firmware version for this device (from the selected model's firmwareVersions list).
  firmwareVersion: text('firmwareVersion'),
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
    isPrimary: boolean('isPrimary').notNull().default(false),
    createdAt: text('createdAt').notNull(),
  },
  (table) => {
    return {
      uqDevicePlugins: uniqueIndex('uq_device_plugins').on(table.deviceId, table.pluginId),
    };
  }
);

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
  createdAt: text('createdAt').notNull(),
});

export const plugins = pgTable('plugins', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  version: text('version').notNull(),
  vendors: text('vendors').notNull().default('[]'),
  capabilities: text('capabilities').notNull().default('[]'),
  endpoint: text('endpoint').notNull(),
  authType: text('authType').notNull().default('none'),
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
  createdAt: text('createdAt').notNull(),
  lastSeenAt: text('lastSeenAt'),
});

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
  metrics: text('metrics').notNull().default('{}'),
  metricDescriptors: text('metricDescriptors'),
}, (table) => {
  return {
    idxTelemetryDevicePluginCollected: index('idx_telemetry_device_plugin_collected')
      .on(table.deviceId, table.pluginId, table.collectedAt),
  };
});

// Normalized inventory tables — populated by the telemetry worker from the
// plugin's /monitoring metrics (see workers/telemetry.ts ingestInventory).
// They power the cross-device Networks and Hosts pages in the webapp. Rows are
// upserted per poll; a periodic sweep drops rows not refreshed within 24h so
// offline devices don't accumulate stale data.

// One row per configured network (interface IP address) as reported by a
// plugin's `networks` metric: { name, ip, prefix, version ('v4'|'v6'), vlanId?,
// mac?, status? }. Interfaces without an IP are stored with ip = '' so their
// MAC/name stay available for topology detection.
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
      pkNetworks: uniqueIndex('uq_networks')
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
    // arp | ndp | dhcp — which table/lease source reported this host.
    source: text('source').notNull(),
    hostname: text('hostname'),
    manufacturer: text('manufacturer'),
    intf: text('intf'),
    expiry: text('expiry'),
    lastSeenAt: text('lastSeenAt').notNull(),
  },
  (table) => {
    return {
      pkHosts: uniqueIndex('uq_hosts')
        .on(table.deviceId, table.pluginId, table.mac, table.ip, table.source),
      idxHostsDevice: index('idx_hosts_device').on(table.deviceId),
      // For the future topology view: "which devices see this MAC / IP".
      idxHostsMac: index('idx_hosts_mac').on(table.mac),
      idxHostsIp: index('idx_hosts_ip').on(table.ip),
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
    // draft | ready | executing | succeeded | failed | cancelled
    status: text('status').notNull().default('ready'),
    // JSON object mapping provisionRequest ref -> created secret id.
    provisionedSecrets: text('provisionedSecrets').notNull().default('{}'),
    error: text('error'),
    // JWT sub of the user who created the plan (also owns its secrets).
    createdBy: text('createdBy').notNull(),
    // Set when a cancel is requested; the executor checks it between steps.
    cancelledAt: text('cancelledAt'),
    createdAt: text('createdAt').notNull(),
    updatedAt: text('updatedAt').notNull(),
    finishedAt: text('finishedAt'),
  },
  (table) => {
    return {
      idxPlansPluginCreated: index('idx_plans_plugin_created').on(table.pluginId, table.createdAt),
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

// Add index for config_jobs
// Note: Drizzle's index definition inside the table definition is 
// usually the best way to handle this. I'll add it to configJobs.