import { pgTable, text, boolean, index, uniqueIndex } from 'drizzle-orm/pg-core';
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

export const devices = pgTable('devices', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  vendor: text('vendor').notNull(),
  deviceType: text('deviceType').notNull(),
  managementAddress: text('managementAddress').notNull(),
  site: text('site'),
  status: text('status').notNull().default('unknown'),
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

// Add index for config_jobs
// Note: Drizzle's index definition inside the table definition is 
// usually the best way to handle this. I'll add it to configJobs.