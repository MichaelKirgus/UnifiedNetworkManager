import { pgTable, text, index } from 'drizzle-orm/pg-core';

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
  pluginId: text('pluginId').notNull(),
  managementAddress: text('managementAddress').notNull(),
  site: text('site'),
  status: text('status').notNull().default('unknown'),
  secretId: text('secretId').notNull(),
  createdAt: text('createdAt').notNull(),
});

export const secrets = pgTable('secrets', {
  id: text('id').primaryKey(),
  encryptedValue: text('encryptedValue').notNull(),
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
  createdAt: text('createdAt').notNull(),
});

export const configJobs = pgTable('config_jobs', {
  id: text('id').primaryKey(),
  deviceId: text('deviceId').notNull(),
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
  collectedAt: text('collectedAt').notNull(),
  health: text('health').notNull().default('unknown'),
  metrics: text('metrics').notNull().default('{}'),
}, (table) => {
  return {
    idxTelemetryDeviceCollected: index('idx_telemetry_device_collected').on(table.deviceId, table.collectedAt),
  };
});

// Add index for config_jobs
// Note: Drizzle's index definition inside the table definition is 
// usually the best way to handle this. I'll add it to configJobs.