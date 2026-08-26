import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { eq, isNull } from 'drizzle-orm';
import { generateSecret, buildOtpAuthUri } from './auth/totp';
import { ADMIN_PERMISSIONS } from './auth/permissions';
import * as schema from './db/schema';

const DEFAULT_DATABASE_URL = 'postgresql://' + 'unm' + ':' + 'unm' + '@localhost:5432/unm';
const DATABASE_URL = process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL;

export const pool = new Pool({ connectionString: DATABASE_URL });
export const db = drizzle(pool, { schema });

export type User = typeof schema.users.$inferSelect;
export type Device = typeof schema.devices.$inferSelect;
export type Plugin = typeof schema.plugins.$inferSelect;
export type ConfigJob = typeof schema.configJobs.$inferSelect;
export type Telemetry = typeof schema.telemetry.$inferSelect;
export type Secret = typeof schema.secrets.$inferSelect;

/**
 * Database bootstrap hook.
 *
 * The API owns the `users` table (the single source of truth for local
 * identities). Identity *verification* is delegated to the active identity
 * provider plugin, but user *provisioning* (seeding the default admin) stays
 * here so the API is always able to resolve usernames (e.g. for secrets).
 */
export async function initDb(): Promise<void> {
  // Defensive migration: ensure the telemetry.metricDescriptors column exists.
  // (drizzle-kit push handles this on setup, but this covers hot-reload / dev.)
  await pool.query(
    `ALTER TABLE telemetry ADD COLUMN IF NOT EXISTS "metricDescriptors" TEXT`
  );

  // Defensive migrations for plugin options: descriptor cache column + the
  // settings table. Same rationale as above — host-dev hot reload may run
  // before drizzle-kit push has created them.
  await pool.query(
    `ALTER TABLE plugins ADD COLUMN IF NOT EXISTS "optionDescriptors" TEXT`
  );
  await pool.query(`
    CREATE TABLE IF NOT EXISTS plugin_settings (
      id TEXT PRIMARY KEY,
      "pluginId" TEXT NOT NULL,
      "deviceId" TEXT,
      "optionKey" TEXT NOT NULL,
      value TEXT NOT NULL,
      "updatedAt" TEXT NOT NULL
    )`);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_plugin_settings_global
      ON plugin_settings ("pluginId", "optionKey") WHERE "deviceId" IS NULL`);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_plugin_settings_device
      ON plugin_settings ("pluginId", "deviceId", "optionKey") WHERE "deviceId" IS NOT NULL`);

  // Multi-plugin-per-device model: the device_plugins join table is the single
  // source of truth for which plugins serve a device (each with its own secret).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_plugins (
      id TEXT PRIMARY KEY,
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      "secretId" TEXT,
      "isPrimary" BOOLEAN NOT NULL DEFAULT FALSE,
      "createdAt" TEXT NOT NULL
    )`);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_device_plugins
      ON device_plugins ("deviceId", "pluginId")`);

  // Multi-IP-per-device model: secondary addresses live in device_ips; the
  // primary is always devices.managementAddress (validated to IPv4/IPv6/DNS).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_ips (
      id TEXT PRIMARY KEY,
      "deviceId" TEXT NOT NULL,
      address TEXT NOT NULL,
      "createdAt" TEXT NOT NULL
    )`);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_device_ips
      ON device_ips ("deviceId", address)`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_device_ips_device
      ON device_ips ("deviceId")`);

  // Sites: first-class site objects; devices reference one via siteId.
  // Replaces the legacy free-text `devices.site` column (see backfillDeviceSites).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sites (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      address TEXT,
      country TEXT,
      timezone TEXT,
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      "createdAt" TEXT NOT NULL
    )`);
  // GPS columns for sites created before they existed (dev DBs).
  await pool.query(`ALTER TABLE sites ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE sites ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION`);
  await pool.query(
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS "siteId" TEXT`
  );

  // Roles: named bundles of permissions (see backfillAdminRole for the seed).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS roles (
      name TEXT PRIMARY KEY,
      description TEXT,
      permissions TEXT NOT NULL DEFAULT '[]',
      "createdAt" TEXT NOT NULL
    )`);

  // Attribute telemetry + config jobs to the plugin that produced/executed them.
  await pool.query(
    `ALTER TABLE telemetry ADD COLUMN IF NOT EXISTS "pluginId" TEXT`
  );
  await pool.query(
    `ALTER TABLE config_jobs ADD COLUMN IF NOT EXISTS "pluginId" TEXT`
  );

  // Action catalog cache: plugins advertise their executable actions in
  // /discover; the API persists them so plan creation is data-driven.
  await pool.query(
    `ALTER TABLE plugins ADD COLUMN IF NOT EXISTS "actionDescriptors" TEXT`
  );

  // Plugin icon + device model catalog (see schema.plugins.iconUrl/deviceModels).
  await pool.query(`ALTER TABLE plugins ADD COLUMN IF NOT EXISTS "iconUrl" TEXT`);
  await pool.query(`ALTER TABLE plugins ADD COLUMN IF NOT EXISTS "deviceModels" TEXT`);

  // Generic credential slots: plugins may declare additional named credential
  // slots in /discover (e.g. a web-UI user/password distinct from SNMP). The
  // slot descriptors are cached on the plugin row; bound secrets live per
  // assignment as JSON { slotName: secretId } on device_plugins.extraCredentials.
  await pool.query(`ALTER TABLE plugins ADD COLUMN IF NOT EXISTS "credentialSlots" TEXT`);
  await pool.query(
    `ALTER TABLE device_plugins ADD COLUMN IF NOT EXISTS "extraCredentials" TEXT`
  );

  // Long-lived API tokens for agents/scripts (MCP server, CI). Only the
  // SHA-256 hash of the token is stored; the raw value is shown once at creation.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS api_tokens (
      id TEXT PRIMARY KEY,
      "userId" TEXT NOT NULL,
      label TEXT,
      "tokenHash" TEXT NOT NULL UNIQUE,
      "tokenPrefix" TEXT,
      permissions TEXT NOT NULL DEFAULT '[]',
      "expiresAt" TEXT,
      "lastUsedAt" TEXT,
      "createdAt" TEXT NOT NULL
    )`);

  // User-selected hardware model / firmware version on devices — chosen from a
  // plugin's advertised catalog, forwarded to every /monitoring call.
  await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS "model" TEXT`);
  await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS "firmwareVersion" TEXT`);

  // Execution plans (see workers/planExecutor.ts). Plans persist a plugin's
  // /plan output + its provisioned secrets; steps run in dependency order.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS plans (
      id TEXT PRIMARY KEY,
      "pluginId" TEXT NOT NULL,
      "intentActionId" TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'ready',
      "provisionedSecrets" TEXT NOT NULL DEFAULT '{}',
      error TEXT,
      "createdBy" TEXT NOT NULL,
      "cancelledAt" TEXT,
      "createdAt" TEXT NOT NULL,
      "updatedAt" TEXT NOT NULL,
      "finishedAt" TEXT
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_plans_plugin_created
      ON plans ("pluginId", "createdAt")`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS plan_steps (
      id TEXT PRIMARY KEY,
      "planId" TEXT NOT NULL,
      "stepIndex" INTEGER NOT NULL,
      "deviceId" TEXT NOT NULL,
      "actionId" TEXT NOT NULL,
      input TEXT NOT NULL DEFAULT '{}',
      "dependsOn" TEXT NOT NULL DEFAULT '[]',
      "secretRefs" TEXT NOT NULL DEFAULT '[]',
      "bestEffort" BOOLEAN NOT NULL DEFAULT FALSE,
      status TEXT NOT NULL DEFAULT 'pending',
      result TEXT,
      "startedAt" TEXT,
      "finishedAt" TEXT
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_plan_steps_plan_index
      ON plan_steps ("planId", "stepIndex")`);

  // Traceability: config jobs dispatched as part of a plan step.
  await pool.query(
    `ALTER TABLE config_jobs ADD COLUMN IF NOT EXISTS "planId" TEXT`
  );

  // Normalized inventory tables (Networks + Hosts pages). Populated by the
  // telemetry worker from plugin /monitoring metrics — see workers/telemetry.ts.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS networks (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      name TEXT NOT NULL,
      ip TEXT NOT NULL DEFAULT '',
      prefix INTEGER,
      version TEXT,
      "vlanId" INTEGER,
      mac TEXT,
      status TEXT,
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", name, ip)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_networks_device ON networks ("deviceId")`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS hosts (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      mac TEXT NOT NULL,
      ip TEXT NOT NULL,
      source TEXT NOT NULL,
      hostname TEXT,
      manufacturer TEXT,
      intf TEXT,
      expiry TEXT,
      "lastSeenAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", mac, ip, source)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_hosts_device ON hosts ("deviceId")`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts (mac)`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts (ip)`);

  // Tunnels inventory table (Tunnels page) — same lifecycle as networks/hosts.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tunnels (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      "peerAddress" TEXT NOT NULL DEFAULT '',
      "localAddress" TEXT NOT NULL DEFAULT '',
      subnet TEXT,
      status TEXT NOT NULL DEFAULT 'unknown',
      "uptimeSeconds" DOUBLE PRECISION,
      "lastHandshakeSeconds" DOUBLE PRECISION,
      "interfaceName" TEXT,
      "rxRate" DOUBLE PRECISION,
      "txRate" DOUBLE PRECISION,
      extra TEXT NOT NULL DEFAULT '{}',
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", name, type)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_tunnels_device ON tunnels ("deviceId")`);
  // Added after the initial release — existing deployments need the column.
  await pool.query(`ALTER TABLE tunnels ADD COLUMN IF NOT EXISTS "lastHandshakeSeconds" DOUBLE PRECISION`);

  // Routes inventory table (Routes page) — same lifecycle as networks/hosts/tunnels.
  // One row per route entry on one device, protocol-labeled. `protocol` is part of the
  // PK so static and dynamically-learned routes to the SAME destination coexist
  // (e.g. a static default + an OSPF-learned prefix), and delete-on-absent at ingest
  // keys on destination|protocol so one plugin's snapshot never wipes another protocol.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS routes (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      destination TEXT NOT NULL,
      gateway TEXT NOT NULL DEFAULT '',
      protocol TEXT NOT NULL DEFAULT 'static',
      distance DOUBLE PRECISION,
      metric DOUBLE PRECISION,
      mtu INTEGER,
      status TEXT NOT NULL DEFAULT 'unknown',
      extra TEXT NOT NULL DEFAULT '{}',
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", destination, protocol)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_routes_device ON routes ("deviceId")`);

  // WiFi inventory tables (WiFi page) — same lifecycle as networks/hosts/tunnels.
  // One row per SSID×band as reported by a plugin's `wifiNetworks` metric.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wifi_ssids (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      name TEXT NOT NULL,
      band TEXT NOT NULL DEFAULT '',
      channel INTEGER,
      bssid TEXT,
      encryption TEXT,
      "vlanId" INTEGER,
      ifc TEXT,
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", name, band)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wifi_ssids_device ON wifi_ssids ("deviceId")`);

  // One row per channel with an airtime-utilization sample (`wifiAirtime`).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wifi_channels (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      channel INTEGER NOT NULL,
      "utilizationPct" DOUBLE PRECISION,
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", channel)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wifi_channels_device ON wifi_channels ("deviceId")`);

  // One row per radio (`wifiRadios`) — noise floor + bandwidth for the
  // spectrum view.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wifi_radios (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      ifc TEXT NOT NULL DEFAULT '',
      band TEXT NOT NULL DEFAULT '',
      channel INTEGER,
      "bandwidthMhz" INTEGER,
      "noiseFloorDbm" DOUBLE PRECISION,
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", ifc)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wifi_radios_device ON wifi_radios ("deviceId")`);

  // One row per neighbor network (`wifiNeighbors`) — scanner-style list.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wifi_neighbors (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      bssid TEXT NOT NULL,
      ssid TEXT,
      band TEXT NOT NULL DEFAULT '',
      channel INTEGER,
      "signalDbm" DOUBLE PRECISION,
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", bssid)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wifi_neighbors_device ON wifi_neighbors ("deviceId")`);

  // One row per associated WLAN client (`wlanClients`) — powers the per-SSID
  // connected-client counts on the WiFi page.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wifi_clients (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      mac TEXT NOT NULL,
      ssid TEXT,
      ip TEXT,
      hostname TEXT,
      intf TEXT,
      "signalDbm" DOUBLE PRECISION,
      "txRateMbps" DOUBLE PRECISION,
      "rxRateMbps" DOUBLE PRECISION,
      "vlanId" INTEGER,
      "lastSeenAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", mac)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wifi_clients_device ON wifi_clients ("deviceId")`);

  // The legacy singular columns are superseded by device_plugins. There is no
  // production data to migrate (confirmed), so drop them outright — any dev
  // devices must be recreated via the new multi-plugin create flow.
  await pool.query(`ALTER TABLE devices DROP COLUMN IF EXISTS "pluginId"`);
  await pool.query(`ALTER TABLE devices DROP COLUMN IF EXISTS "secretId"`);

  const existingAdmin = await db.query.users.findFirst({
    where: (users, { eq }) => eq(users.username, 'admin'),
  });

  if (existingAdmin) {
    return;
  }

  const passwordHash = bcrypt.hashSync('admin', 10);
  const totpSecret = generateSecret();

  await db.insert(schema.users).values({
    id: uuidv4(),
    username: 'admin',
    passwordHash,
    totpSecret,
    roles: JSON.stringify(['admin']),
    permissions: JSON.stringify(ADMIN_PERMISSIONS),
    createdAt: new Date().toISOString(),
  });

  // eslint-disable-next-line no-console
  console.log('[db] seeded default admin user (username: admin, password: admin)');
  // eslint-disable-next-line no-console
  console.log(`[db] admin TOTP secret (dev only): ${totpSecret}`);
  // eslint-disable-next-line no-console
  console.log(`[db] admin otpauth URI (scan with an authenticator app): ${buildOtpAuthUri('admin', totpSecret)}`);
}

/**
 * Idempotent backfill: users whose roles include `admin` get every permission
 * from the canonical catalog. Needed because the admin seed only runs when no
 * admin exists — dev databases created before new permissions were added would
 * otherwise lack them (e.g. sites:write, users:read/write).
 */
export async function backfillAdminPermissions(): Promise<void> {
  const users = await db.query.users.findMany();
  for (const user of users) {
    let roles: string[] = [];
    try {
      roles = JSON.parse(user.roles);
    } catch {
      continue;
    }
    if (!Array.isArray(roles) || !roles.includes('admin')) continue;

    let perms: string[] = [];
    try {
      perms = JSON.parse(user.permissions);
    } catch {
      /* treat as empty */
    }
    const missing = ADMIN_PERMISSIONS.filter((p) => !(Array.isArray(perms) && perms.includes(p)));
    if (missing.length === 0) continue;

    await db
      .update(schema.users)
      .set({ permissions: JSON.stringify([...(Array.isArray(perms) ? perms : []), ...missing]) })
      .where(eq(schema.users.id, user.id));
    // eslint-disable-next-line no-console
    console.log(`[db] backfilled ${missing.length} permission(s) for admin user "${user.username}"`);
  }
}

/**
 * Idempotent: ensures the built-in `admin` role exists in the roles table and
 * carries every catalog permission. Mirrors backfillAdminPermissions() — new
 * permissions added to the catalog flow into the admin role on next API start,
 * so users holding the role pick them up at their next login.
 */
export async function backfillAdminRole(): Promise<void> {
  const existing = await db.query.roles.findFirst({ where: eq(schema.roles.name, 'admin') });

  if (!existing) {
    await db.insert(schema.roles).values({
      name: 'admin',
      description: 'Full access to all platform features (built-in role)',
      permissions: JSON.stringify(ADMIN_PERMISSIONS),
      createdAt: new Date().toISOString(),
    });
    // eslint-disable-next-line no-console
    console.log('[db] seeded built-in admin role');
    return;
  }

  let perms: string[] = [];
  try {
    perms = JSON.parse(existing.permissions);
  } catch {
    /* treat as empty */
  }
  const missing = ADMIN_PERMISSIONS.filter((p) => !(Array.isArray(perms) && perms.includes(p)));
  if (missing.length === 0) return;

  await db
    .update(schema.roles)
    .set({ permissions: JSON.stringify([...(Array.isArray(perms) ? perms : []), ...missing]) })
    .where(eq(schema.roles.name, 'admin'));
  // eslint-disable-next-line no-console
  console.log(`[db] backfilled ${missing.length} permission(s) into the admin role`);
}

/**
 * One-time migration from the legacy free-text `devices.site` column to the
 * sites table: each distinct non-empty site text becomes a Site row (named by
 * that text), devices are re-pointed at it, and the legacy column is dropped.
 * Idempotent — no-ops once the `site` column is gone.
 */
export async function backfillDeviceSites(): Promise<void> {
  const hasSiteCol = await pool.query(
    `SELECT 1 FROM information_schema.columns WHERE table_name = 'devices' AND column_name = 'site'`
  );
  if ((hasSiteCol.rowCount ?? 0) === 0) return;

  const distinct = await pool.query(
    `SELECT DISTINCT "site" AS s FROM devices WHERE "site" IS NOT NULL AND btrim("site") <> ''`
  );
  const now = new Date().toISOString();
  for (const { s } of distinct.rows as Array<{ s: string }>) {
    const name = String(s).trim();
    let siteId = (await db.query.sites.findFirst({ where: eq(schema.sites.name, name) }))?.id;
    if (!siteId) {
      siteId = uuidv4();
      await db.insert(schema.sites).values({ id: siteId, name, createdAt: now });
    }
    await pool.query(`UPDATE devices SET "siteId" = $1 WHERE btrim("site") = $2`, [siteId, String(s)]);
  }

  await pool.query(`ALTER TABLE devices DROP COLUMN IF EXISTS "site"`);
  // eslint-disable-next-line no-console
  console.log('[db] migrated legacy devices.site text values into sites and dropped the column');
}

/**
 * One-time backfill for the multi-provider secrets model: any secret rows that
 * predate the `type`/`providerId` columns are bound to the built-in
 * secrets-provider plugin and typed as `apiKey` (the legacy shape).
 */
export async function backfillSecrets(): Promise<void> {
  const SECRETS_PROVIDER_UUID = '00000000-0000-4000-8000-000000000002';
  const orphans = await db.query.secrets.findMany({
    where: (secrets, { isNull }) => isNull(secrets.providerId),
  });
  if (orphans.length === 0) {
    return;
  }
  await db
    .update(schema.secrets)
    .set({ providerId: SECRETS_PROVIDER_UUID, type: 'apiKey' })
    .where(isNull(schema.secrets.providerId));
  // eslint-disable-next-line no-console
  console.log(`[db] backfilled ${orphans.length} secret(s) to the built-in secrets provider`);
}