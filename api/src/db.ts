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

// Pool size scales with the deployment (see README "Scaling & HA"): the default
// of 10 is fine for a few dozen devices, but at 100+ devices the telemetry
// worker's write wave can queue behind it. Raise via DATABASE_POOL_MAX.
const POOL_MAX = Math.max(1, Number(process.env.DATABASE_POOL_MAX ?? 20));

export const pool = new Pool({ connectionString: DATABASE_URL, max: POOL_MAX });
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

  // Plans: last terminal-status timestamp (top-bar plans icon "recently done").
  await pool.query(
    `ALTER TABLE plans ADD COLUMN IF NOT EXISTS "recentlyFinishedAt" TEXT`
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

  // Disabled devices are skipped by the telemetry worker (no polling); their
  // historical data + last metrics stay preserved. Default enabled.
  await pool.query(
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS "enabled" BOOLEAN NOT NULL DEFAULT TRUE`
  );

  // Per-device metrics poll window in ms (window-based telemetry scheduling).
  // NULL = inherit the plugin's global option / system setting.
  await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS "pollIntervalMs" INTEGER`);

  // Multi-type device roles + free-form tags (JSON arrays of strings).
  // The legacy single `deviceType` column is kept for old clients but becomes
  // nullable; its value is split into the array below.
  await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS "deviceTypes" TEXT NOT NULL DEFAULT '[]'`);
  await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS "tags" TEXT NOT NULL DEFAULT '[]'`);
  // One-time data migration: split legacy slash/comma-separated types
  // ("Router/Firewall", "Access Point") into the array, lowercase-normalized.
  await pool.query(`
    UPDATE devices SET "deviceTypes" = (
      SELECT COALESCE(jsonb_agg(DISTINCT LOWER(TRIM(elem))), '[]'::jsonb)
      FROM UNNEST(string_to_array(REPLACE("deviceType", '/', ','), ',')) AS elem
      WHERE TRIM(elem) <> ''
    )
    WHERE "deviceTypes" = '[]'
      AND "deviceType" IS NOT NULL
      AND TRIM(COALESCE("deviceType", '')) <> ''`);
  await pool.query(`ALTER TABLE devices ALTER COLUMN "deviceType" DROP NOT NULL`);

  // Network layers: registry for the topology view's horizontal bands. Seeded
  // with four built-ins; users may add custom ones (see routes/layers.ts). The
  // upsert only refreshes name/color of EXISTING built-in rows, so user edits
  // to a built-in's color persist across restarts — but new built-ins added in
  // future releases still appear.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS network_layers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      sort INTEGER NOT NULL DEFAULT 0,
      color TEXT NOT NULL,
      is_builtin BOOLEAN NOT NULL DEFAULT FALSE
    )`);
  const BUILTIN_LAYERS: Array<{ id: string; name: string; sort: number; color: string }> = [
    { id: 'core', name: 'Core', sort: 1, color: '#e11d48' },
    { id: 'distribution', name: 'Distribution', sort: 2, color: '#f59e0b' },
    { id: 'access', name: 'Access', sort: 3, color: '#10b981' },
    { id: 'endpoint', name: 'Endpoint', sort: 4, color: '#6366f1' },
  ];
  for (const l of BUILTIN_LAYERS) {
    await pool.query(
      `INSERT INTO network_layers (id, name, sort, color, is_builtin)
       VALUES ($1, $2, $3, $4, TRUE)
       ON CONFLICT (id) DO UPDATE SET
         name = EXCLUDED.name,
         color = EXCLUDED.color
       WHERE network_layers.is_builtin = TRUE`,
      [l.id, l.name, l.sort, l.color]
    );
  }

  // Manual topology-layer override on devices (NULL = auto-classify).
  await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS "layerOverride" TEXT`);

  // Telemetry retention sweep (workers/telemetryRetention.ts): a plain
  // timestamp index makes the periodic DELETE WHERE collectedAt < cutoff cheap.
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_telemetry_collected_at
      ON telemetry ("collectedAt")`);

  // Runtime-tunable system settings (Workers page → HA & workers panel).
  // Key/value rows; a stored value overrides the env default for that knob.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS system_settings (
      "key" TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      "updatedAt" TEXT NOT NULL
    )`);

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

  // Firewall rules inventory table (Firewall page) — same lifecycle as tunnels/routes.
  // One row per firewall rule (filter + NAT kinds) on one device, normalized by the
  // plugin to a unified shape. PK = deviceId+pluginId+ruleType+vendorRuleId so
  // reordering rules (position changes) never churns rows; delete-on-absent at
  // ingest keys on vendorRuleId per ruleType.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS firewall_rules (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      "ruleType" TEXT NOT NULL,
      "vendorRuleId" TEXT NOT NULL,
      position INTEGER NOT NULL DEFAULT 0,
      "ipVersion" TEXT NOT NULL DEFAULT 'v4',
      protocol TEXT NOT NULL DEFAULT '',
      "sourceIp" TEXT NOT NULL DEFAULT '',
      "destIp" TEXT NOT NULL DEFAULT '',
      "sourcePort" TEXT,
      "destPort" TEXT,
      action TEXT NOT NULL DEFAULT 'other',
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      description TEXT NOT NULL DEFAULT '',
      scope TEXT NOT NULL DEFAULT '',
      packets DOUBLE PRECISION,
      bytes DOUBLE PRECISION,
      states INTEGER,
      extra TEXT NOT NULL DEFAULT '{}',
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", "ruleType", "vendorRuleId")
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_firewall_rules_device ON firewall_rules ("deviceId")`);
  // Added after the initial release — existing deployments need the columns.
  await pool.query(`ALTER TABLE firewall_rules ADD COLUMN IF NOT EXISTS "ipVersion" TEXT NOT NULL DEFAULT 'v4'`);
  await pool.query(`ALTER TABLE firewall_rules ADD COLUMN IF NOT EXISTS packets DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE firewall_rules ADD COLUMN IF NOT EXISTS bytes DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE firewall_rules ADD COLUMN IF NOT EXISTS states INTEGER`);

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

  // Port inventory table (per-device Config page + future cross-device views).
  // One row per port/interface as reported by a plugin's `ports` metric — same
  // upsert-per-poll + delete-on-absent lifecycle as tunnels/routes.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_ports (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unknown',
      speed TEXT,
      duplex TEXT,
      "vlanId" INTEGER,
      poe TEXT,
      extra TEXT NOT NULL DEFAULT '{}',
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", name)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_device_ports_device ON device_ports ("deviceId")`);

  // Storage inventory tables (Storage page) — same lifecycle as tunnels/routes:
  // one row per filesystem/pool/dataset and per physical disk, upserted per
  // poll from the plugin's `filesystems` / `disks` metrics.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS storage_filesystems (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'other',
      mountpoint TEXT,
      "sizeBytes" DOUBLE PRECISION,
      "usedBytes" DOUBLE PRECISION,
      "freeBytes" DOUBLE PRECISION,
      status TEXT NOT NULL DEFAULT 'unknown',
      parent TEXT,
      extra TEXT NOT NULL DEFAULT '{}',
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", name)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_storage_filesystems_device ON storage_filesystems ("deviceId")`);

  // Plugin-specific details for filesystem rows (ZFS dataset props, ...) —
  // added after the initial release; existing tables get it via ALTER.
  await pool.query(`ALTER TABLE storage_filesystems ADD COLUMN IF NOT EXISTS extra TEXT NOT NULL DEFAULT '{}'`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS storage_disks (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      name TEXT NOT NULL,
      model TEXT,
      serial TEXT,
      "capacityBytes" DOUBLE PRECISION,
      "rotationRate" TEXT NOT NULL DEFAULT 'unknown',
      health TEXT NOT NULL DEFAULT 'unknown',
      "poolName" TEXT,
      extra TEXT NOT NULL DEFAULT '{}',
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", name)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_storage_disks_device ON storage_disks ("deviceId")`);

  // Plugin-specific details for disk rows — added after the initial release.
  await pool.query(`ALTER TABLE storage_disks ADD COLUMN IF NOT EXISTS extra TEXT NOT NULL DEFAULT '{}'`);

  // Containers inventory table (Containers page) — one row per App/container
  // workload, upserted per poll from the plugin's `containers` metric. Same
  // lifecycle as storage_filesystems (upsert + delete-on-absent + 24h sweep).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS containers (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      name TEXT NOT NULL,
      state TEXT NOT NULL DEFAULT 'UNKNOWN',
      image TEXT,
      version TEXT,
      "upgradeAvailable" BOOLEAN,
      extra TEXT NOT NULL DEFAULT '{}',
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", name)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_containers_device ON containers ("deviceId")`);

  // UNM-observed start of the current RUNNING period — added after the initial
  // release (the TrueNAS API exposes no container start-time; see schema.ts).
  await pool.query(`ALTER TABLE containers ADD COLUMN IF NOT EXISTS "startedAt" TEXT`);

  // Docker images inventory table (Containers page → collapsible images panel) —
  // one row per image, upserted per poll from the plugin's `images` metric.
  // Same lifecycle as containers (upsert + delete-on-absent + 24h sweep).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS docker_images (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      name TEXT NOT NULL,
      "sizeBytes" DOUBLE PRECISION,
      "createdAt" TEXT,
      "updateAvailable" BOOLEAN,
      "dangling" BOOLEAN NOT NULL DEFAULT FALSE,
      extra TEXT NOT NULL DEFAULT '{}',
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", name)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_docker_images_device ON docker_images ("deviceId")`);

  // VMs inventory table (VMs page) — one row per virtual machine, upserted per
  // poll from the plugin's `vms` metric. Same lifecycle as containers
  // (upsert + delete-on-absent + 24h sweep). TrueNAS SCALE VMs today; any
  // plugin may emit the generic key (e.g. a future Proxmox plugin).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS vms (
      "deviceId" TEXT NOT NULL,
      "pluginId" TEXT NOT NULL,
      name TEXT NOT NULL,
      state TEXT NOT NULL DEFAULT 'UNKNOWN',
      vcpus INTEGER,
      "memoryMiB" DOUBLE PRECISION,
      "archType" TEXT,
      "startedAt" TEXT,
      extra TEXT NOT NULL DEFAULT '{}',
      "collectedAt" TEXT NOT NULL,
      PRIMARY KEY ("deviceId", "pluginId", name)
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_vms_device ON vms ("deviceId")`);

  // Plugin log entries (see schema.pluginLogs). Pushed by plugins in batches
  // via POST /plugin/logs; swept by the retention worker after LOG_RETENTION_DAYS.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS plugin_logs (
      id TEXT PRIMARY KEY,
      "pluginId" TEXT NOT NULL,
      "deviceId" TEXT,
      level TEXT NOT NULL DEFAULT 'info',
      message TEXT NOT NULL,
      context TEXT,
      timestamp TEXT NOT NULL
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_plugin_logs_device_timestamp
      ON plugin_logs ("deviceId", timestamp)`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_plugin_logs_plugin_timestamp
      ON plugin_logs ("pluginId", timestamp)`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_plugin_logs_timestamp
      ON plugin_logs (timestamp)`);

  // Self-metrics samples of the plugin processes themselves (see schema.pluginMetrics).
  // Polled by workers/pluginMetrics.ts from each plugin's GET /metrics endpoint.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS plugin_metrics (
      id TEXT PRIMARY KEY,
      "pluginId" TEXT NOT NULL,
      "uptimeSeconds" INTEGER,
      "heapUsedBytes" BIGINT,
      "heapTotalBytes" BIGINT,
      "rssBytes" BIGINT,
      "cpuPercent" DOUBLE PRECISION,
      "eventLoopLagMs" DOUBLE PRECISION,
      "inFlight" INTEGER,
      "lastPollMs" DOUBLE PRECISION,
      "errorRatePercent" DOUBLE PRECISION,
      "emittedMetricsCount" INTEGER,
      "logQueueDepth" INTEGER,
      timestamp TEXT NOT NULL
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_plugin_metrics_plugin_timestamp
      ON plugin_metrics ("pluginId", timestamp)`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_plugin_metrics_timestamp
      ON plugin_metrics (timestamp)`);

  // WebAuthn passkeys per user + credential policies (see schema.ts). The
  // global policy row (userId IS NULL) is seeded once; it defaults to the
  // pre-passkey behavior: TOTP required at login, only `totp` satisfies the
  // require2FA gate.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS webauthn_credentials (
      id TEXT PRIMARY KEY,
      "userId" TEXT NOT NULL,
      "credentialId" TEXT NOT NULL UNIQUE,
      "publicKey" TEXT NOT NULL,
      "counter" BIGINT NOT NULL DEFAULT 0,
      "label" TEXT,
      "transports" TEXT,
      "createdAt" TEXT NOT NULL
    )`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user
      ON webauthn_credentials ("userId")`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS credential_policies (
      id TEXT PRIMARY KEY,
      "userId" TEXT UNIQUE,
      "requiredMethods" TEXT NOT NULL DEFAULT '["totp"]',
      "gateAmrs" TEXT NOT NULL DEFAULT '["totp"]',
      "updatedAt" TEXT NOT NULL
    )`);

  const existingGlobalPolicy = await pool.query(
    `SELECT id FROM credential_policies WHERE "userId" IS NULL LIMIT 1`
  );
  if (existingGlobalPolicy.rows.length === 0) {
    await pool.query(
      `INSERT INTO credential_policies (id, "userId", "requiredMethods", "gateAmrs", "updatedAt")
       VALUES ($1, NULL, '["totp"]', '["totp"]', $2)`,
      [uuidv4(), new Date().toISOString()]
    );
  }
  // Notification center (see schema.notifications / notificationPrefs). The
  // partial unique index on dedupeKey is what makes the worker's upsert cheap:
  // one live row per ongoing condition.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      "dedupeKey" TEXT,
      severity TEXT NOT NULL DEFAULT 'info',
      source TEXT NOT NULL DEFAULT 'system',
      "pluginId" TEXT,
      "deviceId" TEXT,
      title TEXT NOT NULL,
      message TEXT NOT NULL DEFAULT '',
      context TEXT,
      "createdAt" TEXT NOT NULL,
      "lastSeenAt" TEXT NOT NULL,
      occurrences INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'open',
      "acknowledgedBy" TEXT,
      "acknowledgedAt" TEXT,
      "resolvedAt" TEXT
    )`);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_notifications_dedupe_key
      ON notifications ("dedupeKey")
      WHERE "status" IN ('open', 'acknowledged') AND "dedupeKey" IS NOT NULL`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_notifications_status_created
      ON notifications (status, "createdAt")`);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_notifications_device_id
      ON notifications ("deviceId")`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notification_prefs (
      "userId" TEXT PRIMARY KEY,
      visibility TEXT NOT NULL DEFAULT '{}',
      "updatedAt" TEXT NOT NULL
    )`);
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