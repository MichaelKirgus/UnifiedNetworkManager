import { pgTable, text, boolean, integer, bigint, doublePrecision, index, uniqueIndex, primaryKey } from 'drizzle-orm/pg-core';
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
    // Additional named credential slots declared by the plugin in /discover
    // (`credentialSlots`), e.g. { "web": "<secretId>" }. JSON object mapping
    // slot name → secrets.id; NULL/{} = no extra slots bound. Lets one device
    // assignment carry several distinct credentials (e.g. SNMP + web UI).
    extraCredentials: text('extraCredentials'),
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
  // Named credential slots declared by the plugin in /discover (JSON array of
  // { name, secretType, required?, description? }). Drives per-slot credential
  // pickers in the webapp's assignment builder; bound secrets live on
  // device_plugins.extraCredentials. NULL = no extra slots (primary secret only).
  credentialSlots: text('credentialSlots'),
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
    timestamp: text('timestamp').notNull(),
  },
  (table) => {
    return {
      idxPluginLogsDeviceTimestamp: index('idx_plugin_logs_device_timestamp')
        .on(table.deviceId, table.timestamp),
      idxPluginLogsPluginTimestamp: index('idx_plugin_logs_plugin_timestamp')
        .on(table.pluginId, table.timestamp),
      // Plain timestamp index for the retention sweep (DELETE WHERE timestamp < cutoff).
      idxPluginLogsTimestamp: index('idx_plugin_logs_timestamp').on(table.timestamp),
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
    timestamp: text('timestamp').notNull(),
  },
  (table) => {
    return {
      idxPluginMetricsPluginTimestamp: index('idx_plugin_metrics_plugin_timestamp')
        .on(table.pluginId, table.timestamp),
      // Plain timestamp index for the retention sweep.
      idxPluginMetricsTimestamp: index('idx_plugin_metrics_timestamp').on(table.timestamp),
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