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

// Credential policies controlling 2FA requirements. One GLOBAL row
// (`userId IS NULL`) acts as the default for everyone; a per-user row
// (unique on userId) overrides it entirely — user policy wins over global.
//   requiredMethods: which enrolled 2nd factors satisfy login step 2,
//     JSON array of 'totp' | 'webauthn'. Empty = no 2FA required at all.
//     If none of the allowed methods is enrolled, login is blocked with a
//     distinct error so the UI can point to enrollment.
//   gateAmrs: which JWT `amr` values satisfy require2FA (privileged endpoints
//     like config-job submission). Evaluated LIVE per request against this
//     table — admin changes apply immediately to existing sessions.
export const credentialPolicies = pgTable('credential_policies', {
  id: text('id').primaryKey(),
  // NULL = the global default policy; otherwise the user id it applies to.
  userId: text('userId').unique(),
  requiredMethods: text('requiredMethods').notNull().default('["totp"]'),
  gateAmrs: text('gateAmrs').notNull().default('["totp"]'),
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

// Add index for config_jobs
// Note: Drizzle's index definition inside the table definition is 
// usually the best way to handle this. I'll add it to configJobs.