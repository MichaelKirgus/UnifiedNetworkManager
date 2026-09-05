import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { db } from '../db';
import { and, eq, inArray, lt, notInArray, or, sql } from 'drizzle-orm';
import * as schema from '../db/schema';
import { getSecret } from '../secretsProvider';
import { getEffectiveSettings, settingsHeaders } from '../pluginSettings';
import { parseExtraCredentials } from '../types/credentialSlots';
import { decryptCredentialSlots, withSlots } from '../utils/slotCredentials';
import { getSystemSettings, type SystemSettings } from '../systemSettings';
import {
  deviceStatusDedupeKey,
  emitNotification,
  statusToSeverity,
} from '../notifications';
import { LEADER_KEYS } from './leader';
import {
  initWorker,
  recordSkippedTelemetryBeat,
  recordTelemetryCycle,
  recordTelemetryPoll,
  telemetryStats,
  trackBeat,
} from './stats';

// --- Window-based staggered scheduling --------------------------------------
// Instead of polling every device on a fixed beat (a synchronized burst that
// spikes API + plugin CPU, then sleeps), each assignment carries its own
// next-due deadline inside a configurable WINDOW:
//   - metrics window  (system setting telemetryPollIntervalMs, default 30 s):
//     how often /monitoring is called at all;
//   - inventory window (telemetryInventoryWindowMs, default 15 min): how often
//     the slow/static collection runs — polls in between send
//     collectInventory:false and plugins skip it.
// Deadlines are spread across each window by a stable per-target hash + jitter
// so fleet load stays flat instead of bursty; a global in-flight budget
// (telemetryMaxConcurrency) caps parallelism during catch-up bursts. Env vars
// only seed the defaults — system_settings (Workers page) wins at runtime.

const DISPATCH_TICK_MS = 1_000; // dispatcher resolution (due-list scan cadence)
const ROSTER_REFRESH_MS = 30_000; // re-read devices/assignments + windows this often
// Inventory rows not refreshed within the cutoff are swept away (offline
// devices must not accumulate stale networks/hosts in the cross-device views).
// The effective cutoff is max(this, 3 × inventory window) — see sweepStaleInventory.
const INVENTORY_STALE_AFTER_MS = 24 * 60 * 60 * 1000;
const INVENTORY_SWEEP_INTERVAL_MS = 10 * 60 * 1000;

/** Metric keys that carry cross-device inventory (ingested into their own tables). */
const INVENTORY_METRIC_KEYS = [
  'networks', 'arp', 'ndp', 'hosts', 'dhcpLeases', 'wlanClients', 'macTable', 'dockerHosts',
  'tunnels', 'routes', 'firewallRules',
  'wifiNetworks', 'wifiAirtime', 'wifiRadios', 'wifiNeighbors',
  'ports', 'filesystems', 'disks', 'containers', 'images',
] as const;

/** True when a snapshot carries at least one inventory array (any length). */
function hasInventoryKeys(metrics: Record<string, unknown>): boolean {
  for (const key of INVENTORY_METRIC_KEYS) {
    if (Array.isArray(metrics[key])) return true;
  }
  return false;
}

/** FNV-1a — stable across restarts/processes, used to spread deadlines. */
function stableHash(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function toIntOrNull(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.round(v);
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v);
    if (Number.isFinite(n)) return Math.round(n);
  }
  return null;
}

function clampInt(v: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.round(v)));
}

interface MonitoringResponse {
  health?: string;
  metrics?: Record<string, unknown>;
  metricDescriptors?: unknown[];
}

/** A device address as presented to plugins (primary flag included). */
interface DeviceAddressView {
  address: string;
  isPrimary: boolean;
}

/** One plugin's view of a device (assignment + its plugin row). */
interface AssignmentTarget {
  deviceId: string;
  managementAddress: string;
  /** All device addresses, primary first. Lets plugins reach secondary IPs. */
  ipAddresses: DeviceAddressView[];
  pluginId: string;
  secretId: string | null;
  /** Bound extra credential slots (slot name → secrets.id). */
  extraCredentials: Record<string, string>;
  endpoint: string;
  // User-selected hardware model / firmware version (from a plugin's advertised
  // catalog). Forwarded to /monitoring so vendor plugins can adapt their data
  // gathering to the specific device. Null when unset.
  model: string | null;
  firmwareVersion: string | null;
  /** Per-device metrics-window override in ms (devices.pollIntervalMs); null = inherit. */
  pollIntervalMs: number | null;
}

/** One assignment's poll outcome. `reachable` = the plugin answered at all
 * (transport OK); a transport failure yields health 'unknown' + reachable false.
 * `inventoryEmitted` tells the dispatcher whether this snapshot carried any
 * inventory arrays — used to decide if the inventory deadline may advance.
 */
interface PollOutcome {
  health: string;
  reachable: boolean;
  inventoryEmitted: boolean;
}

interface PollOptions {
  /**
   * Whether this poll is an INVENTORY-due one. When false the plugin skips its
   * slow/static collection and omits inventory keys from `metrics` (absent key
   * = no wipe, per the ingestion contract). Old plugin images ignore the flag
   * and always answer with a full snapshot — harmless.
   */
  collectInventory: boolean;
}

async function pollAssignment(target: AssignmentTarget, opts: PollOptions): Promise<PollOutcome> {
  try {
    // The secrets provider plugin owns the crypto; the broker fetches the
    // decrypted secret on our behalf. Secrets are typed: `fields` holds the
    // decrypted values. For backward compatibility we also pass the legacy
    // `apiKey`/`apiSecret` keys when the secret is of type `apiKey`.
    const decrypted = target.secretId ? await getSecret(target.secretId) : null;
    const credentials = withSlots(
      decrypted?.fields ?? {},
      await decryptCredentialSlots(target.extraCredentials)
    );

    // Per-device settings overrides are resolved for THIS assignment scope.
    const headers = await settingsHeaders(target.pluginId, target.deviceId).catch(() => ({}));

    const response = await axios.post<MonitoringResponse>(
      `${target.endpoint.replace(/\/$/, '')}/monitoring`,
      {
        deviceId: target.deviceId,
        managementAddress: target.managementAddress,
        ipAddresses: target.ipAddresses,
        // Hardware model / firmware version selected by the user (may be null).
        model: target.model,
        firmwareVersion: target.firmwareVersion,
        credentials,
        // Window-based scheduling hint (see header comment): true only on
        // inventory-due polls so plugins can skip slow collection in between.
        collectInventory: opts.collectInventory,
        ...(decrypted?.type === 'apiKey'
          ? { apiKey: credentials.apiKey, apiSecret: credentials.apiSecret }
          : {})
      },
      { timeout: 10_000, headers }
    );

    const health = response.data?.health ?? 'unknown';
    const metrics = response.data?.metrics ?? {};
    const metricDescriptors = response.data?.metricDescriptors;
    const collectedAt = new Date().toISOString();

    await db.insert(schema.telemetry).values({
      id: uuidv4(),
      deviceId: target.deviceId,
      pluginId: target.pluginId,
      collectedAt,
      health,
      metrics: JSON.stringify(metrics),
      metricDescriptors: metricDescriptors ? JSON.stringify(metricDescriptors) : null,
    });

    // Normalize the inventory parts of this snapshot into the cross-device
    // tables (Networks + Hosts pages) — ONLY on inventory-due polls. Metrics-
    // only polls carry no inventory keys, so ingesting them would be a no-op;
    // skipping saves the DB round-trips entirely. Best-effort — a parse failure
    // must never break the telemetry cycle.
    if (opts.collectInventory) {
      ingestInventory(target.deviceId, target.pluginId, metrics, collectedAt);
    }

    return { health, reachable: true, inventoryEmitted: hasInventoryKeys(metrics) };
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(
      `[telemetry] failed to poll device ${target.deviceId} via plugin ${target.pluginId}:`,
      (err as Error).message
    );
    return { health: 'unknown', reachable: false, inventoryEmitted: false };
  }
}

/**
 * Normalizes the inventory parts of one monitoring snapshot into the
 * cross-device `networks` and `hosts` tables (Networks + Hosts pages). The
 * metric keys are generic — any plugin may emit them:
 *   - networks[]    { name, ip?, prefix?, version?, vlanId?, mac?, status? }
 *   - arp[] / ndp[] { mac, ip, intf?, manufacturer? }
 *   - dhcpLeases[]  { mac, ip, hostname?, expiry?, intf? }
 *   - wlanClients[] { mac, ip, hostname?, intf? } — associated WLAN clients
 *   - macTable[]    { mac, intf? } — switch MAC tables (e.g. SwOS !dhost.b):
 *                     learned MAC + port only, no IP → stored with source 'mac'
 * Rows are upserted on their natural key; a host seen again simply refreshes
 * lastSeenAt. Unknown/missing fields are tolerated — plugins evolve
 * independently of the API. Never throws: an inventory parse failure must not
 * break the telemetry cycle.
 */
async function ingestInventory(
  deviceId: string,
  pluginId: string,
  metrics: Record<string, unknown>,
  collectedAt: string
): Promise<void> {
  try {
    // --- networks ---------------------------------------------------------
    const rawNetworks = Array.isArray(metrics['networks']) ? (metrics['networks'] as unknown[]) : [];
    if (rawNetworks.length > 0) {
      const values: {
        deviceId: string; pluginId: string; name: string; ip: string; prefix: number | null;
        version: string | null; vlanId: number | null; mac: string | null; status: string | null;
        collectedAt: string;
      }[] = [];
      for (const raw of rawNetworks) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue;
        values.push({
          deviceId,
          pluginId,
          name,
          // '' = interface without an IP (kept for topology detection).
          ip: typeof r['ip'] === 'string' && (r['ip'] as string).trim() !== '' ? (r['ip'] as string).trim() : '',
          prefix: typeof r['prefix'] === 'number' && Number.isFinite(r['prefix']) ? Math.round(r['prefix']) : null,
          version: typeof r['version'] === 'string' ? (r['version'] as string) : null,
          vlanId: typeof r['vlanId'] === 'number' && Number.isFinite(r['vlanId']) ? Math.round(r['vlanId']) : null,
          mac: typeof r['mac'] === 'string' ? (r['mac'] as string).toLowerCase() : null,
          status: typeof r['status'] === 'string' ? (r['status'] as string) : null,
          collectedAt,
        });
      }
      // De-duplicate on the upsert conflict key — two rows with the same
      // (name, ip) in one snapshot make Postgres reject the whole batch
      // ("ON CONFLICT DO UPDATE command cannot affect row a second time").
      const netByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        netByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}|${v.ip}`, v);
      }
      if (netByKey.size > 0) {
        await db.insert(schema.networks).values(Array.from(netByKey.values())).onConflictDoUpdate({
          target: [schema.networks.deviceId, schema.networks.pluginId, schema.networks.name, schema.networks.ip],
          set: {
            prefix: sql`excluded."prefix"`,
            version: sql`excluded."version"`,
            vlanId: sql`excluded."vlanId"`,
            mac: sql`excluded.mac`,
            status: sql`excluded.status`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
    }

    // --- hosts (ARP / NDP neighbors + DHCP leases) -------------------------
    const hostValues: {
      deviceId: string; pluginId: string; mac: string; ip: string; source: string;
      hostname: string | null; manufacturer: string | null; intf: string | null;
      expiry: string | null; lastSeenAt: string;
    }[] = [];
    // Sources: arp/ndp/dhcp/wlan = neighbors observed by the device; 'self' =
    // the appliance's OWN interfaces (plugins emit these with their hostname so
    // cross-device MAC merging can name the box — neighbor tables carry no names).
    const pushHostRow = (source: string, raw: unknown): void => {
      if (!raw || typeof raw !== 'object') return;
      const r = raw as Record<string, unknown>;
      const mac = typeof r['mac'] === 'string' ? (r['mac'] as string).trim().toLowerCase() : '';
      const ip = typeof r['ip'] === 'string' ? (r['ip'] as string).trim() : '';
      // Skip placeholder addresses ("0.0.0.0" / "::") — some plugins report them
      // for hosts without an address yet; they are not joinable IPs.
      if (!mac) return;
      if (ip === '0.0.0.0' || ip === '::') return;
      // IP-less rows are allowed ONLY for source 'mac' — switch MAC tables
      // (e.g. SwOS !dhost.b) report learned MAC + port with no address.
      if (!ip && source !== 'mac') return;
      hostValues.push({
        deviceId,
        pluginId,
        mac,
        ip,
        source,
        hostname: typeof r['hostname'] === 'string' && (r['hostname'] as string).trim() !== '' ? (r['hostname'] as string) : null,
        manufacturer: typeof r['manufacturer'] === 'string' && (r['manufacturer'] as string).trim() !== '' ? (r['manufacturer'] as string) : null,
        intf: typeof r['intf'] === 'string' ? (r['intf'] as string) : null,
        expiry: typeof r['expiry'] === 'string' && (r['expiry'] as string).trim() !== '' ? (r['expiry'] as string) : null,
        lastSeenAt: collectedAt,
      });
    };
    for (const source of ['arp', 'ndp'] as const) {
      const rows = Array.isArray(metrics[source]) ? (metrics[source] as unknown[]) : [];
      for (const raw of rows) pushHostRow(source, raw);
    }
    // The appliance's OWN interfaces — plugins emit these under `hosts` with
    // source 'self' + their hostname so cross-device MAC merging can name the box.
    const selfRows = Array.isArray(metrics['hosts']) ? (metrics['hosts'] as unknown[]) : [];
    for (const raw of selfRows) pushHostRow('self', raw);
    const leases = Array.isArray(metrics['dhcpLeases']) ? (metrics['dhcpLeases'] as unknown[]) : [];
    for (const raw of leases) pushHostRow('dhcp', raw);
    // WLAN clients (e.g. LANCOM station table) — source 'wlan'.
    const wlanClients = Array.isArray(metrics['wlanClients']) ? (metrics['wlanClients'] as unknown[]) : [];
    for (const raw of wlanClients) pushHostRow('wlan', raw);
    // Switch MAC tables (e.g. SwOS !dhost.b) — learned MAC + port, no IP.
    const macRows = Array.isArray(metrics['macTable']) ? (metrics['macTable'] as unknown[]) : [];
    for (const raw of macRows) pushHostRow('mac', raw);

    // Docker/container hosts (e.g. TrueNAS Apps via `docker inspect` over SSH)
    // — source 'docker'. Rows carry a REAL MAC + IP + hostname, so they flow
    // through the standard pushHostRow path and merge by MAC with ARP/NDP
    // entries other devices report for the same container. Plugins only emit
    // these when a real MAC was retrieved (no empty-MAC rows).
    const dockerHosts = Array.isArray(metrics['dockerHosts']) ? (metrics['dockerHosts'] as unknown[]) : [];
    for (const raw of dockerHosts) pushHostRow('docker', raw);

    // Same guard as above — one snapshot must not repeat a (mac, ip, source) row.
    const hostByKey = new Map<string, typeof hostValues[number]>();
    for (const v of hostValues) {
      hostByKey.set(`${v.deviceId}|${v.pluginId}|${v.mac}|${v.ip}|${v.source}`, v);
    }
    if (hostByKey.size > 0) {
      await db.insert(schema.hosts).values(Array.from(hostByKey.values())).onConflictDoUpdate({
        target: [schema.hosts.deviceId, schema.hosts.pluginId, schema.hosts.mac, schema.hosts.ip, schema.hosts.source],
        set: {
          hostname: sql`excluded.hostname`,
          manufacturer: sql`excluded.manufacturer`,
          intf: sql`excluded.intf`,
          expiry: sql`excluded.expiry`,
          lastSeenAt: sql`excluded."lastSeenAt"`,
        },
      });
    }

    // --- tunnels (WireGuard / OpenVPN / IPsec / PPPoE / GRE) -----------------
    const rawTunnels = Array.isArray(metrics['tunnels']) ? (metrics['tunnels'] as unknown[]) : [];
    if (rawTunnels.length > 0) {
      const values: {
        deviceId: string; pluginId: string; name: string; type: string; peerAddress: string;
        localAddress: string; subnet: string | null; status: string; uptimeSeconds: number | null;
        lastHandshakeSeconds: number | null;
        interfaceName: string | null; rxRate: number | null; txRate: number | null;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawTunnels) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        const type = typeof r['type'] === 'string' ? (r['type'] as string).trim().toLowerCase() : '';
        if (!name || !type) continue; // both are part of the conflict key
        values.push({
          deviceId,
          pluginId,
          name,
          type,
          peerAddress: typeof r['peerAddress'] === 'string' ? (r['peerAddress'] as string).trim() : '',
          localAddress: typeof r['localAddress'] === 'string' ? (r['localAddress'] as string).trim() : '',
          subnet: typeof r['subnet'] === 'string' && (r['subnet'] as string).trim() !== '' ? (r['subnet'] as string).trim() : null,
          status: typeof r['status'] === 'string' && (r['status'] as string).trim() !== '' ? (r['status'] as string).trim().toLowerCase() : 'unknown',
          uptimeSeconds: typeof r['uptimeSeconds'] === 'number' && Number.isFinite(r['uptimeSeconds']) ? r['uptimeSeconds'] : null,
          lastHandshakeSeconds: typeof r['lastHandshakeSeconds'] === 'number' && Number.isFinite(r['lastHandshakeSeconds']) ? r['lastHandshakeSeconds'] : null,
          interfaceName: typeof r['interfaceName'] === 'string' && (r['interfaceName'] as string).trim() !== '' ? (r['interfaceName'] as string).trim() : null,
          rxRate: typeof r['rxRate'] === 'number' && Number.isFinite(r['rxRate']) ? r['rxRate'] : null,
          txRate: typeof r['txRate'] === 'number' && Number.isFinite(r['txRate']) ? r['txRate'] : null,
          extra: r['extra'] && typeof r['extra'] === 'object' ? JSON.stringify(r['extra']) : '{}',
          collectedAt,
        });
      }
      // Same de-dup guard as the other inventory blocks.
      const tunnelByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        tunnelByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}|${v.type}`, v);
      }
      if (tunnelByKey.size > 0) {
        await db.insert(schema.tunnels).values(Array.from(tunnelByKey.values())).onConflictDoUpdate({
          target: [schema.tunnels.deviceId, schema.tunnels.pluginId, schema.tunnels.name, schema.tunnels.type],
          set: {
            peerAddress: sql`excluded."peerAddress"`,
            localAddress: sql`excluded."localAddress"`,
            subnet: sql`excluded.subnet`,
            status: sql`excluded.status`,
            uptimeSeconds: sql`excluded."uptimeSeconds"`,
            lastHandshakeSeconds: sql`excluded."lastHandshakeSeconds"`,
            interfaceName: sql`excluded."interfaceName"`,
            rxRate: sql`excluded."rxRate"`,
            txRate: sql`excluded."txRate"`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      // Tunnels are CONFIG objects — a tunnel deleted on the device must vanish
      // from the page, not linger until the 24h sweep. Drop rows this snapshot
      // no longer reports (only when the key is present at all: an ABSENT key
      // means "plugin doesn't report tunnels", which must not wipe other data).
      const seenTunnelNames = new Set(values.map((v) => v.name));
      if (seenTunnelNames.size > 0) {
        await db.delete(schema.tunnels)
          .where(and(
            eq(schema.tunnels.deviceId, deviceId),
            eq(schema.tunnels.pluginId, pluginId),
            notInArray(schema.tunnels.name, Array.from(seenTunnelNames))
          ));
      }
    }

    // --- routes (static + dynamically-learned route entries) ----------------
    // The key is only processed when PRESENT in the snapshot: a present-but-EMPTY
    // array is authoritative ("this device has no routes right now" — e.g. TrueNAS
    // reports per-interface static_routes and emits [] once all are removed), so
    // stale rows get wiped below. An ABSENT key means "plugin doesn't report
    // routes at all" and must not touch the table (24h sweep still applies).
    const rawRoutes = Array.isArray(metrics['routes']) ? (metrics['routes'] as unknown[]) : null;
    if (rawRoutes !== null) {
      const ROUTE_PROTOCOLS = new Set(['static', 'connected', 'ospf', 'bgp', 'rip', 'other']);
      const values: {
        deviceId: string; pluginId: string; destination: string; gateway: string; protocol: string;
        distance: number | null; metric: number | null; mtu: number | null; status: string;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawRoutes) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const destination = typeof r['destination'] === 'string' ? (r['destination'] as string).trim() : '';
        let protocol = typeof r['protocol'] === 'string' ? (r['protocol'] as string).trim().toLowerCase() : '';
        if (!ROUTE_PROTOCOLS.has(protocol)) protocol = 'other'; // unknown labels never break the PK enum
        if (!destination) continue; // destination is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          destination,
          gateway: typeof r['gateway'] === 'string' ? (r['gateway'] as string).trim() : '',
          protocol,
          distance: typeof r['distance'] === 'number' && Number.isFinite(r['distance']) ? r['distance'] : null,
          metric: typeof r['metric'] === 'number' && Number.isFinite(r['metric']) ? r['metric'] : null,
          mtu: typeof r['mtu'] === 'number' && Number.isFinite(r['mtu']) ? Math.trunc(r['mtu']) : null,
          status: typeof r['status'] === 'string' && (r['status'] as string).trim() !== '' ? (r['status'] as string).trim().toLowerCase() : 'unknown',
          extra: r['extra'] && typeof r['extra'] === 'object' ? JSON.stringify(r['extra']) : '{}',
          collectedAt,
        });
      }
      // Same de-dup guard as the other inventory blocks.
      const routeByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        routeByKey.set(`${v.deviceId}|${v.pluginId}|${v.destination}|${v.protocol}`, v);
      }
      if (routeByKey.size > 0) {
        await db.insert(schema.routes).values(Array.from(routeByKey.values())).onConflictDoUpdate({
          target: [schema.routes.deviceId, schema.routes.pluginId, schema.routes.destination, schema.routes.protocol],
          set: {
            gateway: sql`excluded.gateway`,
            distance: sql`excluded.distance`,
            metric: sql`excluded.metric`,
            mtu: sql`excluded.mtu`,
            status: sql`excluded.status`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      // Routes are CONFIG/runtime objects — a route removed on the device must
      // vanish from the page, not linger until the 24h sweep. Drop rows this
      // snapshot no longer reports (only when the key is present at all: an
      // ABSENT key means "plugin doesn't report routes", which must not wipe
      // other data). Keyed on destination|protocol pairs — NOT destination
      // alone — so a static and an OSPF-learned route to the same prefix can't
      // wipe each other when only one of them is reported by this plugin.
      const existingRouteKeys = await db
        .select({ destination: schema.routes.destination, protocol: schema.routes.protocol })
        .from(schema.routes)
        .where(and(eq(schema.routes.deviceId, deviceId), eq(schema.routes.pluginId, pluginId)));
      const seenRouteKeys = new Set(values.map((v) => `${v.destination}|${v.protocol}`));
      const staleRoutes = existingRouteKeys.filter(
        (k) => !seenRouteKeys.has(`${k.destination}|${k.protocol}`)
      );
      if (staleRoutes.length > 0) {
        await db.delete(schema.routes).where(
          and(
            eq(schema.routes.deviceId, deviceId),
            eq(schema.routes.pluginId, pluginId),
            or(...staleRoutes.map((k) => and(eq(schema.routes.destination, k.destination), eq(schema.routes.protocol, k.protocol))))
          )
        );
      }
    }

    // --- firewall rules (filter + NAT kinds) ---------------------------------
    // Same present-vs-absent contract as routes: a PRESENT-but-empty array is
    // authoritative ("this device has no firewall rules right now") so stale rows
    // are wiped; an ABSENT key means "plugin doesn't report firewall rules" and
    // must not touch the table (24h sweep still applies). Identity is
    // ruleType|vendorRuleId — NOT vendorRuleId alone — because RouterOS .ids are
    // per-table (a filter rule and a NAT rule can share the same .id), so one
    // rule type's snapshot must never wipe another type's rows.
    const rawFirewallRules = Array.isArray(metrics['firewallRules']) ? (metrics['firewallRules'] as unknown[]) : null;
    if (rawFirewallRules !== null) {
      const FW_RULE_TYPES = new Set(['filter', 'dnat', 'snat', 'one-to-one', 'npt']);
      const values: {
        deviceId: string; pluginId: string; ruleType: string; vendorRuleId: string; position: number;
        protocol: string; sourceIp: string; destIp: string; sourcePort: string | null; destPort: string | null;
        action: string; enabled: boolean; description: string; scope: string; ipVersion: string;
        packets: number | null; bytes: number | null; states: number | null;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawFirewallRules) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        let ruleType = typeof r['ruleType'] === 'string' ? (r['ruleType'] as string).trim().toLowerCase() : '';
        if (!FW_RULE_TYPES.has(ruleType)) ruleType = 'filter'; // unknown labels never break the PK enum
        const vendorRuleId = typeof r['vendorRuleId'] === 'string' ? (r['vendorRuleId'] as string).trim() : '';
        if (!vendorRuleId) continue; // part of the conflict key
        values.push({
          deviceId,
          pluginId,
          ruleType,
          vendorRuleId,
          position: typeof r['position'] === 'number' && Number.isFinite(r['position']) ? Math.trunc(r['position']) : 0,
          protocol: typeof r['protocol'] === 'string' ? (r['protocol'] as string).trim().toLowerCase() : '',
          sourceIp: typeof r['sourceIp'] === 'string' ? (r['sourceIp'] as string).trim() : '',
          destIp: typeof r['destIp'] === 'string' ? (r['destIp'] as string).trim() : '',
          sourcePort: typeof r['sourcePort'] === 'string' && (r['sourcePort'] as string).trim() !== '' ? (r['sourcePort'] as string).trim() : null,
          destPort: typeof r['destPort'] === 'string' && (r['destPort'] as string).trim() !== '' ? (r['destPort'] as string).trim() : null,
          action: typeof r['action'] === 'string' && (r['action'] as string).trim() !== '' ? (r['action'] as string).trim().toLowerCase() : 'other',
          enabled: r['enabled'] !== false, // absent/true = enabled; only explicit false disables
          description: typeof r['description'] === 'string' ? (r['description'] as string).trim() : '',
          scope: typeof r['scope'] === 'string' ? (r['scope'] as string).trim() : '',
          ipVersion: (() => {
            const v = typeof r['ipVersion'] === 'string' ? (r['ipVersion'] as string).trim().toLowerCase() : '';
            return v === 'v6' || v === 'both' ? v : 'v4'; // default v4 when absent
          })(),
          packets: typeof r['packets'] === 'number' && Number.isFinite(r['packets']) ? Math.trunc(r['packets']) : null,
          bytes: typeof r['bytes'] === 'number' && Number.isFinite(r['bytes']) ? Math.trunc(r['bytes']) : null,
          states: typeof r['states'] === 'number' && Number.isFinite(r['states']) ? Math.trunc(r['states']) : null,
          extra: r['extra'] && typeof r['extra'] === 'object' ? JSON.stringify(r['extra']) : '{}',
          collectedAt,
        });
      }
      // Same de-dup guard as the other inventory blocks.
      const fwByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        fwByKey.set(`${v.deviceId}|${v.pluginId}|${v.ruleType}|${v.vendorRuleId}`, v);
      }
      if (fwByKey.size > 0) {
        await db.insert(schema.firewallRules).values(Array.from(fwByKey.values())).onConflictDoUpdate({
          target: [schema.firewallRules.deviceId, schema.firewallRules.pluginId, schema.firewallRules.ruleType, schema.firewallRules.vendorRuleId],
          set: {
            position: sql`excluded.position`,
            protocol: sql`excluded.protocol`,
            sourceIp: sql`excluded."sourceIp"`,
            destIp: sql`excluded."destIp"`,
            sourcePort: sql`excluded."sourcePort"`,
            destPort: sql`excluded."destPort"`,
            action: sql`excluded.action`,
            enabled: sql`excluded.enabled`,
            description: sql`excluded.description`,
            scope: sql`excluded.scope`,
            ipVersion: sql`excluded."ipVersion"`,
            packets: sql`excluded.packets`,
            bytes: sql`excluded.bytes`,
            states: sql`excluded.states`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      // A rule deleted on the device must vanish from the page, not linger until
      // the 24h sweep. Keyed on ruleType|vendorRuleId pairs (see note above).
      const existingFwKeys = await db
        .select({ ruleType: schema.firewallRules.ruleType, vendorRuleId: schema.firewallRules.vendorRuleId })
        .from(schema.firewallRules)
        .where(and(eq(schema.firewallRules.deviceId, deviceId), eq(schema.firewallRules.pluginId, pluginId)));
      const seenFwKeys = new Set(values.map((v) => `${v.ruleType}|${v.vendorRuleId}`));
      const staleFw = existingFwKeys.filter(
        (k) => !seenFwKeys.has(`${k.ruleType}|${k.vendorRuleId}`)
      );
      if (staleFw.length > 0) {
        await db.delete(schema.firewallRules).where(
          and(
            eq(schema.firewallRules.deviceId, deviceId),
            eq(schema.firewallRules.pluginId, pluginId),
            or(...staleFw.map((k) => and(eq(schema.firewallRules.ruleType, k.ruleType), eq(schema.firewallRules.vendorRuleId, k.vendorRuleId))))
          )
        );
      }
    }

    // --- WiFi (SSIDs / per-channel airtime / associated clients) ------------
    const numOrNull = (v: unknown): number | null =>
      typeof v === 'number' && Number.isFinite(v) ? v : null;

    const rawWifiNetworks = Array.isArray(metrics['wifiNetworks']) ? (metrics['wifiNetworks'] as unknown[]) : [];
    if (rawWifiNetworks.length > 0) {
      const values: {
        deviceId: string; pluginId: string; name: string; band: string; channel: number | null;
        bssid: string | null; encryption: string | null; vlanId: number | null; ifc: string | null;
        collectedAt: string;
      }[] = [];
      for (const raw of rawWifiNetworks) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue;
        values.push({
          deviceId,
          pluginId,
          name,
          band: typeof r['band'] === 'string' ? (r['band'] as string).trim() : '',
          channel: numOrNull(r['channel']),
          bssid: typeof r['bssid'] === 'string' && (r['bssid'] as string).trim() !== '' ? (r['bssid'] as string).trim().toLowerCase() : null,
          encryption: typeof r['encryption'] === 'string' && (r['encryption'] as string).trim() !== '' ? (r['encryption'] as string).trim() : null,
          vlanId: numOrNull(r['vlanId']),
          ifc: typeof r['ifc'] === 'string' && (r['ifc'] as string).trim() !== '' ? (r['ifc'] as string).trim() : null,
          collectedAt,
        });
      }
      const wifiByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        wifiByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}|${v.band}`, v);
      }
      if (wifiByKey.size > 0) {
        await db.insert(schema.wifiSsids).values(Array.from(wifiByKey.values())).onConflictDoUpdate({
          target: [schema.wifiSsids.deviceId, schema.wifiSsids.pluginId, schema.wifiSsids.name, schema.wifiSsids.band],
          set: {
            channel: sql`excluded.channel`,
            bssid: sql`excluded.bssid`,
            encryption: sql`excluded.encryption`,
            vlanId: sql`excluded."vlanId"`,
            ifc: sql`excluded.ifc`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      // SSIDs are CONFIG objects — a removed network must vanish from the page.
      const seenWifiNames = new Set(values.map((v) => v.name));
      if (seenWifiNames.size > 0) {
        await db.delete(schema.wifiSsids)
          .where(and(
            eq(schema.wifiSsids.deviceId, deviceId),
            eq(schema.wifiSsids.pluginId, pluginId),
            notInArray(schema.wifiSsids.name, Array.from(seenWifiNames))
          ));
      }
    }

    const rawWifiAirtime = Array.isArray(metrics['wifiAirtime']) ? (metrics['wifiAirtime'] as unknown[]) : [];
    if (rawWifiAirtime.length > 0) {
      const values: { deviceId: string; pluginId: string; channel: number; utilizationPct: number | null; collectedAt: string }[] = [];
      for (const raw of rawWifiAirtime) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const ch = numOrNull(r['channel']);
        if (ch === null) continue; // channel is part of the conflict key
        values.push({ deviceId, pluginId, channel: Math.round(ch), utilizationPct: numOrNull(r['utilizationPct']), collectedAt });
      }
      const airByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        airByKey.set(`${v.deviceId}|${v.pluginId}|${v.channel}`, v);
      }
      if (airByKey.size > 0) {
        await db.insert(schema.wifiChannels).values(Array.from(airByKey.values())).onConflictDoUpdate({
          target: [schema.wifiChannels.deviceId, schema.wifiChannels.pluginId, schema.wifiChannels.channel],
          set: {
            utilizationPct: sql`excluded."utilizationPct"`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenAirtimeChannels = new Set(values.map((v) => v.channel));
      if (seenAirtimeChannels.size > 0) {
        await db.delete(schema.wifiChannels)
          .where(and(
            eq(schema.wifiChannels.deviceId, deviceId),
            eq(schema.wifiChannels.pluginId, pluginId),
            notInArray(schema.wifiChannels.channel, Array.from(seenAirtimeChannels))
          ));
      }
    }

    // Radios — noise floor + bandwidth for the spectrum view. Upserted by ifc;
    // a radio that disappears (e.g. disabled) is dropped with its row.
    const rawWifiRadios = Array.isArray(metrics['wifiRadios']) ? (metrics['wifiRadios'] as unknown[]) : [];
    if (rawWifiRadios.length > 0) {
      const values: {
        deviceId: string; pluginId: string; ifc: string; band: string; channel: number | null;
        bandwidthMhz: number | null; noiseFloorDbm: number | null; collectedAt: string;
      }[] = [];
      for (const raw of rawWifiRadios) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        values.push({
          deviceId,
          pluginId,
          ifc: typeof r['ifc'] === 'string' ? (r['ifc'] as string).trim() : '',
          band: typeof r['band'] === 'string' ? (r['band'] as string).trim() : '',
          channel: numOrNull(r['channel']),
          bandwidthMhz: numOrNull(r['bandwidthMhz']),
          noiseFloorDbm: numOrNull(r['noiseFloorDbm']),
          collectedAt,
        });
      }
      const radioByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        radioByKey.set(`${v.deviceId}|${v.pluginId}|${v.ifc}`, v);
      }
      if (radioByKey.size > 0) {
        await db.insert(schema.wifiRadios).values(Array.from(radioByKey.values())).onConflictDoUpdate({
          target: [schema.wifiRadios.deviceId, schema.wifiRadios.pluginId, schema.wifiRadios.ifc],
          set: {
            band: sql`excluded.band`,
            channel: sql`excluded.channel`,
            bandwidthMhz: sql`excluded."bandwidthMhz"`,
            noiseFloorDbm: sql`excluded."noiseFloorDbm"`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenRadioIfcs = new Set(values.map((v) => v.ifc));
      if (seenRadioIfcs.size > 0) {
        await db.delete(schema.wifiRadios)
          .where(and(
            eq(schema.wifiRadios.deviceId, deviceId),
            eq(schema.wifiRadios.pluginId, pluginId),
            notInArray(schema.wifiRadios.ifc, Array.from(seenRadioIfcs))
          ));
      }
    }

    // Neighbor networks — scanner-style list. Upserted by BSSID; neighbors that
    // left range are dropped each snapshot (the scan table is a live view).
    const rawWifiNeighbors = Array.isArray(metrics['wifiNeighbors']) ? (metrics['wifiNeighbors'] as unknown[]) : [];
    if (rawWifiNeighbors.length > 0) {
      const values: {
        deviceId: string; pluginId: string; bssid: string; ssid: string | null; band: string;
        channel: number | null; signalDbm: number | null; collectedAt: string;
      }[] = [];
      for (const raw of rawWifiNeighbors) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const bssid = typeof r['bssid'] === 'string' ? (r['bssid'] as string).trim().toLowerCase() : '';
        if (!bssid) continue; // BSSID is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          bssid,
          ssid: typeof r['ssid'] === 'string' && (r['ssid'] as string).trim() !== '' ? (r['ssid'] as string).trim() : null,
          band: typeof r['band'] === 'string' ? (r['band'] as string).trim() : '',
          channel: numOrNull(r['channel']),
          signalDbm: numOrNull(r['signalDbm']),
          collectedAt,
        });
      }
      const neighborByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        neighborByKey.set(`${v.deviceId}|${v.pluginId}|${v.bssid}`, v);
      }
      if (neighborByKey.size > 0) {
        await db.insert(schema.wifiNeighbors).values(Array.from(neighborByKey.values())).onConflictDoUpdate({
          target: [schema.wifiNeighbors.deviceId, schema.wifiNeighbors.pluginId, schema.wifiNeighbors.bssid],
          set: {
            ssid: sql`excluded.ssid`,
            band: sql`excluded.band`,
            channel: sql`excluded.channel`,
            signalDbm: sql`excluded."signalDbm"`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenBssids = new Set(values.map((v) => v.bssid));
      if (seenBssids.size > 0) {
        await db.delete(schema.wifiNeighbors)
          .where(and(
            eq(schema.wifiNeighbors.deviceId, deviceId),
            eq(schema.wifiNeighbors.pluginId, pluginId),
            notInArray(schema.wifiNeighbors.bssid, Array.from(seenBssids))
          ));
      }
    }

    // Associated WLAN clients — upserted by MAC (a roaming client keeps its
    // latest SSID/radio). Rows for stations that disappeared are dropped.
    const rawWifiClients = Array.isArray(metrics['wlanClients']) ? (metrics['wlanClients'] as unknown[]) : [];
    if (rawWifiClients.length > 0) {
      const values: {
        deviceId: string; pluginId: string; mac: string; ssid: string | null; ip: string | null;
        hostname: string | null; intf: string | null; signalDbm: number | null;
        txRateMbps: number | null; rxRateMbps: number | null; vlanId: number | null; lastSeenAt: string;
      }[] = [];
      for (const raw of rawWifiClients) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const mac = typeof r['mac'] === 'string' ? (r['mac'] as string).trim().toLowerCase() : '';
        if (!mac) continue; // MAC is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          mac,
          ssid: typeof r['ssid'] === 'string' && (r['ssid'] as string).trim() !== '' ? (r['ssid'] as string).trim() : null,
          ip: typeof r['ip'] === 'string' && (r['ip'] as string).trim() !== '' ? (r['ip'] as string).trim() : null,
          hostname: typeof r['hostname'] === 'string' && (r['hostname'] as string).trim() !== '' ? (r['hostname'] as string) : null,
          intf: typeof r['intf'] === 'string' && (r['intf'] as string).trim() !== '' ? (r['intf'] as string) : null,
          signalDbm: numOrNull(r['signalDbm']),
          txRateMbps: numOrNull(r['txRateMbps']),
          rxRateMbps: numOrNull(r['rxRateMbps']),
          vlanId: numOrNull(r['vlanId']),
          lastSeenAt: collectedAt,
        });
      }
      const clientByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        clientByKey.set(`${v.deviceId}|${v.pluginId}|${v.mac}`, v);
      }
      if (clientByKey.size > 0) {
        await db.insert(schema.wifiClients).values(Array.from(clientByKey.values())).onConflictDoUpdate({
          target: [schema.wifiClients.deviceId, schema.wifiClients.pluginId, schema.wifiClients.mac],
          set: {
            ssid: sql`excluded.ssid`,
            ip: sql`excluded.ip`,
            hostname: sql`excluded.hostname`,
            intf: sql`excluded.intf`,
            signalDbm: sql`excluded."signalDbm"`,
            txRateMbps: sql`excluded."txRateMbps"`,
            rxRateMbps: sql`excluded."rxRateMbps"`,
            vlanId: sql`excluded."vlanId"`,
            lastSeenAt: sql`excluded."lastSeenAt"`,
          },
        });
      }
      const seenClientMacs = new Set(values.map((v) => v.mac));
      if (seenClientMacs.size > 0) {
        await db.delete(schema.wifiClients)
          .where(and(
            eq(schema.wifiClients.deviceId, deviceId),
            eq(schema.wifiClients.pluginId, pluginId),
            notInArray(schema.wifiClients.mac, Array.from(seenClientMacs))
          ));
      }
    }

    // --- ports (network interfaces with live state) -------------------------
    // Ports are CONFIG objects — a removed interface must vanish from the table,
    // not linger until the 24h sweep. Same upsert + delete-on-absent pattern as
    // tunnels: an ABSENT key means "plugin doesn't report ports" (no wipe); a
    // present-but-EMPTY array is authoritative (wipes this device+plugin's rows).
    const rawPorts = Array.isArray(metrics['ports']) ? (metrics['ports'] as unknown[]) : null;
    if (rawPorts !== null) {
      const values: {
        deviceId: string; pluginId: string; name: string; status: string; speed: string | null;
        duplex: string | null; vlanId: number | null; poe: string | null; extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawPorts) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue; // name is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          name,
          status: typeof r['status'] === 'string' && (r['status'] as string).trim() !== '' ? (r['status'] as string).trim().toLowerCase() : 'unknown',
          speed: typeof r['speed'] === 'string' && (r['speed'] as string).trim() !== '' ? (r['speed'] as string).trim() : null,
          duplex: typeof r['duplex'] === 'string' && (r['duplex'] as string).trim() !== '' ? (r['duplex'] as string).trim() : null,
          vlanId: numOrNull(r['vlanId']),
          poe: typeof r['poe'] === 'string' && (r['poe'] as string).trim() !== '' ? (r['poe'] as string).trim() : null,
          extra: r['extra'] && typeof r['extra'] === 'object' ? JSON.stringify(r['extra']) : '{}',
          collectedAt,
        });
      }
      // Same de-dup guard as the other inventory blocks.
      const portByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        portByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      }
      if (portByKey.size > 0) {
        await db.insert(schema.devicePorts).values(Array.from(portByKey.values())).onConflictDoUpdate({
          target: [schema.devicePorts.deviceId, schema.devicePorts.pluginId, schema.devicePorts.name],
          set: {
            status: sql`excluded.status`,
            speed: sql`excluded.speed`,
            duplex: sql`excluded.duplex`,
            vlanId: sql`excluded."vlanId"`,
            poe: sql`excluded.poe`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenPortNames = new Set(values.map((v) => v.name));
      if (seenPortNames.size > 0) {
        await db.delete(schema.devicePorts)
          .where(and(
            eq(schema.devicePorts.deviceId, deviceId),
            eq(schema.devicePorts.pluginId, pluginId),
            notInArray(schema.devicePorts.name, Array.from(seenPortNames))
          ));
      }
    }

    // --- Storage (filesystems/pools/datasets + physical disks) --------------
    // Generic keys — any plugin may emit them:
    //   filesystems[] { name, type?, mountpoint?, sizeBytes?, usedBytes?, freeBytes?, status?, parent?, extra? }
    //   disks[]       { name, model?, serial?, capacityBytes?, rotationRate?, health?, poolName?, extra? }
    // Both are CONFIG objects → upsert-per-poll + delete-on-absent (a removed
    // dataset/disk must vanish from the page, not linger until the 24h sweep).
    // `extra` is a plugin-specific JSON object stored verbatim for the webapp's
    // expandable rows and future config/state endpoints; non-object values are
    // dropped defensively (a corrupt row must not break ingestion).
    const extraOf = (r: Record<string, unknown>): string => {
      const e = r['extra'];
      if (!e || typeof e !== 'object' || Array.isArray(e)) return '{}';
      try {
        return JSON.stringify(e);
      } catch {
        return '{}';
      }
    };
    const rawFilesystems = Array.isArray(metrics['filesystems']) ? (metrics['filesystems'] as unknown[]) : null;
    if (rawFilesystems !== null) {
      const values: {
        deviceId: string; pluginId: string; name: string; type: string; mountpoint: string | null;
        sizeBytes: number | null; usedBytes: number | null; freeBytes: number | null;
        status: string; parent: string | null; extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawFilesystems) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue;
        values.push({
          deviceId,
          pluginId,
          name,
          type: typeof r['type'] === 'string' && (r['type'] as string).trim() !== '' ? (r['type'] as string).trim().toLowerCase() : 'other',
          mountpoint: typeof r['mountpoint'] === 'string' && (r['mountpoint'] as string).trim() !== '' ? (r['mountpoint'] as string).trim() : null,
          sizeBytes: numOrNull(r['sizeBytes']),
          usedBytes: numOrNull(r['usedBytes']),
          freeBytes: numOrNull(r['freeBytes']),
          status: typeof r['status'] === 'string' && (r['status'] as string).trim() !== '' ? (r['status'] as string).trim().toLowerCase() : 'unknown',
          parent: typeof r['parent'] === 'string' && (r['parent'] as string).trim() !== '' ? (r['parent'] as string).trim() : null,
          extra: extraOf(r),
          collectedAt,
        });
      }
      const fsByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        fsByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      }
      if (fsByKey.size > 0) {
        await db.insert(schema.storageFilesystems).values(Array.from(fsByKey.values())).onConflictDoUpdate({
          target: [schema.storageFilesystems.deviceId, schema.storageFilesystems.pluginId, schema.storageFilesystems.name],
          set: {
            type: sql`excluded.type`,
            mountpoint: sql`excluded.mountpoint`,
            sizeBytes: sql`excluded."sizeBytes"`,
            usedBytes: sql`excluded."usedBytes"`,
            freeBytes: sql`excluded."freeBytes"`,
            status: sql`excluded.status`,
            parent: sql`excluded.parent`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenFsNames = new Set(values.map((v) => v.name));
      if (seenFsNames.size > 0) {
        await db.delete(schema.storageFilesystems)
          .where(and(
            eq(schema.storageFilesystems.deviceId, deviceId),
            eq(schema.storageFilesystems.pluginId, pluginId),
            notInArray(schema.storageFilesystems.name, Array.from(seenFsNames))
          ));
      }
    }

    const rawDisks = Array.isArray(metrics['disks']) ? (metrics['disks'] as unknown[]) : null;
    if (rawDisks !== null) {
      const values: {
        deviceId: string; pluginId: string; name: string; model: string | null; serial: string | null;
        capacityBytes: number | null; rotationRate: string; health: string; poolName: string | null;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawDisks) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue;
        values.push({
          deviceId,
          pluginId,
          name,
          model: typeof r['model'] === 'string' && (r['model'] as string).trim() !== '' ? (r['model'] as string).trim() : null,
          serial: typeof r['serial'] === 'string' && (r['serial'] as string).trim() !== '' ? (r['serial'] as string).trim() : null,
          capacityBytes: numOrNull(r['capacityBytes']),
          rotationRate: typeof r['rotationRate'] === 'string' && (r['rotationRate'] as string).trim() !== '' ? (r['rotationRate'] as string).trim().toLowerCase() : 'unknown',
          health: typeof r['health'] === 'string' && (r['health'] as string).trim() !== '' ? (r['health'] as string).trim().toLowerCase() : 'unknown',
          poolName: typeof r['poolName'] === 'string' && (r['poolName'] as string).trim() !== '' ? (r['poolName'] as string).trim() : null,
          extra: extraOf(r),
          collectedAt,
        });
      }
      const diskByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        diskByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      }
      if (diskByKey.size > 0) {
        await db.insert(schema.storageDisks).values(Array.from(diskByKey.values())).onConflictDoUpdate({
          target: [schema.storageDisks.deviceId, schema.storageDisks.pluginId, schema.storageDisks.name],
          set: {
            model: sql`excluded.model`,
            serial: sql`excluded.serial`,
            capacityBytes: sql`excluded."capacityBytes"`,
            rotationRate: sql`excluded."rotationRate"`,
            health: sql`excluded.health`,
            poolName: sql`excluded."poolName"`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenDiskNames = new Set(values.map((v) => v.name));
      if (seenDiskNames.size > 0) {
        await db.delete(schema.storageDisks)
          .where(and(
            eq(schema.storageDisks.deviceId, deviceId),
            eq(schema.storageDisks.pluginId, pluginId),
            notInArray(schema.storageDisks.name, Array.from(seenDiskNames))
          ));
      }
    }

    // --- Containers (Apps) --------------------------------------------------
    // Generic key — any plugin may emit it:
    //   containers[] { name, state?, image?, version?, upgradeAvailable?, extra? }
    // CONFIG objects → upsert-per-poll + delete-on-absent (an uninstalled app
    // must vanish from the page, not linger until the 24h sweep). `extra` is a
    // plugin-specific JSON object stored verbatim (networks[], ips[], ports[],
    // per-service detail) — same contract as storage_filesystems.extra.
    //
    // startedAt: the TrueNAS public API exposes NO container start-time, so UNM
    // tracks it from observed state transitions instead. When a row is RUNNING
    // and was NOT RUNNING on the previous poll (a transition, or our first
    // observation of it), we stamp collectedAt; while it stays RUNNING we keep
    // the existing value; when it leaves RUNNING we clear it to NULL. The result
    // is a lower-bound "running since" that resets correctly after restarts and
    // grows toward accuracy for apps UNM started watching mid-run (the UI labels
    // it as UNM-observed, not the container's true start time).
    const rawContainers = Array.isArray(metrics['containers']) ? (metrics['containers'] as unknown[]) : null;
    if (rawContainers !== null) {
      // Previous state + startedAt per app name for THIS device+plugin — needed
      // to detect RUNNING transitions without a second write round-trip.
      const prevRows = await db.query.containers.findMany({
        where: and(eq(schema.containers.deviceId, deviceId), eq(schema.containers.pluginId, pluginId)),
      });
      const prevByName = new Map<string, { state: string; startedAt: string | null }>();
      for (const p of prevRows) prevByName.set(p.name, { state: p.state, startedAt: p.startedAt });

      // Plugin-provided start times (e.g. TrueNAS `docker inspect` over SSH)
      // are the REAL container start — they win over transition tracking.
      const pluginStartedAt = new Map<string, string>();
      for (const raw of rawContainers) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const n = typeof r['name'] === 'string' ? r['name'].trim() : '';
        const s = typeof r['startedAt'] === 'string' && (r['startedAt'] as string).trim() !== '' ? (r['startedAt'] as string) : null;
        if (n && s) pluginStartedAt.set(n, s);
      }

      const values: {
        deviceId: string; pluginId: string; name: string; state: string; image: string | null;
        version: string | null; upgradeAvailable: boolean | null; startedAt: string | null;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawContainers) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue;
        const state = typeof r['state'] === 'string' && (r['state'] as string).trim() !== '' ? (r['state'] as string).trim().toUpperCase() : 'UNKNOWN';
        const prev = prevByName.get(name);
        let startedAt: string | null = null;
        if (state === 'RUNNING') {
          // Priority 1: the plugin's REAL start time (docker inspect over SSH)
          // — authoritative, resets correctly after restarts.
          const realStart = pluginStartedAt.get(name);
          if (realStart) {
            startedAt = realStart;
          } else {
            // Priority 2: transition tracking fallback. Continuous RUNNING with
            // an existing stamp → keep it; a fresh transition or first
            // observation → stamp now.
            startedAt = prev && prev.state === 'RUNNING' && prev.startedAt ? prev.startedAt : collectedAt;
          }
        }
        values.push({
          deviceId,
          pluginId,
          name,
          state,
          image: typeof r['image'] === 'string' && (r['image'] as string).trim() !== '' ? (r['image'] as string).trim() : null,
          version: typeof r['version'] === 'string' && (r['version'] as string).trim() !== '' ? (r['version'] as string).trim() : null,
          upgradeAvailable: typeof r['upgradeAvailable'] === 'boolean' ? (r['upgradeAvailable'] as boolean) : null,
          startedAt,
          extra: extraOf(r),
          collectedAt,
        });
      }
      const contByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        contByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      }
      if (contByKey.size > 0) {
        await db.insert(schema.containers).values(Array.from(contByKey.values())).onConflictDoUpdate({
          target: [schema.containers.deviceId, schema.containers.pluginId, schema.containers.name],
          set: {
            state: sql`excluded.state`,
            image: sql`excluded.image`,
            version: sql`excluded.version`,
            upgradeAvailable: sql`excluded."upgradeAvailable"`,
            startedAt: sql`excluded."startedAt"`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenContNames = new Set(values.map((v) => v.name));
      if (seenContNames.size > 0) {
        await db.delete(schema.containers)
          .where(and(
            eq(schema.containers.deviceId, deviceId),
            eq(schema.containers.pluginId, pluginId),
            notInArray(schema.containers.name, Array.from(seenContNames))
          ));
      } else if (rawContainers.length === 0) {
        // Present-but-EMPTY is the authoritative wipe: delete ALL rows for this
        // device+plugin. (The size>0 guard above must NOT swallow this case —
        // otherwise a plugin that stops reporting containers, e.g. via its
        // "Enable App/Container collection" option off, would leave stale rows.)
        await db.delete(schema.containers)
          .where(and(
            eq(schema.containers.deviceId, deviceId),
            eq(schema.containers.pluginId, pluginId)
          ));
      }
    }

    // --- Docker images ------------------------------------------------------
    // Generic key — any plugin may emit it:
    //   images[] { name, sizeBytes?, createdAt?, updateAvailable?, dangling?, extra? }
    // Same CONFIG-object lifecycle as containers (upsert-per-poll + delete-on-
    // absent, present-but-empty = authoritative wipe): an image removed from the
    // host must vanish from the Containers page's images panel on the next poll.
    const rawImages = Array.isArray(metrics['images']) ? (metrics['images'] as unknown[]) : null;
    if (rawImages !== null) {
      const values: {
        deviceId: string; pluginId: string; name: string; sizeBytes: number | null;
        createdAt: string | null; updateAvailable: boolean | null; dangling: boolean;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawImages) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue; // name is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          name,
          sizeBytes: numOrNull(r['sizeBytes']),
          createdAt: typeof r['createdAt'] === 'string' && (r['createdAt'] as string).trim() !== '' ? (r['createdAt'] as string) : null,
          updateAvailable: typeof r['updateAvailable'] === 'boolean' ? (r['updateAvailable'] as boolean) : null,
          dangling: r['dangling'] === true,
          extra: extraOf(r),
          collectedAt,
        });
      }
      const imgByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        imgByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      }
      if (imgByKey.size > 0) {
        await db.insert(schema.dockerImages).values(Array.from(imgByKey.values())).onConflictDoUpdate({
          target: [schema.dockerImages.deviceId, schema.dockerImages.pluginId, schema.dockerImages.name],
          set: {
            sizeBytes: sql`excluded."sizeBytes"`,
            createdAt: sql`excluded."createdAt"`,
            updateAvailable: sql`excluded."updateAvailable"`,
            dangling: sql`excluded.dangling`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenImgNames = new Set(values.map((v) => v.name));
      if (seenImgNames.size > 0) {
        await db.delete(schema.dockerImages)
          .where(and(
            eq(schema.dockerImages.deviceId, deviceId),
            eq(schema.dockerImages.pluginId, pluginId),
            notInArray(schema.dockerImages.name, Array.from(seenImgNames))
          ));
      } else if (rawImages.length === 0) {
        // Present-but-EMPTY is the authoritative wipe — same contract as containers.
        await db.delete(schema.dockerImages)
          .where(and(
            eq(schema.dockerImages.deviceId, deviceId),
            eq(schema.dockerImages.pluginId, pluginId)
          ));
      }
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(
      `[telemetry] inventory ingestion failed for device ${deviceId} via plugin ${pluginId}:`,
      (err as Error).message
    );
  }
}

/**
 * Drops inventory rows not refreshed within INVENTORY_STALE_AFTER_MS so
 * offline devices don't accumulate stale networks/hosts in the cross-device
 * views. ISO-8601 strings compare correctly lexicographically.
 */
async function sweepStaleInventory(inventoryWindowMs: number): Promise<void> {
  // Adaptive cutoff: with a long inventory window (e.g. 12 h) the plain 24 h
  // floor would self-sweep rows of perfectly healthy devices — require at least
  // three full windows of silence before a row counts as stale.
  const staleAfterMs = Math.max(INVENTORY_STALE_AFTER_MS, 3 * inventoryWindowMs);
  const cutoff = new Date(Date.now() - staleAfterMs).toISOString();
  // Disabled devices are intentionally not polled — their inventory rows must
  // survive the stale sweep (re-enabling a device restores its views without
  // waiting for fresh data).
  const disabledIds = (
    await db.query.devices.findMany({ where: eq(schema.devices.enabled, false) })
  ).map((d) => d.id);
  if (disabledIds.length > 0) {
    await db.delete(schema.hosts).where(and(lt(schema.hosts.lastSeenAt, cutoff), notInArray(schema.hosts.deviceId, disabledIds)));
    await db.delete(schema.networks).where(and(lt(schema.networks.collectedAt, cutoff), notInArray(schema.networks.deviceId, disabledIds)));
    await db.delete(schema.devicePorts).where(and(lt(schema.devicePorts.collectedAt, cutoff), notInArray(schema.devicePorts.deviceId, disabledIds)));
  } else {
    await db.delete(schema.hosts).where(lt(schema.hosts.lastSeenAt, cutoff));
    await db.delete(schema.networks).where(lt(schema.networks.collectedAt, cutoff));
    await db.delete(schema.devicePorts).where(lt(schema.devicePorts.collectedAt, cutoff));
  }
  // Tunnels/routes/Wi-Fi rows carry no deviceId — they are only ever refreshed
  // by polling enabled devices, so the plain stale sweep applies to them.
  await db.delete(schema.tunnels).where(lt(schema.tunnels.collectedAt, cutoff));
  await db.delete(schema.routes).where(lt(schema.routes.collectedAt, cutoff));
  await db.delete(schema.firewallRules).where(lt(schema.firewallRules.collectedAt, cutoff));
  await db.delete(schema.wifiSsids).where(lt(schema.wifiSsids.collectedAt, cutoff));
  await db.delete(schema.wifiChannels).where(lt(schema.wifiChannels.collectedAt, cutoff));
  await db.delete(schema.wifiRadios).where(lt(schema.wifiRadios.collectedAt, cutoff));
  await db.delete(schema.wifiNeighbors).where(lt(schema.wifiNeighbors.collectedAt, cutoff));
  await db.delete(schema.wifiClients).where(lt(schema.wifiClients.lastSeenAt, cutoff));
  await db.delete(schema.storageFilesystems).where(lt(schema.storageFilesystems.collectedAt, cutoff));
  await db.delete(schema.storageDisks).where(lt(schema.storageDisks.collectedAt, cutoff));
  await db.delete(schema.containers).where(lt(schema.containers.collectedAt, cutoff));
  await db.delete(schema.dockerImages).where(lt(schema.dockerImages.collectedAt, cutoff));
}

/**
 * Overall device status from per-assignment poll outcomes — worst-wins:
 *   any assignment UNREACHABLE → offline (transport failure / dead plugin);
 *   reachable but critical health → critical (device answers, real problem
 *     reported — e.g. a degraded pool; it is NOT offline);
 *   all ok → online; otherwise degraded.
 */
function deriveDeviceStatus(outcomes: PollOutcome[]): string {
  if (outcomes.length === 0) return 'unknown';
  if (outcomes.some((o) => !o.reachable)) return 'offline';
  if (outcomes.some((o) => o.health === 'critical')) return 'critical';
  if (outcomes.every((o) => o.health === 'ok')) return 'online';
  return 'degraded';
}

/**
 * Mirror a device status transition into the notification center.
 *   - degrading (offline/critical/degraded): one live row per condition via a
 *     stable dedupe key — re-emissions while ongoing just bump occurrences,
 *     and the notifications worker auto-resolves it when the device recovers;
 *   - recovering to online: a one-shot info note (unique key, no recurrence).
 * Never throws — notification failures must not break the poll cycle.
 */
async function emitDeviceStatusNotification(deviceId: string, prev: string, next: string): Promise<void> {
  try {
    const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
    const name = device?.name ?? deviceId;

    if (next === 'online' && prev !== 'unknown') {
      await emitNotification({
        severity: 'info',
        source: 'device',
        title: `${name} is back online`,
        message: `Device recovered from ${prev}.`,
        deviceId,
        context: { from: prev, to: next },
      });
      return;
    }

    const severity = statusToSeverity(next);
    if (!severity) return; // unknown/online — nothing to report

    await emitNotification({
      severity,
      source: 'device',
      title:
        next === 'offline'
          ? `${name} is offline`
          : next === 'critical'
            ? `${name} reports a critical problem`
            : `${name} is degraded`,
      message:
        next === 'offline'
          ? `Device stopped responding to monitoring (was ${prev}).`
          : `Health changed from ${prev} to ${next}.`,
      dedupeKey: deviceStatusDedupeKey(deviceId, next),
      deviceId,
      context: { from: prev, to: next },
    });
  } catch {
    // Best-effort by contract.
  }
}

// --- Dispatcher state -------------------------------------------------------

/** Per-assignment scheduling state (in-memory; re-staggered on restart). */
interface TargetState {
  target: AssignmentTarget;
  /** Stable identity `${deviceId}|${pluginId}` — survives roster refreshes. */
  key: string;
  metricsNextDueAt: number;
  inventoryNextDueAt: number;
  /** Effective windows (ms) resolved at the last roster refresh. */
  metricsWindowMs: number;
  inventoryWindowMs: number;
  /** True once this plugin emitted any inventory array in a snapshot. */
  everEmittedInventory: boolean;
  /** Consecutive inventory-due polls that came back without inventory keys. */
  inventoryMissStreak: number;
}

const targetStates = new Map<string, TargetState>();
/** Assignments currently being polled — prevents double-dispatch. */
const inFlightKeys = new Set<string>();
/** Last-known poll outcome per assignment (device status is worst-wins over these). */
const lastOutcomesByDevice = new Map<string, Map<string, PollOutcome>>();
/** In-memory mirror of devices.status (avoids a DB read per poll). */
const lastKnownStatus = new Map<string, string>();
/** Assignment count per device — status is only derived once all are known. */
const assignmentsPerDevice = new Map<string, number>();
let lastRosterRefreshAt = 0;
let lastSweepAt = 0;
/** Global safety net: a wedged dispatcher tick must never stack on itself. */
let dispatcherRunning = false;

/**
 * Effective windows for one assignment. Resolution order (most specific wins):
 *   plugin option @device scope → devices.pollIntervalMs column
 *   → plugin option @global scope → system setting.
 * The device column overrides the metrics window only; the inventory window is
 * then clamped to at least the metrics window (inventory can't refresh faster
 * than the poll itself).
 */
async function resolveWindows(
  target: AssignmentTarget,
  settings: SystemSettings
): Promise<{ metricsWindowMs: number; inventoryWindowMs: number }> {
  const deviceOpts = await getEffectiveSettings(target.pluginId, target.deviceId).catch((): Record<string, unknown> => ({}));
  const globalOpts = await getEffectiveSettings(target.pluginId).catch((): Record<string, unknown> => ({}));

  let metricsWindowMs = toIntOrNull(deviceOpts['pollIntervalMs']);
  if (metricsWindowMs === null) metricsWindowMs = toIntOrNull(target.pollIntervalMs);
  if (metricsWindowMs === null) metricsWindowMs = toIntOrNull(globalOpts['pollIntervalMs']);
  if (metricsWindowMs === null) metricsWindowMs = settings.telemetryPollIntervalMs;
  metricsWindowMs = clampInt(metricsWindowMs, 5_000, 3_600_000);

  let inventoryWindowMs = toIntOrNull(deviceOpts['inventoryWindowMs']);
  if (inventoryWindowMs === null) inventoryWindowMs = toIntOrNull(globalOpts['inventoryWindowMs']);
  if (inventoryWindowMs === null) inventoryWindowMs = settings.telemetryInventoryWindowMs;
  inventoryWindowMs = clampInt(inventoryWindowMs, 30_000, 12 * 60 * 60_000);

  return { metricsWindowMs, inventoryWindowMs: Math.max(inventoryWindowMs, metricsWindowMs) };
}

/**
 * Re-reads enabled devices + assignments and (re)builds the scheduling state.
 * New targets get their first deadline staggered across the window via a stable
 * hash — a fleet boot or bulk import never produces a synchronized burst.
 */
async function refreshRoster(settings: SystemSettings): Promise<void> {
  const startedAt = Date.now();
  // Disabled devices are not polled — their historical data and last metrics
  // stay preserved, and the status column keeps its last derived value.
  const devices = await db.query.devices.findMany({ where: eq(schema.devices.enabled, true) });
  const deviceById = new Map(devices.map((d) => [d.id, d] as const));

  if (devices.length === 0) {
    targetStates.clear();
    lastOutcomesByDevice.clear();
    assignmentsPerDevice.clear();
    recordTelemetryCycle(0, 0, Date.now() - startedAt);
    return;
  }

  // Load every assignment with its plugin endpoint in one pass.
  const assignments = await db.query.devicePlugins.findMany({});
  const pluginsById = new Map((await db.query.plugins.findMany()).map((p) => [p.id, p] as const));

  // Secondary IPs per device (primary is always managementAddress). Batched.
  const deviceIds = devices.map((d) => d.id);
  const secondaryIps =
    deviceIds.length > 0
      ? await db.query.deviceIps.findMany({ where: inArray(schema.deviceIps.deviceId, deviceIds) })
      : [];
  const ipsByDevice = new Map<string, string[]>();
  for (const row of secondaryIps) {
    const list = ipsByDevice.get(row.deviceId) ?? [];
    list.push(row.address);
    ipsByDevice.set(row.deviceId, list);
  }

  const now = Date.now();
  const seenKeys = new Set<string>();
  for (const a of assignments) {
    const device = deviceById.get(a.deviceId);
    const plugin = pluginsById.get(a.pluginId);
    if (!device || !plugin) continue; // stale assignment or unknown plugin: skip
    const key = `${a.deviceId}|${a.pluginId}`;
    seenKeys.add(key);

    const target: AssignmentTarget = {
      deviceId: device.id,
      managementAddress: device.managementAddress,
      ipAddresses: [
        { address: device.managementAddress, isPrimary: true },
        ...(ipsByDevice.get(device.id) ?? []).map((address) => ({ address, isPrimary: false })),
      ],
      pluginId: a.pluginId,
      secretId: a.secretId,
      extraCredentials: parseExtraCredentials(a.extraCredentials),
      endpoint: plugin.endpoint,
      model: device.model ?? null,
      firmwareVersion: device.firmwareVersion ?? null,
      pollIntervalMs: device.pollIntervalMs ?? null,
    };

    const existing = targetStates.get(key);
    if (!existing) {
      // New assignment — stagger first deadlines across their windows.
      const windows = await resolveWindows(target, settings);
      targetStates.set(key, {
        target,
        key,
        metricsNextDueAt: now + (stableHash(key) % Math.max(1, windows.metricsWindowMs)),
        inventoryNextDueAt: now + (stableHash(`${key}:inv`) % Math.max(1, windows.inventoryWindowMs)),
        metricsWindowMs: windows.metricsWindowMs,
        inventoryWindowMs: windows.inventoryWindowMs,
        everEmittedInventory: false,
        inventoryMissStreak: 0,
      });
    } else {
      // Existing — refresh the target (endpoint/credentials may have changed)
      // and re-resolve windows; deadlines stay untouched.
      existing.target = target;
      const windows = await resolveWindows(target, settings);
      existing.metricsWindowMs = windows.metricsWindowMs;
      existing.inventoryWindowMs = windows.inventoryWindowMs;
    }
  }

  // Drop state for assignments that no longer exist (device deleted/disabled).
  for (const key of Array.from(targetStates.keys())) {
    if (!seenKeys.has(key)) targetStates.delete(key);
  }
  const liveDeviceIds = new Set(Array.from(seenKeys).map((k) => k.split('|')[0]));
  for (const deviceId of Array.from(lastOutcomesByDevice.keys())) {
    if (!liveDeviceIds.has(deviceId)) lastOutcomesByDevice.delete(deviceId);
  }

  // Per-device assignment counts + status mirror for transition detection.
  assignmentsPerDevice.clear();
  for (const state of targetStates.values()) {
    assignmentsPerDevice.set(
      state.target.deviceId,
      (assignmentsPerDevice.get(state.target.deviceId) ?? 0) + 1
    );
  }
  for (const d of devices) lastKnownStatus.set(d.id, d.status);

  recordTelemetryCycle(devices.length, targetStates.size, Date.now() - startedAt);
}

/** Dispatches one due assignment: poll → reschedule deadlines → update status. */
async function dispatchPoll(state: TargetState, settings: SystemSettings): Promise<void> {
  inFlightKeys.add(state.key);
  telemetryStats.pollsInFlight = inFlightKeys.size;
  const startedAt = Date.now();
  try {
    // Inventory-due? Checked at DISPATCH time — the deadline may have passed
    // while this target waited for a free slot.
    const collectInventory = Date.now() >= state.inventoryNextDueAt;

    const outcome = await pollAssignment(state.target, { collectInventory });
    recordTelemetryPoll(Date.now() - startedAt);

    // Reschedule the metrics deadline from COMPLETION (not dispatch) so a slow
    // device isn't double-polled back-to-back. Jitter decorrelates phases over
    // time so targets never re-synchronize.
    const jitter = 1 + (Math.random() * 2 - 1) * (settings.telemetryJitterPercent / 100);
    state.metricsNextDueAt = Date.now() + Math.max(5_000, state.metricsWindowMs * jitter);

    // Inventory deadline: advance only when the plugin actually delivered
    // inventory this poll — a transient collection failure retries on the next
    // metrics beat instead of waiting a full window. Plugins that never emit
    // inventory (e.g. ICMP) always advance; after 5 consecutive misses we force-
    // advance anyway so a permanently broken collector can't pin every poll to
    // full-collection mode.
    if (collectInventory) {
      const delivered = outcome.reachable && (!state.everEmittedInventory || outcome.inventoryEmitted);
      state.inventoryMissStreak = delivered ? 0 : state.inventoryMissStreak + 1;
      if (delivered || state.inventoryMissStreak >= 5) {
        state.inventoryNextDueAt = Date.now() + Math.max(30_000, state.inventoryWindowMs * jitter);
      }
    }
    if (outcome.inventoryEmitted) state.everEmittedInventory = true;

    await updateDeviceStatus(state.target.deviceId, state.key, outcome);
  } finally {
    inFlightKeys.delete(state.key);
    telemetryStats.pollsInFlight = inFlightKeys.size;
  }
}

/**
 * Device status = worst-wins over the LAST KNOWN outcome of every assignment.
 * With staggered deadlines each assignment polls at its own pace, so we keep a
 * per-assignment outcome cache and only derive once all of the device's
 * assignments have reported at least once (no boot-time flapping).
 */
async function updateDeviceStatus(
  deviceId: string,
  assignmentKey: string,
  outcome: PollOutcome
): Promise<void> {
  let byAssignment = lastOutcomesByDevice.get(deviceId);
  if (!byAssignment) {
    byAssignment = new Map();
    lastOutcomesByDevice.set(deviceId, byAssignment);
  }
  byAssignment.set(assignmentKey, outcome);

  const expected = assignmentsPerDevice.get(deviceId) ?? 1;
  if (byAssignment.size < expected) return; // wait for the full picture

  const status = deriveDeviceStatus(Array.from(byAssignment.values()));
  const prev = lastKnownStatus.get(deviceId) ?? 'unknown';
  if (status === prev) return;
  lastKnownStatus.set(deviceId, status);
  // Mirror the transition into the notification center. Degrading states carry
  // a stable dedupe key so they upsert while ongoing and are auto-resolved by
  // the notifications worker when the device recovers; recovery emits one-shot.
  void emitDeviceStatusNotification(deviceId, prev, status);
  await db.update(schema.devices).set({ status }).where(eq(schema.devices.id, deviceId));
}

/** One dispatcher tick: roster/sweeps on their cadences + dispatch due targets. */
async function dispatcherTick(): Promise<void> {
  const settings = await getSystemSettings();

  if (Date.now() - lastRosterRefreshAt >= ROSTER_REFRESH_MS) {
    lastRosterRefreshAt = Date.now();
    try {
      await refreshRoster(settings);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[telemetry] roster refresh failed:', err);
    }
  }

  if (Date.now() - lastSweepAt >= INVENTORY_SWEEP_INTERVAL_MS) {
    lastSweepAt = Date.now();
    void sweepStaleInventory(settings.telemetryInventoryWindowMs).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[telemetry] inventory sweep failed:', err);
    });
  }

  const now = Date.now();
  const budget = Math.max(1, settings.telemetryMaxConcurrency);

  // Due targets (not already in flight), most-overdue first for fair catch-up.
  const due: TargetState[] = [];
  for (const state of targetStates.values()) {
    if (!inFlightKeys.has(state.key) && now >= state.metricsNextDueAt) due.push(state);
  }
  telemetryStats.overdueWaiting = Math.max(0, due.length - (budget - inFlightKeys.size));

  const slots = budget - inFlightKeys.size;
  if (slots <= 0 || due.length === 0) return;
  due.sort((a, b) => a.metricsNextDueAt - b.metricsNextDueAt);
  for (const state of due.slice(0, slots)) {
    void dispatchPoll(state, settings).catch(() => undefined); // dispatchPoll never throws
  }
}

/**
 * Starts the telemetry dispatcher. Each assignment is polled once per metrics
 * window (staggered across the window) and carries a slower inventory deadline;
 * windows + concurrency are re-read from system_settings every tick, so an
 * admin can tune them live from the Workers page without a restart. Returns a
 * stop function.
 */
export function startTelemetryWorker(): () => void {
  initWorker('telemetry', LEADER_KEYS.telemetry);
  // eslint-disable-next-line no-console
  console.log('[telemetry] worker started (window-based staggered dispatcher, 1 s resolution)');

  let stopped = false;
  let timer: NodeJS.Timeout | null = null;

  const tick = async (): Promise<void> => {
    if (stopped) return;
    // Global safety net: a wedged tick must never stack on itself.
    if (!dispatcherRunning) {
      dispatcherRunning = true;
      try {
        await trackBeat('telemetry', () => dispatcherTick());
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error('[telemetry] dispatcher tick failed:', err);
      } finally {
        dispatcherRunning = false;
      }
    } else {
      recordSkippedTelemetryBeat();
    }
    timer = setTimeout(() => void tick(), DISPATCH_TICK_MS);
  };

  // First tick shortly after start (the roster refresh happens inside it).
  timer = setTimeout(() => void tick(), 500);

  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
}

