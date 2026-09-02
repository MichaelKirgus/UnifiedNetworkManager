import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { db } from '../db';
import { and, eq, inArray, lt, notInArray, or, sql } from 'drizzle-orm';
import * as schema from '../db/schema';
import { getSecret } from '../secretsProvider';
import { settingsHeaders } from '../pluginSettings';
import { parseExtraCredentials } from '../types/credentialSlots';
import { decryptCredentialSlots, withSlots } from '../utils/slotCredentials';
import { getSystemSettings } from '../systemSettings';
import { LEADER_KEYS } from './leader';
import {
  initWorker,
  recordSkippedTelemetryBeat,
  recordTelemetryCycle,
  trackBeat,
} from './stats';

// Poll cadence is env-tunable for large fleets (see README "Scaling & HA"):
// more devices → longer beat, or raise TELEMETRY_MAX_CONCURRENCY instead.
// These are the ENV defaults — the Workers page can override both at runtime
// via system_settings (getSystemSettings), which wins over the environment.
const POLL_INTERVAL_MS = Math.max(5_000, Number(process.env.TELEMETRY_POLL_INTERVAL_MS ?? 30_000));
// Cap on in-flight /monitoring calls per cycle. Without a cap the burst grows
// linearly with fleet size (200 devices × 2 plugins = 400 simultaneous HTTP
// calls + DB writes), which spikes plugin event-loop lag and queues behind the
// Postgres pool. 64 keeps the beat smooth at any scale; raise for fast fleets.
const MAX_CONCURRENT_POLLS = Math.max(1, Number(process.env.TELEMETRY_MAX_CONCURRENCY ?? 64));
// Inventory rows not refreshed within this window are swept away (offline
// devices must not accumulate stale networks/hosts in the cross-device views).
const INVENTORY_STALE_AFTER_MS = 24 * 60 * 60 * 1000;
const INVENTORY_SWEEP_INTERVAL_MS = 10 * 60 * 1000;

/**
 * Runs `fn` over every item with at most `limit` invocations in flight.
 * Items are consumed in order by a fixed pool of workers — no extra deps.
 */
async function runWithConcurrency<T>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<void>
): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i]);
    }
  });
  await Promise.all(workers);
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
}

/** One assignment's poll outcome. `reachable` = the plugin answered at all
 * (transport OK); a transport failure yields health 'unknown' + reachable false.
 */
interface PollOutcome {
  health: string;
  reachable: boolean;
}

async function pollAssignment(target: AssignmentTarget): Promise<PollOutcome> {
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
    // tables (Networks + Hosts pages). Best-effort — a parse failure must
    // never break the telemetry cycle.
    ingestInventory(target.deviceId, target.pluginId, metrics, collectedAt);

    return { health, reachable: true };
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(
      `[telemetry] failed to poll device ${target.deviceId} via plugin ${target.pluginId}:`,
      (err as Error).message
    );
    return { health: 'unknown', reachable: false };
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
async function sweepStaleInventory(): Promise<void> {
  const cutoff = new Date(Date.now() - INVENTORY_STALE_AFTER_MS).toISOString();
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
  await db.delete(schema.wifiSsids).where(lt(schema.wifiSsids.collectedAt, cutoff));
  await db.delete(schema.wifiChannels).where(lt(schema.wifiChannels.collectedAt, cutoff));
  await db.delete(schema.wifiRadios).where(lt(schema.wifiRadios.collectedAt, cutoff));
  await db.delete(schema.wifiNeighbors).where(lt(schema.wifiNeighbors.collectedAt, cutoff));
  await db.delete(schema.wifiClients).where(lt(schema.wifiClients.lastSeenAt, cutoff));
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

async function pollAllDevices(): Promise<void> {
  // Disabled devices are not polled — their historical data and last metrics
  // stay preserved, and the status column keeps its last derived value.
  const devices = await db.query.devices.findMany({
    where: eq(schema.devices.enabled, true),
  });
  if (devices.length === 0) {
    recordTelemetryCycle(0, 0, Date.now() - cycleStartedAt);
    return;
  }

  // Load every assignment with its plugin endpoint in one pass.
  const assignments = await db.query.devicePlugins.findMany({});
  const pluginsById = new Map(
    (await db.query.plugins.findMany()).map((p) => [p.id, p] as const)
  );

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

  const targetsByDevice = new Map<string, AssignmentTarget[]>();
  for (const a of assignments) {
    const device = devices.find((d) => d.id === a.deviceId);
    const plugin = pluginsById.get(a.pluginId);
    if (!device || !plugin) continue; // stale assignment or unknown plugin: skip
    const ipAddresses: DeviceAddressView[] = [
      { address: device.managementAddress, isPrimary: true },
      ...(ipsByDevice.get(device.id) ?? []).map((address) => ({ address, isPrimary: false })),
    ];
    const list = targetsByDevice.get(device.id) ?? [];
    list.push({
      deviceId: device.id,
      managementAddress: device.managementAddress,
      ipAddresses,
      pluginId: a.pluginId,
      secretId: a.secretId,
      extraCredentials: parseExtraCredentials(a.extraCredentials),
      endpoint: plugin.endpoint,
      model: device.model ?? null,
      firmwareVersion: device.firmwareVersion ?? null,
    });
    targetsByDevice.set(device.id, list);
  }

  // Poll every assignment independently — one dead plugin must not take the
  // whole device down. Device status is derived worst-wins afterwards. The
  // concurrency cap keeps the per-beat burst flat regardless of fleet size.
  const entries = Array.from(targetsByDevice.entries());
  await runWithConcurrency(
    entries,
    MAX_CONCURRENT_POLLS,
    async ([deviceId, targets]) => {
      const outcomes = await Promise.all(targets.map((t) => pollAssignment(t)));
      const status = deriveDeviceStatus(outcomes);
      await db.update(schema.devices).set({ status }).where(eq(schema.devices.id, deviceId));
    }
  );

  recordTelemetryCycle(
    devices.length,
    entries.reduce((sum, [, targets]) => sum + targets.length, 0),
    Date.now() - cycleStartedAt
  );
}

/** True while a poll cycle is in flight — the timer skips overlapping beats. */
let pollCycleRunning = false;
/** Timestamp of the current (or last) cycle start — for duration stats. */
let cycleStartedAt = Date.now();

/**
 * Starts the telemetry polling loop. Each device's assigned plugins are asked
 * for a monitoring snapshot which is normalized and persisted to the
 * `telemetry` table (one row per plugin per cycle). The beat cadence +
 * concurrency cap are re-read from system_settings every iteration, so an
 * admin can tune them live from the Workers page without a restart.
 * Returns a stop function (the loop self-reschedules with setTimeout so the
 * next beat always picks up the latest configured interval).
 */
export function startTelemetryWorker(): () => void {
  initWorker('telemetry', LEADER_KEYS.telemetry);
  // eslint-disable-next-line no-console
  console.log(
    `[telemetry] worker started, polling every ${POLL_INTERVAL_MS / 1000}s (max ${MAX_CONCURRENT_POLLS} concurrent polls)`
  );

  let cycle = 0;
  let stopped = false;
  let timer: NodeJS.Timeout | null = null;

  const tick = async (): Promise<void> => {
    if (stopped) return;
    // Runtime-tunable cadence (Workers page overrides the env default).
    const settings = await getSystemSettings();
    cycle += 1;
    const sweepsPerCycle = Math.max(1, Math.round(INVENTORY_SWEEP_INTERVAL_MS / settings.telemetryPollIntervalMs));
    if (cycle % sweepsPerCycle === 0) {
      sweepStaleInventory().catch((err) => {
        // eslint-disable-next-line no-console
        console.error('[telemetry] inventory sweep failed:', err);
      });
    }
    // Cycle guard: a slow cycle (dead devices hitting their timeouts, big
    // fleet) must not stack on top of itself — overlapping cycles would poll
    // unreachable devices at MORE than the configured cadence and double the
    // write load. The next beat simply retries; no work is lost.
    if (pollCycleRunning) {
      recordSkippedTelemetryBeat();
      // eslint-disable-next-line no-console
      console.warn('[telemetry] previous poll cycle still running — skipping this beat');
    } else {
      pollCycleRunning = true;
      cycleStartedAt = Date.now();
      void trackBeat('telemetry', () => pollAllDevices())
        .catch((err) => {
          // eslint-disable-next-line no-console
          console.error('[telemetry] poll cycle failed:', err);
        })
        .finally(() => {
          pollCycleRunning = false;
        });
    }
    timer = setTimeout(() => void tick(), settings.telemetryPollIntervalMs);
  };

  // First beat after one interval (same as the old setInterval behavior).
  timer = setTimeout(() => void tick(), POLL_INTERVAL_MS);

  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
}

