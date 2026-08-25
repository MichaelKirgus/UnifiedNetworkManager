import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { db } from '../db';
import { and, eq, inArray, lt, notInArray, sql } from 'drizzle-orm';
import * as schema from '../db/schema';
import { getSecret } from '../secretsProvider';
import { settingsHeaders } from '../pluginSettings';
import { parseExtraCredentials } from '../types/credentialSlots';
import { decryptCredentialSlots, withSlots } from '../utils/slotCredentials';

const POLL_INTERVAL_MS = 30_000;
// Inventory rows not refreshed within this window are swept away (offline
// devices must not accumulate stale networks/hosts in the cross-device views).
const INVENTORY_STALE_AFTER_MS = 24 * 60 * 60 * 1000;
const INVENTORY_SWEEP_INTERVAL_MS = 10 * 60 * 1000;

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

async function pollAssignment(target: AssignmentTarget): Promise<string> {
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

    return health;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(
      `[telemetry] failed to poll device ${target.deviceId} via plugin ${target.pluginId}:`,
      (err as Error).message
    );
    return 'unknown';
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
      await db.delete(schema.tunnels)
        .where(and(
          eq(schema.tunnels.deviceId, deviceId),
          eq(schema.tunnels.pluginId, pluginId),
          notInArray(schema.tunnels.name, Array.from(seenTunnelNames))
        ));
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
      await db.delete(schema.wifiSsids)
        .where(and(
          eq(schema.wifiSsids.deviceId, deviceId),
          eq(schema.wifiSsids.pluginId, pluginId),
          notInArray(schema.wifiSsids.name, Array.from(seenWifiNames))
        ));
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
      await db.delete(schema.wifiChannels)
        .where(and(
          eq(schema.wifiChannels.deviceId, deviceId),
          eq(schema.wifiChannels.pluginId, pluginId),
          notInArray(schema.wifiChannels.channel, Array.from(seenAirtimeChannels))
        ));
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
      await db.delete(schema.wifiClients)
        .where(and(
          eq(schema.wifiClients.deviceId, deviceId),
          eq(schema.wifiClients.pluginId, pluginId),
          notInArray(schema.wifiClients.mac, Array.from(seenClientMacs))
        ));
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
  await db.delete(schema.hosts).where(lt(schema.hosts.lastSeenAt, cutoff));
  await db.delete(schema.networks).where(lt(schema.networks.collectedAt, cutoff));
  await db.delete(schema.tunnels).where(lt(schema.tunnels.collectedAt, cutoff));
  await db.delete(schema.wifiSsids).where(lt(schema.wifiSsids.collectedAt, cutoff));
  await db.delete(schema.wifiChannels).where(lt(schema.wifiChannels.collectedAt, cutoff));
  await db.delete(schema.wifiClients).where(lt(schema.wifiClients.lastSeenAt, cutoff));
}

/**
 * Overall device status from per-assignment health — worst-wins:
 *   any critical → offline; all ok → online; otherwise degraded.
 */
function deriveDeviceStatus(healths: string[]): string {
  if (healths.length === 0) return 'unknown';
  if (healths.some((h) => h === 'critical')) return 'offline';
  if (healths.every((h) => h === 'ok')) return 'online';
  return 'degraded';
}

async function pollAllDevices(): Promise<void> {
  const devices = await db.query.devices.findMany();
  if (devices.length === 0) return;

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
  // whole device down. Device status is derived worst-wins afterwards.
  await Promise.all(
    Array.from(targetsByDevice.entries()).map(async ([deviceId, targets]) => {
      const healths = await Promise.all(targets.map((t) => pollAssignment(t)));
      const status = deriveDeviceStatus(healths);
      await db.update(schema.devices).set({ status }).where(eq(schema.devices.id, deviceId));
    })
  );
}

/**
 * Starts the telemetry polling loop. Every `POLL_INTERVAL_MS`, each device's
 * assigned plugins are asked for a monitoring snapshot which is normalized and
 * persisted to the `telemetry` table (one row per plugin per cycle).
 */
export function startTelemetryWorker(): NodeJS.Timeout {
  // eslint-disable-next-line no-console
  console.log(`[telemetry] worker started, polling every ${POLL_INTERVAL_MS / 1000}s`);

  // Stale-inventory sweep runs on its own cadence (cheap DELETEs) — counted in
  // poll cycles so the worker keeps a single timer.
  const sweepsPerCycle = Math.max(1, Math.round(INVENTORY_SWEEP_INTERVAL_MS / POLL_INTERVAL_MS));
  let cycle = 0;

  return setInterval(() => {
    cycle += 1;
    if (cycle % sweepsPerCycle === 0) {
      sweepStaleInventory().catch((err) => {
        // eslint-disable-next-line no-console
        console.error('[telemetry] inventory sweep failed:', err);
      });
    }
    pollAllDevices().catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[telemetry] poll cycle failed:', err);
    });
  }, POLL_INTERVAL_MS);
}
