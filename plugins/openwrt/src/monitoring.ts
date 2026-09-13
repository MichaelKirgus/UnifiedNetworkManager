/**
 * Monitoring collection for OpenWRT — two-tier cadence mirroring opnsense:
 *   - LIVE every poll: CPU %, load, memory, per-interface traffic counters.
 *   - INVENTORY at SDK INVENTORY_INTERVAL_MS (15 min): board identity, networks,
 *     ARP/NDP, DHCP leases, routes, tunnels, wifi SSIDs, firewall rules,
 *     services, filesystems, certificates — cached per host with in-flight
 *     dedupe so N concurrent polls share one cold collection.
 *
 * The API's window scheduler sends collectInventory=false on metrics-only
 * polls; absent = full collection (old-API compatible). Absent metric keys are
 * load-bearing: they never wipe stored rows, while a present empty array is
 * authoritative. firewallRules uses null-on-failure for the same reason.
 */

import { INVENTORY_INTERVAL_MS } from '@unm/plugin-sdk';
import type { CertificateRow, MetricDescriptor } from '@unm/plugin-sdk';
import type { Backend } from './client/backend';
import type { InventorySnapshot, NetworkRow, PortRowLike, TunnelRow } from './types';

/** Window-based scheduling flag (absent = collect everything). */
export function wantsInventory(collectInventory: unknown): boolean {
  return collectInventory !== false;
}

// --- Per-host inventory cache -------------------------------------------------

interface CacheEntry {
  at: number;
  snapshot: InventorySnapshot;
}
const inventoryCache = new Map<string, CacheEntry>();
const inventoryInFlight = new Map<string, Promise<InventorySnapshot>>();

/** Returns the cached snapshot when fresh, else collects (deduped). */
export async function getInventory(
  hostKey: string,
  backend: Backend,
  certificates: CertificateRow[]
): Promise<InventorySnapshot> {
  const hit = inventoryCache.get(hostKey);
  if (hit && Date.now() - hit.at < INVENTORY_INTERVAL_MS) return hit.snapshot;

  let pending = inventoryInFlight.get(hostKey);
  if (!pending) {
    pending = backend
      .collectInventory(certificates)
      .then((snap) => {
        inventoryCache.set(hostKey, { at: Date.now(), snapshot: snap });
        return snap;
      })
      .finally(() => inventoryInFlight.delete(hostKey));
    inventoryInFlight.set(hostKey, pending);
  }
  return pending;
}

// --- Live metrics ---------------------------------------------------------------

export interface LiveMetrics {
  metrics: Record<string, unknown>;
  interfaces: string[];
  /** True when the negotiated transport is degraded (auto mode fell back to SSH). */
  transportDegraded: boolean;
}

/** Collects the fast per-poll metrics (CPU/load/memory/traffic). */
export async function collectLive(backend: Backend): Promise<LiveMetrics> {
  const metrics: Record<string, unknown> = {};
  const [cpu, mem, traffic] = await Promise.all([
    backend.cpuLoad().catch(() => ({ percent: null, load1: null, load5: null, load15: null })),
    backend.memory().catch(() => ({ used: null, total: null, percent: null })),
    backend.traffic().catch(() => ({ counters: {}, rates: {} } as { counters: Record<string, { rx: number; tx: number }>; rates: Record<string, { rxBitsPerSec: number; txBitsPerSec: number }> })),
  ]);

  if (cpu.percent !== null) metrics['cpu.percent'] = cpu.percent;
  if (cpu.load1 !== null) metrics['load.1m'] = cpu.load1;
  if (cpu.load5 !== null) metrics['load.5m'] = cpu.load5;
  if (cpu.load15 !== null) metrics['load.15m'] = cpu.load15;
  if (mem.used !== null) metrics['memory.used'] = mem.used;
  if (mem.total !== null) metrics['memory.total'] = mem.total;
  if (mem.percent !== null) metrics['memory.percent'] = mem.percent;

  const interfaces: string[] = [];
  for (const name of Object.keys(traffic.counters)) {
    if (!interfaces.includes(name)) interfaces.push(name);
  }
  if (Object.keys(traffic.counters).length > 0) metrics['traffic'] = traffic.counters;

  // Aggregate bandwidth gauge: sum the live byte rates across all interfaces.
  // Scalar bits/sec values so they render as gauges in both the metrics view and
  // the device overview table (no explicit max → the webapp auto-scales the bar).
  let rxTotal = 0, txTotal = 0;
  for (const r of Object.values(traffic.rates)) {
    rxTotal += r.rxBitsPerSec;
    txTotal += r.txBitsPerSec;
  }
  if (rxTotal > 0) metrics['bandwidth.rx'] = rxTotal;
  if (txTotal > 0) metrics['bandwidth.tx'] = txTotal;

  // Degraded transport: auto mode with LuCI unreachable but SSH working.
  const degraded = backend.state.mode === 'auto' && !backend.state.luciBaseUrl && backend.state.sshAvailable;
  if (degraded) {
    metrics['system.transport'] = 'ssh (LuCI unavailable — using shell fallback)';
  }

  return { metrics, interfaces, transportDegraded: degraded };
}

// --- Full /monitoring assembly ---------------------------------------------------

export interface MonitoringResult {
  health: 'ok' | 'warning' | 'critical' | 'unknown';
  metrics: Record<string, unknown>;
  metricDescriptors: MetricDescriptor[];
}

/** Assembles the complete monitoring response for one poll. */
export async function collectMonitoring(
  hostKey: string,
  backend: Backend,
  opts: { collectInventory: boolean; certificates?: CertificateRow[] }
): Promise<MonitoringResult> {
  const live = await collectLive(backend);
  const metrics: Record<string, unknown> = { ...live.metrics };

  let inventory: InventorySnapshot | null = null;
  if (wantsInventory(opts.collectInventory)) {
    // Certificates are collected by the caller (credential-free probes) and
    // merged in here so they ride the same cache window.
    const certs = opts.certificates ?? [];
    inventory = await getInventory(hostKey, backend, certs);

    if (inventory.board?.hostname) metrics['hostname'] = inventory.board.hostname;
    if (inventory.board?.release) metrics['version'] = inventory.board.release;
    if (inventory.networks.length > 0) {
      metrics['networks'] = inventory.networks;
      // Ports: one row per interface (deduped by name) → device_ports table.
      const seen = new Map<string, PortRowLike>();
      for (const row of inventory.networks) {
        if (!row.name || seen.has(row.name)) continue;
        const extra: Record<string, unknown> = {};
        if (row.mac) extra.mac = row.mac;
        if (row.ip) extra.ip = `${row.ip}${row.prefix ? `/${row.prefix}` : ''}`;
        seen.set(row.name, {
          name: row.name,
          status: (row.status ?? 'unknown').toLowerCase(),
          ...(Object.keys(extra).length > 0 ? { extra } : {}),
          ...(row.vlanId !== undefined && row.vlanId !== null ? { vlanId: row.vlanId } : {}),
        });
      }
      const portRows = [...seen.values()];
      if (portRows.length > 0) metrics['ports'] = portRows;
    }
    if (inventory.arp.length > 0) metrics['arp'] = inventory.arp;
    if (inventory.ndp.length > 0) metrics['ndp'] = inventory.ndp;
    if (inventory.dhcpLeases.length > 0) metrics['dhcpLeases'] = inventory.dhcpLeases;
    if (inventory.routes.length > 0) metrics['routes'] = inventory.routes;
    if (inventory.tunnels.length > 0) {
      // Attach live byte rates from the traffic counters of each tunnel's interface.
      const traffic = (metrics['traffic'] ?? {}) as Record<string, { rx: number; tx: number }>;
      metrics['tunnels'] = attachTunnelRates(hostKey, inventory.tunnels, traffic);
    }
    if (inventory.wifiSsids.length > 0) metrics['wifiNetworks'] = inventory.wifiSsids;
    // firewallRules: null = collection failed → OMIT the key (keep previous rows).
    if (inventory.firewallRules !== null) {
      metrics['firewallRules'] = inventory.firewallRules;
    }
    if (inventory.services.length > 0) metrics['services'] = inventory.services;
    if (inventory.filesystems.length > 0) metrics['filesystems'] = inventory.filesystems;
    // Certificates — always emitted when present so renewals refresh in place.
    if (inventory.certificates.length > 0) {
      metrics['certificates'] = inventory.certificates;
    }
  }

  // Health: anything collected at all → ok. NOTE: running on the SSH transport
  // instead of LuCI is NOT a degradation — both are first-class data paths and
  // auto mode falling back to SSH is the intended behavior (many OpenWRT boxes,
  // including custom firmware builds, don't expose programmatic LuCI auth). The
  // `system.transport` metric still surfaces WHICH path was used for visibility.
  let health: MonitoringResult['health'];
  if (Object.keys(metrics).length === 0) {
    health = 'critical';
  } else {
    health = 'ok';
  }

  return { health, metrics, metricDescriptors: descriptorsFromMetrics(metrics) };
}

// --- Tunnel rate attachment -------------------------------------------------------

/** Per-tunnel byte-counter baselines (module-level; first poll has no delta). */
const tunnelRxTracker = new Map<string, { value: number; at: number }>();
const tunnelTxTracker = new Map<string, { value: number; at: number }>();

function sampleRate(map: Map<string, { value: number; at: number }>, key: string, current: number): number | null {
  const now = Date.now();
  const prev = map.get(key);
  map.set(key, { value: current, at: now });
  if (!prev || now <= prev.at) return null;
  if (current < prev.value) return null; // counter reset — skip
  return Math.round((current - prev.value) / ((now - prev.at) / 1000));
}

/** Merges live rx/tx byte rates into tunnel rows that expose an interface. */
export function attachTunnelRates(hostKey: string, tunnels: TunnelRow[], traffic: Record<string, { rx: number; tx: number }>): TunnelRow[] {
  return tunnels.map((t) => {
    if (!t.interfaceName || !traffic[t.interfaceName]) return t;
    const c = traffic[t.interfaceName];
    const rxRate = sampleRate(tunnelRxTracker, `${hostKey}:${t.name}:rx`, c.rx);
    const txRate = sampleRate(tunnelTxTracker, `${hostKey}:${t.name}:tx`, c.tx);
    return { ...t, rxRate: rxRate ?? t.rxRate ?? null, txRate: txRate ?? t.txRate ?? null };
  });
}

// --- Dynamic metric descriptors -----------------------------------------------------

/** Builds descriptors from the metrics actually collected (opnsense pattern). */
export function descriptorsFromMetrics(metrics: Record<string, unknown>): MetricDescriptor[] {
  const descriptors: MetricDescriptor[] = [];
  const seen = new Set<string>();
  const push = (d: MetricDescriptor): void => {
    if (!seen.has(d.key)) {
      seen.add(d.key);
      descriptors.push(d);
    }
  };

  if (typeof metrics['cpu.percent'] === 'number') {
    push({ key: 'cpu.percent', label: 'CPU', unit: '%', type: 'number', visualization: 'gauge', group: 'System', min: 0, max: 100, color: '#f59e0b', summary: true });
  }
  if (typeof metrics['memory.percent'] === 'number') {
    push({ key: 'memory.percent', label: 'Memory', unit: '%', type: 'number', visualization: 'gauge', group: 'System', min: 0, max: 100, color: '#8b5cf6', summary: true });
  }
  // Bandwidth gauges (aggregate rx/tx across all interfaces). No explicit max —
  // the webapp auto-scales the bar to a "nice" bound for whatever rate is seen.
  if (typeof metrics['bandwidth.rx'] === 'number') {
    push({ key: 'bandwidth.rx', label: 'Bandwidth RX', unit: 'bps', format: 'bits', type: 'number', visualization: 'gauge', group: 'Network', color: '#22c55e', summary: true });
  }
  if (typeof metrics['bandwidth.tx'] === 'number') {
    push({ key: 'bandwidth.tx', label: 'Bandwidth TX', unit: 'bps', format: 'bits', type: 'number', visualization: 'gauge', group: 'Network', color: '#06b6d4', summary: true });
  }
  if (typeof metrics['memory.used'] === 'number') {
    push({ key: 'memory.used', label: 'Memory Used', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'text', group: 'System' });
  }
  if (typeof metrics['memory.total'] === 'number') {
    push({ key: 'memory.total', label: 'Memory Total', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'text', group: 'System' });
  }
  for (const [key, label] of [['load.1m', 'Load 1m'], ['load.5m', 'Load 5m'], ['load.15m', 'Load 15m']] as const) {
    if (typeof metrics[key] === 'number') push({ key, label, type: 'number', visualization: 'text', group: 'System' });
  }
  if (metrics['hostname'] !== undefined) {
    push({ key: 'hostname', label: 'Hostname', type: 'string', visualization: 'text', group: 'Inventory', intervalMs: INVENTORY_INTERVAL_MS });
  }
  if (metrics['version'] !== undefined) {
    push({ key: 'version', label: 'Version', type: 'string', visualization: 'text', group: 'Inventory', intervalMs: INVENTORY_INTERVAL_MS });
  }
  if (typeof metrics['system.transport'] === 'string') {
    push({ key: 'system.transport', label: 'Transport', type: 'string', visualization: 'text', group: 'System' });
  }

  const traffic = metrics['traffic'];
  if (traffic && typeof traffic === 'object' && !Array.isArray(traffic)) {
    const rows = Object.keys(traffic as Record<string, unknown>);
    if (rows.length > 0) {
      push({ key: 'traffic', label: 'Interface Traffic', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'table', group: 'Network', rows, columns: ['rx', 'tx'] });
    }
  }

  const tables: Array<[string, string, string[]]> = [
    ['networks', 'Networks', ['name', 'ip', 'prefix', 'version', 'vlanId', 'mac']],
    ['arp', 'ARP Table', ['mac', 'ip', 'intf']],
    ['ndp', 'NDP Table', ['mac', 'ip', 'intf']],
    ['dhcpLeases', 'DHCP Leases', ['mac', 'ip', 'hostname', 'expiry']],
    ['routes', 'Routes', ['destination', 'gateway', 'protocol', 'status']],
    ['tunnels', 'Tunnels', ['name', 'type', 'peerAddress', 'subnet', 'status', 'interfaceName']],
    ['wifiNetworks', 'Wireless Networks', ['name', 'band', 'channel', 'encryption', 'ifc']],
    ['firewallRules', 'Firewall Rules', ['ruleType', 'position', 'protocol', 'sourceIp', 'destIp', 'action', 'enabled']],
    ['services', 'Services', ['name', 'enabled', 'running']],
    ['filesystems', 'Filesystems', ['name', 'type', 'sizeBytes', 'usedBytes', 'availBytes', 'mountpoint']],
  ];
  for (const [key, label, columns] of tables) {
    const v = metrics[key];
    if (Array.isArray(v) && v.length > 0) {
      push({ key, label, type: 'string', visualization: 'table', group: 'Inventory', columns, intervalMs: INVENTORY_INTERVAL_MS });
    }
  }

  // Fallback: any other numeric metric becomes a text card so nothing is lost.
  for (const [key, value] of Object.entries(metrics)) {
    if (seen.has(key)) continue;
    if (typeof value === 'number') push({ key, label: key, type: 'number', visualization: 'text', group: 'Other' });
  }

  return descriptors;
}
