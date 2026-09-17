/**
 * Generic SSH plugin — monitoring collection over POSIX shell commands.
 *
 * Two-tier cadence (mirrors openwrt/opnsense):
 *   - LIVE every poll: CPU % (/proc/stat delta), load, memory + swap
 *     (/proc/meminfo), per-interface byte counters (/sys/class/net) → rates,
 *     device clock (Time page).
 *   - INVENTORY at the SDK's 15-min interval: system identity, interfaces +
 *     MACs, ARP/NDP tables, routes, filesystems (df), disks (lsblk) — cached
 *     per host with in-flight dedupe so N concurrent polls share one cold run.
 *
 * Everything is best-effort POSIX: a missing tool (iproute2 on busybox boxes)
 * degrades to the /proc + /sys fallbacks; an absent metric key never wipes
 * stored rows, while a present-but-empty array is authoritative.
 */

import { INVENTORY_INTERVAL_MS, buildDeviceTimeInfo, listUpgradablePackages } from '@unm/plugin-sdk';
import type { MetricDescriptor, UpdateRow } from '@unm/plugin-sdk';
import { SshBackend } from './client/sshClient';
import type {
  BoardInfo,
  DiskRow,
  FilesystemRow,
  HostRow,
  InventorySnapshot,
  NetworkRow,
  PortRowLike,
  RouteRow,
} from './types';

// --- Per-host inventory cache -------------------------------------------------

interface CacheEntry {
  at: number;
  snapshot: InventorySnapshot;
}
const inventoryCache = new Map<string, CacheEntry>();
const inventoryInFlight = new Map<string, Promise<InventorySnapshot | null>>();
/** hostKey → last-failure timestamp — back off so a dead box isn't hammered every poll. */
const inventoryFailures = new Map<string, number>();
const INVENTORY_FAILURE_BACKOFF_MS = 60_000;

/**
 * Returns the cached snapshot when fresh, else collects (deduped).
 * Resolves to `null` when collection failed or is in backoff — callers must
 * treat null as "no inventory data this poll" and emit NO inventory keys at
 * all (absent key = no wipe of stored rows, per the ingestion contract).
 */
export async function getInventory(hostKey: string, backend: SshBackend): Promise<InventorySnapshot | null> {
  const hit = inventoryCache.get(hostKey);
  if (hit && Date.now() - hit.at < INVENTORY_INTERVAL_MS) return hit.snapshot;

  // Back off after a failed collection — retry at most once per minute.
  const lastFail = inventoryFailures.get(hostKey);
  if (lastFail !== undefined && Date.now() - lastFail < INVENTORY_FAILURE_BACKOFF_MS) {
    return null;
  }

  let pending = inventoryInFlight.get(hostKey);
  if (!pending) {
    const collector = new GenericSshCollector(backend);
    pending = collector
      .collectInventory()
      .then((snap: InventorySnapshot) => {
        // Only SUCCESSFUL collections are cached — a failure must never poison
        // the cache with an authoritative-empty snapshot.
        inventoryCache.set(hostKey, { at: Date.now(), snapshot: snap });
        inventoryFailures.delete(hostKey);
        return snap;
      })
      .catch((err) => {
        inventoryFailures.set(hostKey, Date.now());
        throw err;
      })
      .finally(() => inventoryInFlight.delete(hostKey));
    inventoryInFlight.set(hostKey, pending);
  }
  return pending;
}

// --- Update checks (Updates page) ---------------------------------------------
// Independent of the 15-min inventory cache on purpose: a forced refresh
// ("Check now") re-runs /monitoring with collectInventory=true even when the
// inventory snapshot is still fresh, so updates get their own shorter TTL to
// stay reasonably current without hammering `apt list --upgradable` every poll.
const UPDATES_TTL_MS = 5 * 60_000;
const updatesCache = new Map<string, { at: number; rows: UpdateRow[] }>();

/**
 * One row per upgradable OS package (kind 'os-package'), each carrying the
 * `packages.update` apply action. Resolves [] when nothing is upgradable —
 * that empty array IS authoritative (the API wipes stale rows). THROWS when
 * the box is unreachable so the caller omits the key entirely (no wipe on a
 * transient outage).
 */
export async function getUpdates(hostKey: string, backend: SshBackend): Promise<UpdateRow[]> {
  const hit = updatesCache.get(hostKey);
  if (hit && Date.now() - hit.at < UPDATES_TTL_MS) return hit.rows;

  // Liveness gate — a dead box must not be reported as "no updates".
  const ping = await backend.exec('true', 10_000);
  if (!ping || ping.code !== 0) {
    throw new Error(`Update check failed: SSH exec "true" returned code ${ping?.code ?? 'null'}`);
  }

  // listUpgradablePackages never throws (unknown PM / parse issues → []), so a
  // result here is authoritative for this host.
  const rows = await listUpgradablePackages(backend, { applyActionId: 'packages.update', perPackageApply: true });
  updatesCache.set(hostKey, { at: Date.now(), rows });
  return rows;
}

// --- Module-level baselines (survive per-request backend instances) -----------

/** Per-host /proc/stat busy-time baselines for the CPU gauge. */
const statBaselines = new Map<string, { total: number; idle: number; at: number }>();
/** Per-host byte-counter baselines for bandwidth rate computation. */
const trafficBaselines = new Map<string, { at: number; counters: Record<string, { rx: number; tx: number }> }>();

// ---------------------------------------------------------------------------
// Live metrics (every poll)
// ---------------------------------------------------------------------------

export interface LiveMetrics {
  metrics: Record<string, unknown>;
}

/** Collects the fast per-poll metrics (CPU/load/memory/swap/traffic/clock). */
export async function collectLive(backend: SshBackend): Promise<LiveMetrics> {
  const metrics: Record<string, unknown> = {};

  // ONE combined round-trip for all live reads — cheap on low-end boxes.
  const sections = await backend.runSections([
    { name: 'stat', cmd: "head -1 /proc/stat" },
    { name: 'loadavg', cmd: 'cat /proc/loadavg' },
    { name: 'meminfo', cmd: 'cat /proc/meminfo' },
    // lo + veth* excluded: loopback is noise, and veth pairs DOUBLE-COUNT container
    // traffic (it appears on both ends of the pair) — would inflate the aggregate.
    { name: 'counters', cmd: "for i in /sys/class/net/*; do n=$(basename $i); case $n in lo|veth*) continue;; esac; [ -f \"$i/statistics/rx_bytes\" ] && echo \"$n $(cat $i/statistics/rx_bytes) $(cat $i/statistics/tx_bytes)\"; done" },
    { name: 'date', cmd: "date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z" },
    { name: 'tz', cmd: "echo \"TZFILE=$(cat /etc/timezone 2>/dev/null)\"; echo \"SYMLINK=$(readlink -f /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##')\"" },
  ]).catch(() => new Map<string, string>());

  // --- CPU % + load -----------------------------------------------------------
  const statLine = sections.get('stat') ?? '';
  if (/^cpu\s+/.test(statLine)) {
    const pct = cpuPercentFromStat(backend.host, statLine);
    if (pct !== null) metrics['cpu.percent'] = pct;
  }
  const lm = (sections.get('loadavg') ?? '').match(/^([\d.]+)\s+([\d.]+)\s+([\d.]+)/);
  if (lm) {
    metrics['load.1m'] = Number(lm[1]);
    metrics['load.5m'] = Number(lm[2]);
    metrics['load.15m'] = Number(lm[3]);
  }

  // --- Memory + swap ------------------------------------------------------------
  const mem: Record<string, number> = {};
  for (const line of (sections.get('meminfo') ?? '').split('\n')) {
    const m = line.match(/^(\w+):\s+(\d+)\s*kB/);
    if (m) mem[m[1]] = Number(m[2]) * 1024;
  }
  const memTotal = mem['MemTotal'] ?? null;
  const memAvail = mem['MemAvailable'];
  const memUsed = memTotal !== null && memAvail !== undefined ? memTotal - memAvail : null;
  if (memTotal !== null) metrics['memory.total'] = memTotal;
  if (memUsed !== null) metrics['memory.used'] = memUsed;
  if (memTotal && memUsed !== null) metrics['memory.percent'] = Math.round((memUsed / memTotal) * 100);

  const swapTotal = mem['SwapTotal'];
  const swapFree = mem['SwapFree'];
  if (swapTotal !== undefined && swapTotal > 0) {
    const swapUsed = swapTotal - (swapFree ?? 0);
    metrics['swap.total'] = swapTotal;
    metrics['swap.used'] = Math.max(0, swapUsed);
    metrics['swap.percent'] = Math.round((Math.max(0, swapUsed) / swapTotal) * 100);
  }

  // --- Per-interface traffic counters → live rates ------------------------------
  const counters: Record<string, { rx: number; tx: number }> = {};
  for (const line of (sections.get('counters') ?? '').split('\n')) {
    const [name, rxS, txS] = line.trim().split(/\s+/);
    if (!name) continue;
    const rx = Number(rxS), tx = Number(txS);
    if (Number.isFinite(rx) && Number.isFinite(tx)) counters[name] = { rx, tx };
  }
  const rates = computeRates(backend.host, counters);
  if (Object.keys(counters).length > 0) metrics['traffic'] = counters;

  // Aggregate bandwidth gauges: sum the live byte rates across all interfaces.
  let rxTotal = 0, txTotal = 0;
  for (const r of Object.values(rates)) {
    rxTotal += r.rxBitsPerSec;
    txTotal += r.txBitsPerSec;
  }
  if (rxTotal > 0) metrics['bandwidth.rx'] = rxTotal;
  if (txTotal > 0) metrics['bandwidth.tx'] = txTotal;

  // --- Device clock (Time page) ---------------------------------------------------
  const localIso = (sections.get('date') ?? '').trim().split('\n')[0]?.trim() ?? '';
  if (localIso) {
    // `date -Iseconds` carries a UTC offset → epochMs resolves even without the zone.
    metrics['system.deviceTime'] = buildDeviceTimeInfo(localIso, resolveZone(sections.get('tz') ?? '')) ?? { localIso };
  }

  return { metrics };
}

/** IANA zone from the labelled TZFILE/SYMLINK probe (see openwrt deviceTime). */
function resolveZone(tzRaw: string): string | null {
  const isZone = (s: string): boolean =>
    s.length > 0 && s.length <= 40 && !/\s/.test(s) && /^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)*$/.test(s);
  for (const line of tzRaw.split('\n')) {
    const m = line.match(/^TZFILE=(.*)$/);
    if (m && isZone(m[1].trim())) return m[1].trim();
  }
  for (const line of tzRaw.split('\n')) {
    const m = line.match(/^SYMLINK=(.*)$/);
    if (m && isZone(m[1].trim())) return m[1].trim();
  }
  return null;
}

/** CPU % from the aggregate /proc/stat `cpu` line delta (busy/total). */
function cpuPercentFromStat(host: string, statLine: string): number | null {
  const m = statLine.match(/^cpu\s+([\d\s]+)/);
  if (!m) return null;
  const fields = m[1].trim().split(/\s+/).map(Number);
  if (fields.length < 4 || fields.some((n) => !Number.isFinite(n))) return null;
  const total = fields.reduce((a, b) => a + b, 0);
  // idle is field index 3; iowait (index 4) also counts as idle time.
  const idle = fields[3] + (fields[4] ?? 0);
  const now = Date.now();
  const prev = statBaselines.get(host);
  statBaselines.set(host, { total, idle, at: now });
  if (!prev || now <= prev.at) return null; // first sample — no delta yet
  const dTotal = total - prev.total;
  const dIdle = Math.max(0, idle - prev.idle);
  if (dTotal <= 0) return null; // counter reset/wrap
  return Math.max(0, Math.min(100, Math.round(((dTotal - dIdle) / dTotal) * 100)));
}

/** Per-interface bits/sec rates from cumulative byte-counter deltas. */
function computeRates(host: string, counters: Record<string, { rx: number; tx: number }>): Record<string, { rxBitsPerSec: number; txBitsPerSec: number }> {
  const now = Date.now();
  const prev = trafficBaselines.get(host);
  trafficBaselines.set(host, { at: now, counters });

  const rates: Record<string, { rxBitsPerSec: number; txBitsPerSec: number }> = {};
  if (!prev) return rates; // first sample — no delta yet
  const dtMs = now - prev.at;
  if (dtMs <= 0) return rates;

  for (const [name, c] of Object.entries(counters)) {
    const p = prev.counters[name];
    if (!p) continue;
    const drx = c.rx - p.rx;
    const dtx = c.tx - p.tx;
    if (drx < 0 || dtx < 0) continue; // counter reset/wrap — skip this round
    const rxBitsPerSec = Math.round((drx * 8) / (dtMs / 1000));
    const txBitsPerSec = Math.round((dtx * 8) / (dtMs / 1000));
    if (rxBitsPerSec > 0 || txBitsPerSec > 0) rates[name] = { rxBitsPerSec, txBitsPerSec };
  }
  return rates;
}

// ---------------------------------------------------------------------------
// Inventory collection (15-min cadence) — one SshBackend per host
// ---------------------------------------------------------------------------

export class GenericSshCollector {
  constructor(private readonly backend: SshBackend) {}

  /** System identity: hostname, OS release, uptime. */
  async boardInfo(): Promise<BoardInfo | null> {
    const sections = await this.backend.runSections([
      { name: 'hostname', cmd: "hostname 2>/dev/null" },
      // /etc/os-release (POSIX standard) → PRETTY_NAME; fall back to uname.
      { name: 'release', cmd: "grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | head -1 || true; grep -E '^NAME=|^VERSION=' /etc/os-release 2>/dev/null | head -2 || true; uname -sr 2>/dev/null" },
      { name: 'uptime', cmd: "awk '{print int($1)}' /proc/uptime 2>/dev/null" },
    ]).catch(() => new Map<string, string>());

    const hostname = (sections.get('hostname') ?? '').trim().split('\n')[0]?.trim() ?? '';
    let release = '';
    for (const line of (sections.get('release') ?? '').split('\n')) {
      const m = line.match(/^(?:PRETTY_NAME|NAME)=(.*)$/);
      if (m) { release = m[1].replace(/^["']|["']$/g, '').trim(); break; }
    }
    if (!release) {
      // Last line of the section is `uname -sr` output ("Linux 6.1.0").
      const lines = (sections.get('release') ?? '').split('\n').map((l) => l.trim()).filter(Boolean);
      release = lines[lines.length - 1] ?? '';
    }
    const uptime = Number((sections.get('uptime') ?? '0').trim());

    if (!hostname && !release) return null;
    return {
      hostname: hostname || this.backend.host,
      model: '',
      board: '',
      release,
      revision: null,
      uptimeSeconds: Number.isFinite(uptime) && uptime > 0 ? uptime : null,
    };
  }

  /** Interfaces + MACs — /sys/class/net (always present on Linux). */
  async interfaces(): Promise<NetworkRow[]> {
    const sections = await this.backend.runSections([
      // One line per interface: name mac operstate speedMbps.
      {
        name: 'ifaces',
        cmd: "for i in /sys/class/net/*; do n=$(basename $i); a=$(cat $i/address 2>/dev/null); s=$(cat $i/operstate 2>/dev/null); sp=$(cat $i/speed 2>/dev/null); echo \"$n|$a|${s:-unknown}|${sp:--1}\"; done",
      },
      // IP addresses — prefer iproute2, fall back to /proc/net/fib_trie (v4 only).
      { name: 'ipaddr', cmd: "ip -o addr show 2>/dev/null || true" },
    ]).catch(() => new Map<string, string>());

    // Base info per interface (MAC/state/VLAN) — one entry even without IPs.
    const base = new Map<string, { mac: string | null; status: string; vlanId: number | null }>();
    for (const line of (sections.get('ifaces') ?? '').split('\n')) {
      const [name, mac, state] = line.split('|');
      // lo + veth* are container plumbing — noise on every page and they churn
      // with every container restart. Bridges (br-*) and docker0 stay: they are
      // stable and meaningful for topology detection.
      if (!name || name === 'lo' || /^veth/.test(name)) continue;
      base.set(name, {
        mac: mac && /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(mac) ? mac.toLowerCase() : null,
        status: state === 'up' || state === 'unknown' ? (state === 'up' ? 'up' : 'down') : state ?? 'unknown',
        vlanId: name.match(/\.(\d+)$/)?.[1] !== undefined ? Number(name.match(/\.(\d+)$/)![1]) : null,
      });
    }

    // Parse `ip -o addr` lines: "2: eth0    inet 192.168.1.5/24 brd ... scope global eth0".
    type Cand = { addr: string; prefix: number | null; v6: boolean; rank: number };
    const cands = new Map<string, Cand[]>();
    for (const line of (sections.get('ipaddr') ?? '').split('\n')) {
      const m = line.match(/^\d+:\s+(\S+)\s+(?:inet|inet6)\s+(\S+)/);
      if (!m) continue;
      const [addr, prefix] = m[2].split('/');
      const v6 = m[0].includes('inet6') || addr.includes(':');
      // Rank: global IPv4 (0) > global IPv6 (1) > APIPA 169.254/16 (2) > loopback (3)
      // > fe80:: link-local / ::1 (4). Link-locals are noise on every Linux box —
      // they must never shadow the real management address in the best-row pick.
      let rank: number;
      if (!v6) {
        rank = /^169\.254\./.test(addr) ? 2 : /^127\./.test(addr) ? 3 : 0;
      } else {
        rank = addr.startsWith('fe80') || addr === '::1' ? 4 : 1;
      }
      const list = cands.get(m[1]) ?? [];
      list.push({ addr, prefix: prefix !== undefined && Number.isFinite(Number(prefix)) ? Number(prefix) : null, v6, rank });
      cands.set(m[1], list);
    }

    // ONE row per (interface, address) — the TrueNAS pattern. The API's networks
    // table is keyed by (name, ip), so dual-stack interfaces yield two rows that
    // merge into one logical network on the Networks page; an interface with no
    // IP at all still yields a single ip-less row for topology detection.
    const out: NetworkRow[] = [];
    for (const [name, list] of cands) {
      const b = base.get(name);
      if (!b) continue; // interface vanished between reads — fine
      list.sort((a, x) => a.rank - x.rank || a.addr.localeCompare(x.addr));
      for (const c of list) {
        out.push({ name, ip: c.addr, prefix: c.prefix, version: c.v6 ? 'v6' : 'v4', vlanId: b.vlanId, mac: b.mac, status: b.status });
      }
    }
    for (const [name, b] of base) {
      if (!cands.has(name)) out.push({ name, ip: null, prefix: null, version: null, vlanId: b.vlanId, mac: b.mac, status: b.status });
    }
    return out;
  }

  /** ARP + NDP neighbor tables — /proc/net/arp (always present) + ip -6 neigh. */
  async neighbors(): Promise<{ arp: HostRow[]; ndp: HostRow[] }> {
    const sections = await this.backend.runSections([
      { name: 'arp', cmd: 'cat /proc/net/arp 2>/dev/null' },
      { name: 'ndp', cmd: "ip -6 neigh show 2>/dev/null || true" },
    ]).catch(() => new Map<string, string>());

    const arp: HostRow[] = [];
    for (const line of (sections.get('arp') ?? '').split('\n').slice(1)) {
      // IP address HW type Flags HW address Mask Device
      const parts = line.trim().split(/\s+/);
      if (parts.length < 6) continue;
      const [ip, , flags, mac] = parts;
      if (!mac || mac === '00:00:00:00:00:00' || !/^\d/.test(ip)) continue;
      arp.push({ mac: mac.toLowerCase(), ip, hostname: null, manufacturer: null, intf: parts[7] ?? null });
    }

    const ndp: HostRow[] = [];
    for (const line of (sections.get('ndp') ?? '').split('\n')) {
      // 2001:db8::1 dev eth0 lladdr aa:bb:... REACHABLE
      const m = line.match(/^(\S+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-f:]+)/i);
      if (!m) continue;
      ndp.push({ mac: m[3].toLowerCase(), ip: m[1], hostname: null, manufacturer: null, intf: m[2] });
    }
    return { arp, ndp };
  }

  /** Routes — `ip route show` (static + connected + default). */
  async routes(): Promise<RouteRow[]> {
    const r = await this.backend.exec('ip route show 2>/dev/null').catch(() => null);
    if (!r || r.code !== 0) return [];
    const rows: RouteRow[] = [];
    for (const line of r.stdout.split('\n')) {
      // default via 192.168.1.1 dev eth0 / 192.168.1.0/24 dev br-lan proto kernel scope link src ...
      const m = line.trim().match(/^(default|(\S+))\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)/);
      if (!m) continue;
      rows.push({
        destination: m[1] === 'default' ? '0.0.0.0/0' : m[2],
        gateway: m[3],
        protocol: /proto kernel/.test(line) ? 'connected' : /proto static/.test(line) || (m[3] && m[1] !== 'default') ? 'static' : 'other',
        distance: null,
        metric: null,
        mtu: null,
        status: 'active',
        extra: { interface: m[4] },
      });
    }
    return rows;
  }

  /** Filesystems — `df -T` (POSIX). */
  async filesystems(): Promise<FilesystemRow[]> {
    const r = await this.backend.exec('df -kT 2>/dev/null').catch(() => null);
    if (!r || r.code !== 0) return [];
    const rows: FilesystemRow[] = [];
    for (const line of r.stdout.split('\n').slice(1)) {
      // Filesystem Type 1K-blocks Used Available Use% Mounted on
      const parts = line.trim().split(/\s+/);
      if (parts.length < 7) continue;
      const [fs, type, sizeS, usedS, availS, , mount] = parts;
      // Skip tmpfs/overlay noise? No — keep them: a container host's overlay IS its disk.
      rows.push({
        name: fs,
        type,
        sizeBytes: Number(sizeS) * 1024 || null,
        usedBytes: Number(usedS) * 1024 || null,
        availBytes: Number(availS) * 1024 || null,
        mountpoint: mount,
      });
    }
    return rows;
  }

  /** Physical disks — `lsblk` (util-linux; absent on minimal busybox → []). */
  async disks(): Promise<DiskRow[]> {
    const r = await this.backend.exec("lsblk -bno NAME,MODEL,SERIAL,SIZE,ROTA,TYPE 2>/dev/null").catch(() => null);
    if (!r || r.code !== 0) return [];
    const rows: DiskRow[] = [];
    for (const line of r.stdout.split('\n')) {
      // Only whole disks (partitions are children — they'd double-count capacity).
      const parts = line.trim().split(/\s+/);
      if (parts.length < 6) continue;
      const [name, model, serial, sizeS, rota, type] = parts;
      if (type !== 'disk') continue;
      rows.push({
        name,
        model: model && model !== '-' ? model : null,
        serial: serial && serial !== '-' ? serial : null,
        capacityBytes: Number(sizeS) || null,
        rotationRate: rota === '1' ? 'hdd' : rota === '0' ? 'ssd' : 'unknown',
        health: 'healthy', // no SMART access over plain SSH — assume healthy when listed
      });
    }
    return rows;
  }

  /** Full inventory snapshot (15-min cadence). Throws when the box is unreachable. */
  async collectInventory(): Promise<InventorySnapshot> {
    // Liveness gate FIRST: if even one trivial read fails, the whole collection
    // failed — throw so the caller emits NO inventory keys (absent = no wipe)
    // and the failure backoff kicks in instead of caching an empty snapshot.
    const ping = await this.backend.exec('true', 10_000);
    if (!ping || ping.code !== 0) {
      throw new Error(`Inventory collection failed: SSH exec "true" returned code ${ping?.code ?? 'null'}`);
    }

    const [board, networks, neighborsRes, routes, filesystems, disks] = await Promise.all([
      this.boardInfo().catch(() => null),
      this.interfaces().catch(() => [] as NetworkRow[]),
      this.neighbors().catch(() => ({ arp: [], ndp: [] })),
      this.routes().catch(() => [] as RouteRow[]),
      this.filesystems().catch(() => [] as FilesystemRow[]),
      this.disks().catch(() => [] as DiskRow[]),
    ]);

    // Ports: ONE row per interface (networks[] carries one row PER ADDRESS — the
    // device_ports table is keyed by name, so merge all addresses of an interface
    // into a single `ips` list in extra).
    const portByIface = new Map<string, PortRowLike & { ips: string[]; extra: Record<string, unknown> }>();
    for (const n of networks) {
      let p = portByIface.get(n.name);
      if (!p) {
        p = { name: n.name, status: (n.status ?? 'unknown').toLowerCase(), speed: null, duplex: null, vlanId: n.vlanId ?? undefined, poe: null, ips: [], extra: {} };
        portByIface.set(n.name, p);
      }
      if (n.mac) p.extra['mac'] = n.mac;
      if (n.ip) p.ips.push(`${n.ip}${n.prefix !== null ? `/${n.prefix}` : ''}`);
    }
    const ports: PortRowLike[] = [...portByIface.values()].map(({ ips, ...rest }) => ({
      ...rest,
      extra: { ...rest.extra, ...(ips.length > 0 ? { ip: ips[0], ips } : {}) },
    }));

    return {
      collectedAt: new Date().toISOString(),
      board,
      networks,
      arp: neighborsRes.arp,
      ndp: neighborsRes.ndp,
      routes,
      ports,
      filesystems,
      disks,
    };
  }
}

// ---------------------------------------------------------------------------
// Full /monitoring assembly
// ---------------------------------------------------------------------------

export interface MonitoringResult {
  health: 'ok' | 'warning' | 'critical' | 'unknown';
  metrics: Record<string, unknown>;
  metricDescriptors: MetricDescriptor[];
}

/** Assembles the complete monitoring response for one poll. */
export async function collectMonitoring(
  hostKey: string,
  backend: SshBackend,
  opts: { collectInventory: boolean }
): Promise<MonitoringResult> {
  const live = await collectLive(backend);
  const metrics: Record<string, unknown> = { ...live.metrics };

  if (opts.collectInventory) {
    // null = collection failed or in backoff → emit NO inventory keys at all.
    // An absent key means "no wipe" for the API's ingestion contract, so a
    // transient outage never blanks stored interfaces/routes/filesystems.
    const inventory = await getInventory(hostKey, backend).catch(() => null);
    if (inventory) {
      const board = inventory.board;
      if (board?.hostname) metrics['system.hostname'] = board.hostname;
      if (board?.release) metrics['system.osRelease'] = board.release;
      if (board && board.uptimeSeconds !== null && board.uptimeSeconds !== undefined) {
        metrics['system.uptime'] = board.uptimeSeconds;
      }
      // Present-but-empty is authoritative for these CONFIG/runtime tables:
      // a removed interface/route/filesystem must vanish, not linger 24h.
      if (inventory.networks.length > 0) {
        metrics['networks'] = inventory.networks;
        metrics['ports'] = inventory.ports;
      } else {
        metrics['networks'] = [];
        metrics['ports'] = [];
      }
      // Updates (Updates page): independent 5-min TTL so a forced refresh
      // re-checks even when the inventory snapshot above came from cache.
      // Failure → omit the key entirely (absent = no wipe, per ingestion contract).
      try {
        metrics['updates'] = await getUpdates(hostKey, backend);
      } catch {
        /* unreachable or transient — keep previously stored rows */
      }
      metrics['arp'] = inventory.arp;
      if (inventory.ndp.length > 0) metrics['ndp'] = inventory.ndp;
      metrics['routes'] = inventory.routes;
      metrics['filesystems'] = inventory.filesystems;
      if (inventory.disks.length > 0) metrics['disks'] = inventory.disks;
    }
  }

  // Health: anything collected at all → ok. A box that answers SSH but yields
  // no /proc data is still reachable — warning, not critical.
  let health: MonitoringResult['health'];
  if (Object.keys(metrics).length === 0) {
    health = 'critical';
  } else if (typeof metrics['cpu.percent'] !== 'number' && typeof metrics['memory.total'] !== 'number') {
    health = 'warning';
  } else {
    health = 'ok';
  }

  return { health, metrics, metricDescriptors: descriptorsFromMetrics(metrics) };
}

// --- Dynamic metric descriptors -------------------------------------------------

/** Builds descriptors from the metrics actually collected (openwrt pattern). */
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
  if (typeof metrics['swap.percent'] === 'number') {
    push({ key: 'swap.percent', label: 'Swap', unit: '%', type: 'number', visualization: 'gauge', group: 'System', min: 0, max: 100, color: '#64748b' });
  }
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
  if (typeof metrics['swap.used'] === 'number') {
    push({ key: 'swap.used', label: 'Swap Used', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'text', group: 'System' });
  }
  if (typeof metrics['swap.total'] === 'number') {
    push({ key: 'swap.total', label: 'Swap Total', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'text', group: 'System' });
  }
  for (const [key, label] of [['load.1m', 'Load 1m'], ['load.5m', 'Load 5m'], ['load.15m', 'Load 15m']] as const) {
    if (typeof metrics[key] === 'number') push({ key, label, type: 'number', visualization: 'text', group: 'System' });
  }
  if (metrics['system.hostname'] !== undefined) {
    push({ key: 'system.hostname', label: 'Hostname', type: 'string', visualization: 'text', group: 'Inventory', intervalMs: INVENTORY_INTERVAL_MS });
  }
  if (metrics['system.osRelease'] !== undefined) {
    push({ key: 'system.osRelease', label: 'OS Release', type: 'string', visualization: 'text', group: 'Inventory', intervalMs: INVENTORY_INTERVAL_MS });
  }
  if (typeof metrics['system.uptime'] === 'number') {
    push({ key: 'system.uptime', label: 'Uptime', unit: 's', format: 'duration', type: 'number', visualization: 'text', group: 'Inventory', intervalMs: INVENTORY_INTERVAL_MS });
  }

  const traffic = metrics['traffic'];
  if (traffic && typeof traffic === 'object' && !Array.isArray(traffic)) {
    const rows = Object.keys(traffic as Record<string, unknown>);
    if (rows.length > 0) {
      push({ key: 'traffic', label: 'Interface Traffic', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'table', group: 'Network', rows, columns: ['rx', 'tx'] });
    }
  }

  const tables: Array<[string, string, string[]]> = [
    ['networks', 'Network Interfaces', ['name', 'ip', 'prefix', 'version', 'mac', 'status']],
    ['arp', 'ARP Table', ['mac', 'ip', 'intf']],
    ['ndp', 'NDP Table', ['mac', 'ip', 'intf']],
    ['routes', 'Routes', ['destination', 'gateway', 'protocol', 'status']],
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
