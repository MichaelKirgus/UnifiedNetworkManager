/**
 * Optional SSH data path for the OPNsense plugin — ZFS pool/dataset inventory.
 *
 * The OPNsense API exposes NO ZFS pool or dataset listing (only the mounted-root
 * overview via system_disk, see index.ts collectStorage). When a user binds an
 * `ssh` credential slot to this plugin, we run ONE combined read-only command on
 * the appliance and parse its output into Storage-page rows:
 *
 *   zfs list -o name,mountpoint,size,used,avail,compression,origin,created,encrypted
 *     (pools + datasets + zvols in one call)
 *   zpool status -v            (per-vdev state — degraded/failed disks)
 *   zpool get -H -o value scrub,pool    (last scrub per pool)
 *   zfs list -t snapshot -o name,used,referenced,volblocksize 2>/dev/null | head -n 400
 *     (snapshot count + space per dataset — the API has no snapshot listing either)
 *
 * Design constraints:
 *   - BEST-EFFORT ONLY. A missing slot, a failed login or a broken command must
 *     never affect health or wipe existing storage rows — the caller simply
 *     keeps the previous snapshot (the inventory cache is not updated).
 *   - INVENTORY CADENCE. The caller runs this at most every 15 min (same TTL as
 *     the rest of the inventory) and caches per host — never on every 30 s poll.
 *   - ONE SSH session, RE-USED across polls via the SDK pool (no re-auth per
 *     cycle); the whole collection is a single exec() round-trip.
 */

import { createSshPool, resolveSshCredentials, SshError } from '@unm/plugin-sdk';

/** Process-wide SSH pool — one session per appliance, kept alive between polls. */
const sshPool = createSshPool();

// Close every pooled session on shutdown (the container gets SIGTERM).
process.on('SIGTERM', () => sshPool.closeAll());
process.on('SIGINT', () => sshPool.closeAll());

/** One filesystem row for the Storage page (same shape as collectStorage's rows). */
export interface ZfsFsRow {
  name: string;
  type: 'zfs-pool' | 'zfs-dataset' | 'zfs-zvol';
  mountpoint?: string | null;
  sizeBytes?: number | null;
  usedBytes?: number | null;
  freeBytes?: number | null;
  status?: string;
  parent?: string | null;
  /** ZFS properties for the expandable row (compression, origin, created, ...). */
  extra?: Record<string, unknown>;
}

/** One physical disk / vdev leaf from `zpool status -v`. */
export interface ZfsDiskRow {
  name: string;
  model?: string | null;
  serial?: string | null;
  capacityBytes?: number | null;
  rotationRate: 'hdd' | 'ssd' | 'flash' | 'unknown';
  health?: string;
  poolName?: string | null;
  extra?: Record<string, unknown>;
}

export interface ZfsSshResult {
  filesystems: ZfsFsRow[];
  disks: ZfsDiskRow[];
}

/** The combined read-only command (single exec round-trip). */
const ZFS_SSH_COMMAND = [
  'echo __ZFS_LIST__',
  "zfs list -o name,mountpoint,size,used,avail,compression,origin,created,encrypted 2>/dev/null",
  'echo __ZPOOL_STATUS__',
  'zpool status -v 2>/dev/null',
  'echo __ZPOOL_SCRUB__',
  'zpool get -H -o value scrub,pool 2>/dev/null',
  'echo __ZFS_SNAPSHOTS__',
  "zfs list -t snapshot -o name,used,referenced 2>/dev/null | head -n 400",
].join('\n');

/** Splits the combined output into its sections (marker lines). */
function splitSections(stdout: string): { zfsList: string; poolStatus: string; poolScrub: string; snapshots: string } {
  const out = { zfsList: '', poolStatus: '', poolScrub: '', snapshots: '' };
  let current: keyof typeof out | null = null;
  for (const line of stdout.split('\n')) {
    if (line === '__ZFS_LIST__') { current = 'zfsList'; continue; }
    if (line === '__ZPOOL_STATUS__') { current = 'poolStatus'; continue; }
    if (line === '__ZPOOL_SCRUB__') { current = 'poolScrub'; continue; }
    if (line === '__ZFS_SNAPSHOTS__') { current = 'snapshots'; continue; }
    if (!current) continue;
    out[current] += line + '\n';
  }
  return out;
}

/** ZFS human sizes ("8.00G", "512K", "16T") → bytes (base-10, like zfs itself). */
function parseZfsSize(v: string | undefined): number | null {
  if (!v) return null;
  const m = v.trim().match(/^(\d+(?:\.\d+)?)([BKMGTPE]?)$/i);
  if (!m) return null; // "-" (unlimited), "no", ... → no size
  const num = parseFloat(m[1]);
  if (!Number.isFinite(num)) return null;
  const mult: Record<string, number> = { '': 1, B: 1, K: 1e3, M: 1e6, G: 1e9, T: 1e12, P: 1e15, E: 1e18 };
  return Math.round(num * (mult[(m[2] ?? '').toUpperCase()] ?? 1));
}

/** Splits a `zfs list` line into columns (whitespace-separated; mountpoints with
 * spaces are rare and not worth breaking the simple contract for). */
function zfsListRow(line: string): Record<string, string> | null {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 3 || !parts[0]) return null;
  return {
    name: parts[0],
    mountpoint: parts[1] ?? '',
    size: parts[2] ?? '',
    used: parts[3] ?? '',
    avail: parts[4] ?? '',
    compression: parts[5] ?? '',
    origin: parts[6] ?? '',
    created: parts[7] ?? '',
    encrypted: parts[8] ?? '',
  };
}

/** Parses the `zfs list` section into filesystem rows (pools + datasets + zvols). */
function parseZfsList(section: string): ZfsFsRow[] {
  const rows: ZfsFsRow[] = [];
  for (const line of section.split('\n')) {
    if (!line.trim()) continue;
    const r = zfsListRow(line);
    if (!r) continue;
    // Datasets/zvols carry a slash; the first path element is their pool.
    const isPool = !r.name.includes('/');
    const parent = isPool ? null : r.name.slice(0, r.name.lastIndexOf('/')) || null;
    // `zfs list` without -t only shows filesystems + volumes (no snapshots).
    const type: ZfsFsRow['type'] = isPool ? 'zfs-pool' : 'zfs-dataset';
    const sizeBytes = parseZfsSize(r.size);
    const usedBytes = parseZfsSize(r.used);
    // avail is only meaningful for pools (datasets report "-").
    const freeBytes = isPool ? parseZfsSize(r.avail) : null;
    const extra: Record<string, unknown> = {};
    if (r.compression && r.compression !== 'off' && r.compression !== '-') extra['compression'] = r.compression;
    if (r.origin && r.origin !== '-' && !isPool) extra['origin'] = r.origin;
    if (r.created && r.created !== '-' && isPool) extra['created'] = r.created;
    if (r.encrypted === 'yes') extra['encrypted'] = true;
    rows.push({
      name: r.name,
      type,
      mountpoint: r.mountpoint && r.mountpoint !== 'legacy' ? r.mountpoint : null,
      sizeBytes: sizeBytes ?? null,
      usedBytes: usedBytes ?? null,
      freeBytes: freeBytes ?? (sizeBytes !== null && usedBytes !== null ? Math.max(0, sizeBytes - usedBytes) : null),
      status: 'online', // listed by zfs = mounted/active; pool health comes from zpool status
      parent,
      extra: Object.keys(extra).length > 0 ? extra : undefined,
    });
  }
  return rows;
}

/** Parses `zpool status -v` into per-disk rows (name + state) and a pool→health map. */
function parsePoolStatus(section: string): { disks: ZfsDiskRow[]; poolHealth: Map<string, string> } {
  const disks: ZfsDiskRow[] = [];
  const poolHealth = new Map<string, string>();
  let currentPool: string | null = null;

  for (const rawLine of section.split('\n')) {
    // Pool header: "pool: tank" → "  pool: tank".
    const poolMatch = rawLine.match(/^\s*pool:\s+(\S+)/);
    if (poolMatch) {
      currentPool = poolMatch[1];
      continue;
    }
    // Pool state line: "state: ONLINE|DEGRADED|FAULTED|OFFLINE"
    const stateMatch = rawLine.match(/^\s*state:\s+(\S+)/);
    if (stateMatch && currentPool) {
      poolHealth.set(currentPool, stateMatch[1].toLowerCase());
      continue;
    }
    // Vdev leaf lines: "  disk0" / "  da2  ONLINE" / "  spare" — indented names
    // under the current pool. Lines with a device path or bare name + optional
    // state word are physical members; vdev type headers (mirror, stripe, log,
    // cache, spares) and "errors:" lines are not disks.
    const leafMatch = rawLine.match(/^\s{2,}([A-Za-z0-9._/-]+)\s+(ONLINE|DEGRADED|FAULTED|OFFLINE|REMOVED|MAINTENANCE)?\s*$/);
    if (leafMatch && currentPool) {
      const name = leafMatch[1];
      // Vdev category/type keywords are not physical disks.
      if (['mirror', 'stripe', 'log', 'cache', 'spares', 'special', 'dedup', 'errors:', 'no'].includes(name.toLowerCase())) continue;
      const state = (leafMatch[2] ?? 'ONLINE').toLowerCase();
      // Capacity: "da2  ONLINE" lines carry no size in `zpool status`; the disk
      // capacity comes from zfs list's pool rows instead — keep it null here.
      disks.push({
        name,
        rotationRate: 'unknown',
        health: state === 'online' ? 'healthy' : state === 'degraded' || state === 'maintenance' ? 'degraded' : 'failed',
        poolName: currentPool,
        extra: { zfsState: state },
      });
    }
  }
  return { disks, poolHealth };
}

/** Parses the `zpool get scrub` section (one "value\tpool" line per pool). */
function parseScrub(section: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const line of section.split('\n')) {
    if (!line.trim()) continue;
    // -H output is tab-separated: "<value>\t<pool>"
    const [value, pool] = line.split('\t');
    if (pool && value) map.set(pool.trim(), value.trim());
  }
  return map;
}

/** Parses the snapshot section into per-dataset counts + space. */
function parseSnapshots(section: string): Map<string, { count: number; usedBytes: number }> {
  const map = new Map<string, { count: number; usedBytes: number }>();
  for (const line of section.split('\n')) {
    if (!line.trim()) continue;
    const parts = line.trim().split(/\s+/);
    // Snapshot names are "pool/dataset@name" — the dataset is everything before '@'.
    const at = parts[0]?.lastIndexOf('@');
    if (at === undefined || at <= 0) continue;
    const dsName = parts[0].slice(0, at);
    const used = parseZfsSize(parts[1]) ?? 0;
    const cur = map.get(dsName) ?? { count: 0, usedBytes: 0 };
    cur.count += 1;
    cur.usedBytes += used;
    map.set(dsName, cur);
  }
  return map;
}

/**
 * Collects the ZFS inventory over SSH. Returns null when no usable SSH
 * credential is bound (the caller keeps its previous data) or on any failure —
 * this path must never throw into /monitoring.
 */
export async function collectZfsViaSsh(
  host: string,
  credentials: Record<string, unknown> | undefined,
  log?: (level: 'info' | 'warn', message: string) => void
): Promise<ZfsSshResult | null> {
  // slotOnly: the primary secret is an apiKey (or could be username/password) —
  // never fall back to top-level fields, only a bound `ssh` slot counts.
  const creds = resolveSshCredentials(credentials, { slotOnly: true });
  if (!creds) return null; // no ssh slot bound — API-only mode

  try {
    const client = await sshPool.get(host, 22, creds);
    const r = await client.exec(ZFS_SSH_COMMAND, creds);
    if (r.code !== 0 && !r.stdout.includes('__ZFS_LIST__')) {
      log?.('warn', `SSH ZFS collection on ${host} failed (exit ${r.code}): ${r.stderr.slice(0, 200)}`);
      return null;
    }

    const sections = splitSections(r.stdout);
    if (!sections.zfsList.trim()) {
      log?.('warn', `SSH ZFS collection on ${host}: empty zfs list output`);
      return null;
    }

    const filesystems = parseZfsList(sections.zfsList);
    const { disks, poolHealth } = parsePoolStatus(sections.poolStatus);
    const scrubByPool = parseScrub(sections.poolScrub);
    const snapshots = parseSnapshots(sections.snapshots);

    // Enrich: pool rows get health + last scrub; datasets get snapshot stats.
    for (const row of filesystems) {
      if (row.type === 'zfs-pool') {
        const health = poolHealth.get(row.name);
        if (health && health !== 'online') row.status = health;
        const scrub = scrubByPool.get(row.name);
        if (scrub && scrub !== 'none' && scrub !== '-') {
          row.extra ??= {};
          row.extra['lastScrub'] = scrub;
        }
      } else {
        const snap = snapshots.get(row.name);
        if (snap) {
          row.extra ??= {};
          row.extra['snapshotCount'] = snap.count;
          row.extra['snapshotUsedBytes'] = snap.usedBytes;
        }
      }
    }

    return { filesystems, disks };
  } catch (e) {
    if (e instanceof SshError) {
      log?.('warn', `SSH ZFS collection on ${host} failed: ${e.message}`);
    } else {
      log?.('warn', `SSH ZFS collection on ${host} unexpected error: ${(e as Error).message}`);
    }
    return null; // best-effort — keep previous data, never sink the poll
  }
}
