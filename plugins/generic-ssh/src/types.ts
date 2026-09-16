/**
 * Generic SSH plugin — shared row/snapshot types.
 *
 * Row shapes mirror what the API's ingestInventory() consumes (see
 * api/src/workers/telemetry.ts): networks[], arp[]/ndp[], routes[], ports[],
 * filesystems[], disks[]. Everything is best-effort over POSIX shell commands,
 * so a minimal Linux box (busybox) still yields most of it.
 */

/** One network/interface row → `metrics['networks']` + device_ports. */
export interface NetworkRow {
  name: string;
  ip?: string | null;
  prefix?: number | null;
  version?: 'v4' | 'v6' | null;
  vlanId?: number | null;
  mac?: string | null;
  status?: string | null;
}

/** One ARP/NDP neighbor row → `metrics['arp'|'ndp']` (hosts table). */
export interface HostRow {
  mac: string;
  ip?: string;
  hostname?: string | null;
  manufacturer?: string | null;
  intf?: string | null;
}

/** One route row → `metrics['routes']`. */
export interface RouteRow {
  destination: string;
  gateway?: string;
  protocol?: string;
  distance?: number | null;
  metric?: number | null;
  mtu?: number | null;
  status?: string;
  extra?: Record<string, unknown>;
}

/** One device port row → `metrics['ports']` (device_ports table). */
export interface PortRowLike {
  name: string;
  status?: string | null;
  speed?: string | null;
  duplex?: string | null;
  vlanId?: number | null;
  poe?: string | null;
  extra?: Record<string, unknown>;
}

/** One filesystem row for the Storage page (df -T). */
export interface FilesystemRow {
  name: string;
  type: string;
  sizeBytes: number | null;
  usedBytes: number | null;
  availBytes: number | null;
  mountpoint?: string | null;
}

/** One physical disk row for the Storage page (lsblk). */
export interface DiskRow {
  name: string;
  model?: string | null;
  serial?: string | null;
  capacityBytes?: number | null;
  rotationRate?: string; // hdd | ssd | flash | unknown
  health?: string; // healthy | degraded | failed | unknown
  poolName?: string | null;
}

/** System identity info (hostname, OS release, uptime). */
export interface BoardInfo {
  hostname: string;
  model: string;
  board: string;
  release: string;
  revision?: string | null;
  uptimeSeconds?: number | null;
}

/** The full per-host inventory snapshot (15-min cadence, cached in memory). */
export interface InventorySnapshot {
  collectedAt: string;
  board: BoardInfo | null;
  networks: NetworkRow[];
  arp: HostRow[];
  ndp: HostRow[];
  routes: RouteRow[];
  ports: PortRowLike[];
  filesystems: FilesystemRow[];
  disks: DiskRow[];
}
