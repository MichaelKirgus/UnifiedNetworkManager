import { useEffect, useRef, useState, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { ChevronDown, ChevronRight, ChevronUp, HardDrive, Database } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { StatusBadge } from '../components/StatusBadge';
import { formatBytes } from '../components/formatMetric';
import { api, StorageDiskRow, StorageFilesystemRow } from '../api/client';

/** Filesystem type → badge style + label. */
const FS_TYPE_STYLES: Record<string, string> = {
  'zfs-pool': 'bg-indigo-100 text-indigo-700',
  'zfs-dataset': 'bg-sky-100 text-sky-700',
  'zfs-zvol': 'bg-teal-100 text-teal-700',
  ext4: 'bg-success text-success-fg',
  squashfs: 'bg-violet-100 text-violet-700',
  usb: 'bg-warning text-warning-fg',
};

function FsTypeBadge({ type }: { type: string }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium ${FS_TYPE_STYLES[type] ?? 'bg-muted text-secondary'}`}>
      {type}
    </span>
  );
}

/** Rotation-rate badge for physical disks. */
const ROTATION_STYLES: Record<string, string> = {
  hdd: 'bg-muted text-secondary',
  ssd: 'bg-info text-info-fg',
  flash: 'bg-purple-100 text-purple-700',
};

function RotationBadge({ rate }: { rate: string }) {
  if (rate === 'unknown') return <span className="text-faint">—</span>;
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${ROTATION_STYLES[rate] ?? 'bg-muted text-secondary'}`}>
      {rate}
    </span>
  );
}

/** Usage bar (green → amber → red) for size/used columns. */
function usagePct(row: { sizeBytes?: number | null; usedBytes?: number | null }): number | null {
  const size = row.sizeBytes ?? null;
  const used = row.usedBytes ?? null;
  if (size === null || used === null || size <= 0) return null;
  return Math.min(100, (used / size) * 100);
}

function usageColor(pct: number | null): string {
  if (pct === null) return 'text-faint';
  if (pct < 70) return 'text-success-fg';
  if (pct < 90) return 'text-warning-fg';
  return 'text-danger-fg';
}

function usageBarColor(pct: number | null): string {
  if (pct === null) return '#cbd5e1'; // slate-300 — no data
  if (pct < 70) return '#10b981'; // emerald-500
  if (pct < 90) return '#f59e0b'; // amber-500
  return '#ef4444'; // red-500
}

function UsageCell({ row }: { row: StorageFilesystemRow }) {
  const pct = usagePct(row);
  // No capacity ceiling (unlimited dataset, no quota/reservation): show the
  // used space alone so per-dataset consumption is still visible.
  if (row.sizeBytes === null || row.sizeBytes === undefined) {
    return row.usedBytes !== null && row.usedBytes !== undefined ? (
      <span className="font-mono text-xs" title="No quota/reservation — unlimited capacity">
        {formatBytes(row.usedBytes)} used
      </span>
    ) : (
      <span className="text-faint">—</span>
    );
  }
  return (
    <div className="flex flex-col gap-1" title={pct !== null ? `${Math.round(pct)}% used` : 'No usage data'}>
      <div className="flex items-baseline justify-between gap-2 font-mono text-xs">
        <span>{formatBytes(row.sizeBytes)}</span>
        <span className={usageColor(pct)}>
          {row.usedBytes !== null && row.usedBytes !== undefined ? formatBytes(row.usedBytes) : '—'} used
        </span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded bg-muted">
        <div className="h-full" style={{ width: `${pct ?? 0}%`, background: usageBarColor(pct) }} />
      </div>
    </div>
  );
}

/** Cell content for one column of an expanded child row — mirrors the
 * top-level column renders so children line up with the header. */
function childCell(key: string, child: StorageFilesystemRow, depth: number): ReactNode {
  switch (key) {
    case 'name': {
      // Show only the BASENAME — the nesting already conveys the parent chain;
      // the full dataset path stays available in the tooltip. Every level is
      // indented (base 18px + one step per depth) so even direct children of a
      // pool are clearly nested, not top-level rows.
      const basename = child.name.split('/').pop() ?? child.name;
      return (
        <span
          className="block truncate font-medium text-secondary"
          style={{ paddingLeft: 18 + depth * 14 }}
          title={child.name}
        >
          {basename}
        </span>
      );
    }
    case 'type':
      return <FsTypeBadge type={child.type} />;
    case 'mountpoint':
      return <span className="font-mono text-xs">{orDash(child.mountpoint)}</span>;
    case 'sizeBytes':
      // Same usage cell as pools — per-dataset size / used / free is visible.
      return <UsageCell row={child} />;
    case 'freeBytes':
      return (
        <span className="font-mono text-xs">
          {child.freeBytes !== null && child.freeBytes !== undefined ? formatBytes(child.freeBytes) : '—'}
        </span>
      );
    case 'status':
      return <StatusBadge status={child.status} />;
    case 'deviceName':
      return (
        <DeviceChip
          deviceName={child.deviceName}
          managementAddress={child.managementAddress}
          pluginName={child.pluginName}
          siteName={child.siteName}
          interfaces={[]}
        />
      );
    default: {
      const v = (child as unknown as Record<string, unknown>)[key];
      return typeof v === 'string' || typeof v === 'number' ? String(v) : '';
    }
  }
}

/** One expanded child rendered as a FULL `<tr>` — a chevron cell plus one cell
 * per visible column (ctx.columns), so it stays aligned with the header.
 * Datasets are hierarchical: a child that itself has children gets its own
 * chevron, and deeper levels indent in the name cell. */
function DatasetChildRow({ child, ctx }: { child: StorageFilesystemRow; ctx: ExpandChildContext }) {
  return (
    <tr className="bg-sky-50/40">
      <td className="px-1 py-2 align-middle">
        {ctx.hasChildren ? (
          <button
            type="button"
            onClick={ctx.onToggle}
            aria-expanded={ctx.expanded}
            title={ctx.expanded ? 'Collapse sub-datasets / zvols' : 'Expand sub-datasets / zvols'}
            className="flex h-6 w-6 items-center justify-center rounded text-faint hover:bg-muted hover:text-secondary"
          >
            {ctx.expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
          </button>
        ) : (
          <span className="inline-block h-6 w-6" />
        )}
      </td>
      {ctx.columns.map((col) => (
        <td key={col.key} className="overflow-hidden px-4 py-2 text-secondary">
          {childCell(col.key, child, ctx.depth)}
        </td>
      ))}
    </tr>
  );
}

/** "—" for empty/unknown values. */
function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

export default function Storage() {
  // The API polls plugins every 30s and upserts the storage inventory — refresh
  // at the same cadence so pools/datasets/disks track live state.
  const storageQuery = useQuery({
    queryKey: ['storage'],
    queryFn: () => api.storage(),
    refetchInterval: 30_000,
  });

  // Horizontal splitter: filesystem table (top) vs disk table (bottom). The
  // table gets a fixed share of the page height; collapsing the disks below
  // gives its space back to the table.
  const [disksOpen, setDisksOpen] = useState(true);
  const [tablePct, setTablePct] = useState(58);
  const vSplitRef = useRef<HTMLDivElement>(null);
  const vDragCleanup = useRef<(() => void) | null>(null);

  useEffect(() => () => { vDragCleanup.current?.(); }, []);

  const startVDrag = (e: ReactMouseEvent) => {
    e.preventDefault();
    const el = vSplitRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const move = (ev: globalThis.MouseEvent) => {
      const pct = ((ev.clientY - rect.top) / rect.height) * 100;
      setTablePct(Math.min(85, Math.max(20, pct)));
    };
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      vDragCleanup.current = null;
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
    vDragCleanup.current = up;
  };

  const overview = storageQuery.data;
  const allFilesystems: StorageFilesystemRow[] = overview?.filesystems ?? [];
  const disks: StorageDiskRow[] = overview?.disks ?? [];

  // ZFS datasets + zvols are nested HIERARCHICALLY under their parent (pool →
  // dataset → sub-dataset / zvol) instead of as flat rows. A row whose parent
  // is not present in the data (e.g. an intermediate dataset missing on this
  // poll, or a pool that failed to parse) stays top-level so nothing disappears.
  const fsKey = (f: StorageFilesystemRow): string => `${f.deviceId}|${f.pluginId}|${f.name}`;
  const byName = new Map<string, StorageFilesystemRow[]>();
  for (const f of allFilesystems) {
    let arr = byName.get(f.name);
    if (!arr) { arr = []; byName.set(f.name, arr); }
    arr.push(f);
  }
  const isZfsChild = (f: StorageFilesystemRow): boolean => f.type === 'zfs-dataset' || f.type === 'zfs-zvol';
  // A child attaches to its parent only when the parent row exists in THIS
  // device's data — names are per-device, so scope the lookup by deviceId.
  const hasParent = (f: StorageFilesystemRow): boolean => {
    if (!f.parent) return false;
    const parents = byName.get(f.parent);
    return !!parents?.some((p) => p.deviceId === f.deviceId && p.pluginId === f.pluginId);
  };
  // childrenOf for the DataTable: direct children of one row, sorted by name.
  const childrenByParentKey = new Map<string, StorageFilesystemRow[]>();
  for (const f of allFilesystems) {
    if (!isZfsChild(f) || !hasParent(f)) continue;
    // Find the matching parent row's key to attach under it.
    const parents = byName.get(f.parent!)!;
    const parent = parents.find((p) => p.deviceId === f.deviceId && p.pluginId === f.pluginId);
    if (!parent) continue;
    const pk = fsKey(parent);
    let arr = childrenByParentKey.get(pk);
    if (!arr) { arr = []; childrenByParentKey.set(pk, arr); }
    arr.push(f);
  }
  for (const arr of childrenByParentKey.values()) arr.sort((a, b) => a.name.localeCompare(b.name));
  const filesystems: StorageFilesystemRow[] = allFilesystems.filter(
    (f) => !isZfsChild(f) || !hasParent(f)
  );

  // Summary strip: aggregate capacity across top-level filesystems (pools +
  // non-ZFS rows — datasets/zvols are sub-volumes of their pool, counting them
  // too would double the numbers).
  const topLevel = filesystems.filter((f) => !isZfsChild(f));
  const totalSize = topLevel.reduce((sum, f) => sum + (f.sizeBytes ?? 0), 0);
  const totalUsed = topLevel.reduce((sum, f) => sum + (f.usedBytes ?? 0), 0);
  const poolCount = filesystems.filter((f) => f.type === 'zfs-pool').length;
  const datasetCount = allFilesystems.filter(isZfsChild).length;

  const fsColumns: DataTableColumn<StorageFilesystemRow>[] = [
    {
      header: 'Name',
      key: 'name',
      width: 260,
      render: (row) => (
        <div className="flex flex-col gap-0.5">
          <span className="font-medium text-foreground">{row.name}</span>
          {row.parent && (
            // Only visible for orphaned datasets whose parent row is missing —
            // nested children get their context from the tree instead.
            <span className="text-[10px] text-faint">in pool {row.parent}</span>
          )}
        </div>
      ),
    },
    {
      header: 'Type',
      key: 'type',
      width: 120,
      render: (row) => <FsTypeBadge type={row.type} />,
    },
    {
      header: 'Mountpoint',
      key: 'mountpoint',
      width: 200,
      render: (row) => <span className="font-mono text-xs">{orDash(row.mountpoint)}</span>,
    },
    {
      header: 'Size / Used',
      key: 'sizeBytes',
      width: 240,
      sortAccessor: (row) => row.sizeBytes ?? -1,
      exportValue: (row) => `${formatBytes(row.sizeBytes ?? 0)} total, ${formatBytes(row.usedBytes ?? 0)} used`,
      render: (row) => <UsageCell row={row} />,
    },
    {
      header: 'Free',
      key: 'freeBytes',
      width: 110,
      sortAccessor: (row) => row.freeBytes ?? -1,
      exportValue: (row) => formatBytes(row.freeBytes ?? 0),
      render: (row) => (
        <span className="font-mono text-xs">
          {row.freeBytes !== null && row.freeBytes !== undefined ? formatBytes(row.freeBytes) : '—'}
        </span>
      ),
    },
    {
      header: 'Status',
      key: 'status',
      width: 120,
      render: (row) => <StatusBadge status={row.status} />,
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 260,
      exportValue: (row) => `${row.deviceName ?? '?'} (${row.managementAddress ?? '?'})`,
      render: (row) => (
        <DeviceChip
          deviceName={row.deviceName}
          managementAddress={row.managementAddress}
          pluginName={row.pluginName}
          siteName={row.siteName}
          interfaces={[]}
        />
      ),
    },
  ];

  const diskColumns: DataTableColumn<StorageDiskRow>[] = [
    {
      header: 'Disk',
      key: 'name',
      width: 160,
      render: (row) => <span className="font-medium text-foreground">{row.name}</span>,
    },
    {
      header: 'Model',
      key: 'model',
      width: 240,
      render: (row) => <span className="text-xs text-secondary">{orDash(row.model)}</span>,
    },
    {
      header: 'Serial',
      key: 'serial',
      width: 180,
      render: (row) => <span className="font-mono text-xs">{orDash(row.serial)}</span>,
    },
    {
      header: 'Capacity',
      key: 'capacityBytes',
      width: 120,
      sortAccessor: (row) => row.capacityBytes ?? -1,
      exportValue: (row) => formatBytes(row.capacityBytes ?? 0),
      render: (row) => (
        <span className="font-mono text-xs">
          {row.capacityBytes !== null && row.capacityBytes !== undefined ? formatBytes(row.capacityBytes) : '—'}
        </span>
      ),
    },
    {
      header: 'Media',
      key: 'rotationRate',
      width: 100,
      render: (row) => <RotationBadge rate={row.rotationRate} />,
    },
    {
      header: 'Health',
      key: 'health',
      width: 120,
      render: (row) => <StatusBadge status={row.health} />,
    },
    {
      header: 'Pool',
      key: 'poolName',
      width: 140,
      render: (row) => (
        row.poolName ? (
          <span className="rounded bg-indigo-50 px-1.5 py-0.5 text-xs font-medium text-indigo-700">{row.poolName}</span>
        ) : (
          <span className="text-faint">—</span>
        )
      ),
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 260,
      exportValue: (row) => `${row.deviceName ?? '?'} (${row.managementAddress ?? '?'})`,
      render: (row) => (
        <DeviceChip
          deviceName={row.deviceName}
          managementAddress={row.managementAddress}
          pluginName={row.pluginName}
          siteName={row.siteName}
          interfaces={[]}
        />
      ),
    },
  ];

  return (
    <Layout title="Storage">
      {/* Full-height column: filesystem / disk tables split by a horizontal
          splitter — collapsing the disks gives its space back to the table
          instead of leaving it empty below. */}
      <div className="flex h-full min-h-0 flex-col">
        {storageQuery.isLoading && <p className="shrink-0 text-sm text-muted-foreground">Loading storage inventory...</p>}
        {storageQuery.isError && (
          <p className="shrink-0 text-sm text-danger-fg">Failed to load storage data: {(storageQuery.error as Error).message}</p>
        )}

        {/* Summary strip — aggregate capacity + counts. */}
        {!storageQuery.isLoading && !storageQuery.isError && (
          <div className="mb-3 flex shrink-0 flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-border bg-card px-4 py-2 text-xs">
            {totalSize > 0 ? (
              <span className="flex items-center gap-2 font-mono">
                <Database size={13} className="text-indigo-500" />
                <span>{formatBytes(totalUsed)} used of {formatBytes(totalSize)}</span>
                <span className={usageColor(usagePct({ sizeBytes: totalSize, usedBytes: totalUsed }))}>
                  ({Math.round((totalUsed / totalSize) * 100)}%)
                </span>
              </span>
            ) : (
              <span className="text-faint">No capacity data reported yet</span>
            )}
            <span className="flex items-center gap-2 text-secondary">
              <Database size={13} className="text-indigo-500" />
              {poolCount} pool{poolCount === 1 ? '' : 's'} · {datasetCount} dataset{datasetCount === 1 ? '' : 's'} ·{' '}
              {filesystems.length - poolCount - datasetCount} other filesystem{filesystems.length - poolCount - datasetCount === 1 ? '' : 's'}
            </span>
            <span className="flex items-center gap-2 text-secondary">
              <HardDrive size={13} className="text-muted-foreground" />
              {disks.length} disk{disks.length === 1 ? '' : 's'} / media device{disks.length === 1 ? '' : 's'}
            </span>
          </div>
        )}

        <div ref={vSplitRef} className="flex min-h-0 flex-1 flex-col">
          {/* Filesystem table (top) — fixed share of the page height while the
              disk table is open; when collapsed it takes everything left. */}
          <div
            className={clsx('min-h-0 pr-1', !disksOpen && 'flex-1')}
            style={{ height: disksOpen ? `${tablePct}%` : undefined }}
          >
            <DataTable<StorageFilesystemRow>
              columns={fsColumns}
              rows={filesystems}
              rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}`}
              storageKey="storage-filesystems"
              autoRefresh={{ intervalMs: 30_000, queries: [storageQuery] }}
              fillHeight
              searchPlaceholder="Search filesystems…"
              emptyMessage="No filesystems reported yet — devices with a storage plugin (TrueNAS pools/datasets, RouterOS/SwOS root filesystem) populate this view within a poll cycle."
              expandable={{
                // Hierarchical nesting: pools → datasets → sub-datasets/zvols.
                childrenOf: (row) => childrenByParentKey.get(`${row.deviceId}|${row.pluginId}|${row.name}`) ?? [],
                renderChild: (child, _parent, ctx) => <DatasetChildRow child={child} ctx={ctx} />,
              }}
            />
          </div>

          {/* Horizontal splitter between the two tables. */}
          {disksOpen && (
            <div
              role="separator"
              aria-orientation="horizontal"
              onMouseDown={startVDrag}
              className="group relative -my-1 h-3 shrink-0 cursor-row-resize"
              title="Drag to resize — or collapse the disk table for full filesystem height"
            >
              <div className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-muted transition-colors group-hover:bg-indigo-400" />
              <div className="absolute left-1/2 top-1/2 flex h-3 w-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center">
                <span className="h-1 w-6 rounded-full bg-slate-300 transition-colors group-hover:bg-indigo-400" />
              </div>
            </div>
          )}

          {/* Disk table (bottom) — takes the remaining height. The header stays
              mounted when collapsed so it can be re-opened. */}
          <div className={clsx('shrink-0 min-h-0 pl-1', disksOpen && 'flex-1')}>
            <div className="flex h-full min-h-0 flex-col rounded-lg border border-border bg-card">
              <button
                type="button"
                onClick={() => setDisksOpen((o) => !o)}
                className="flex w-full shrink-0 items-center justify-between px-4 py-3 text-left"
                aria-expanded={disksOpen}
              >
                <span className="flex items-center gap-2 text-sm font-semibold text-secondary">
                  <HardDrive size={16} className="text-muted-foreground" />
                  Physical disks &amp; media
                </span>
                {/* Expanded panel → chevron points DOWN (click collapses it);
                    collapsed → UP (click expands). */}
                {disksOpen ? <ChevronDown size={18} className="text-faint" /> : <ChevronUp size={18} className="text-faint" />}
              </button>
              {disksOpen && (
                <div className="min-h-0 flex-1 border-t border-border p-3">
                  <DataTable<StorageDiskRow>
                    columns={diskColumns}
                    rows={disks}
                    rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}`}
                    storageKey="storage-disks"
                    autoRefresh={{ intervalMs: 30_000, queries: [storageQuery] }}
                    fillHeight
                    searchPlaceholder="Search disks…"
                    emptyMessage="No physical disk data reported yet — TrueNAS appliances report their drives (model, serial, capacity, pool membership) within a poll cycle."
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
