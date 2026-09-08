import { useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { ArrowDownToLine, ArrowUpFromLine, Camera, ChevronDown, ChevronRight, ChevronUp, Database, FolderOpen, Gauge, HardDrive, Loader2, Search, Trash2, X } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import { Layout } from '../components/Layout';
import { FileBrowserDialog } from '../components/FileBrowserDialog';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { StatusBadge } from '../components/StatusBadge';
import { formatBytes } from '../components/formatMetric';
import { ReauthDialog } from '../components/ReauthDialog';
import { api, ApiError, StorageDiskRow, StorageFilesystemRow } from '../api/client';

// ---------------------------------------------------------------------------
// Badges + usage cells (unchanged visual language)
// ---------------------------------------------------------------------------

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

/** "—" for empty/unknown values. */
function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

// ---------------------------------------------------------------------------
// Plan helpers (same contract as the Containers / VMs pages)
// ---------------------------------------------------------------------------

/** Creates a plan for ONE plugin and executes it in the background. The first
 * step is the plan's intent; further steps are appended in one bulk round-trip.
 * Throws on failure — callers catch ApiError 401 to offer two-factor revalidation. */
async function createAndExecutePlan(
  pluginId: string,
  actionId: string,
  steps: Array<{ deviceId: string; input: Record<string, unknown> }>,
): Promise<string> {
  const first = steps[0];
  const plan = await api.createPlan({
    pluginId,
    intentActionId: actionId,
    inputs: first.input,
    devices: [{ deviceId: first.deviceId }],
  });
  if (steps.length > 1) {
    await api.addPlanStepsBulk(plan.id, steps.slice(1).map((s) => ({ deviceId: s.deviceId, actionId, input: s.input })));
  }
  await api.executePlan(plan.id);
  return plan.id;
}

/** Groups selected rows by (pluginId, deviceId), collecting a per-row value. */
function groupByDevice<T>(rows: T[], keyOf: (r: T) => { pluginId: string; deviceId: string }, valOf: (r: T) => string): Map<string, { pluginId: string; deviceId: string; values: string[] }> {
  const m = new Map<string, { pluginId: string; deviceId: string; values: string[] }>();
  for (const r of rows) {
    const k = keyOf(r);
    const entry = m.get(`${k.pluginId}|${k.deviceId}`) ?? { pluginId: k.pluginId, deviceId: k.deviceId, values: [] };
    entry.values.push(valOf(r));
    m.set(`${k.pluginId}|${k.deviceId}`, entry);
  }
  return m;
}

// ---------------------------------------------------------------------------
// Snapshot dialog — submits storage.snapshot through the plan workflow (2FA-gated).
// ---------------------------------------------------------------------------

function SnapshotDialog({ row, onClose }: { row: StorageFilesystemRow; onClose: () => void }) {
  const [retentionDays, setRetentionDays] = useState(7);
  const [recursive, setRecursive] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reauth, setReauth] = useState(false);

  async function submit() {
    setSaving(true);
    setError(null);
    const input: Record<string, unknown> = { name: row.name, retentionDays, recursive };
    const attempt = async () => {
      await createAndExecutePlan(row.pluginId, 'storage.snapshot', [{ deviceId: row.deviceId, input }]);
      onClose();
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth(true);
      else setError(err instanceof Error ? err.message : String(err));
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      <div className="mt-8 w-full max-w-md rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">Snapshot — {row.name}</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">Creates a timestamped ZFS snapshot on {row.deviceName ?? row.deviceId}.</p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X size={16} />
          </button>
        </header>

        <div className="space-y-4 px-4 py-4">
          {error && !reauth && (
            <div className="rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
          )}
          <div>
            <label className="mb-1 block text-xs font-medium text-secondary">Retention (days)</label>
            <input
              type="number"
              min={1}
              max={3650}
              value={retentionDays}
              onChange={(e) => setRetentionDays(Math.max(1, Number(e.target.value) || 1))}
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
            />
            <p className="mt-1 text-[11px] text-faint">Older UNM-created snapshots of this dataset older than N days are pruned.</p>
          </div>
          <label className="flex items-center gap-2 text-xs text-secondary">
            <input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} />
            Include child datasets (recursive)
          </label>
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={saving}
            onClick={() => void submit()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving && <Loader2 size={12} className="animate-spin" />}
            Create snapshot
          </button>
        </footer>

        {reauth && (
          <ReauthDialog
            contextLabel={`Snapshot ${row.name}`}
            onClose={() => setReauth(false)}
            onSuccess={async () => {
              setReauth(false);
              try { await submit(); } catch { /* dialog stays open */ }
            }}
          />
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Quota dialog — submits storage.quota-set through the plan workflow (2FA-gated).
// ---------------------------------------------------------------------------

function QuotaDialog({ row, onClose }: { row: StorageFilesystemRow; onClose: () => void }) {
  const extra = row.extra ?? {};
  const currentQuota = typeof extra['quota'] === 'number' ? formatBytes(extra['quota'] as number) : (typeof extra['quotaParsed'] === 'string' ? (extra['quotaParsed'] as string) : null);
  const [value, setValue] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reauth, setReauth] = useState(false);

  async function submit() {
    setSaving(true);
    setError(null);
    const input: Record<string, unknown> = { name: row.name, quota: value.trim() }; // empty string clears the quota
    const attempt = async () => {
      await createAndExecutePlan(row.pluginId, 'storage.quota-set', [{ deviceId: row.deviceId, input }]);
      onClose();
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth(true);
      else setError(err instanceof Error ? err.message : String(err));
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      <div className="mt-8 w-full max-w-md rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">Set quota — {row.name}</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Current: {currentQuota ?? 'none'} · applies on {row.deviceName ?? row.deviceId}.
            </p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X size={16} />
          </button>
        </header>

        <div className="space-y-4 px-4 py-4">
          {error && !reauth && (
            <div className="rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
          )}
          <div>
            <label className="mb-1 block text-xs font-medium text-secondary">New quota</label>
            <input
              type="text"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder='Bytes (e.g. 5368709120) or a size like "10 GB". Leave empty to clear.'
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint"
            />
          </div>
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={saving}
            onClick={() => void submit()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving && <Loader2 size={12} className="animate-spin" />}
            Apply quota
          </button>
        </footer>

        {reauth && (
          <ReauthDialog
            contextLabel={`Set quota on ${row.name}`}
            onClose={() => setReauth(false)}
            onSuccess={async () => {
              setReauth(false);
              try { await submit(); } catch { /* dialog stays open */ }
            }}
          />
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page component
// ---------------------------------------------------------------------------

export default function Storage() {
  // The API polls plugins every ~30s and upserts the storage inventory — refresh
  // at the same cadence so pools/datasets/disks track live state.
  const storageQuery = useQuery({
    queryKey: ['storage'],
    queryFn: () => api.storage(),
    refetchInterval: 30_000,
  });
  const queryClient = useQueryClient();

  // --- Action catalogs (drive per-row action availability GENERICALLY) -------
  // A button only renders when the row's plugin advertises that action id — so
  // any future storage plugin implementing the same ids gets this column + bulk
  // bar for free.
  const catalogPluginIds = useMemo(
    () => Array.from(new Set((storageQuery.data?.filesystems ?? []).map((r) => r.pluginId))),
    [storageQuery.data],
  );
  const catalogsQuery = useQuery({
    queryKey: ['plugin-actions-catalogs', 'storage', catalogPluginIds.join('|')],
    queryFn: async () => {
      const entries = await Promise.all(
        catalogPluginIds.map(async (pid) => [pid, (await api.pluginActions(pid)).actions] as const),
      );
      return Object.fromEntries(entries);
    },
    enabled: catalogPluginIds.length > 0,
  });

  function hasAction(pluginId: string, actionId: string): boolean {
    const actions = catalogsQuery.data?.[pluginId];
    return Array.isArray(actions) && actions.some((a) => a.id === actionId);
  }

  // --- Filesystem browser (capability 'filesystem') ---------------------------
  // The Browse button only renders when the row's plugin advertises the
  // 'filesystem' capability — GENERIC: any future storage plugin serving POST
  // /filesystem gets the file browser for free. Capabilities come from the
  // plugins catalog (react-query caches it).
  const [pluginsForCaps, setPluginsForCaps] = useState<Record<string, string[]>>({});
  useEffect(() => {
    let cancelled = false;
    api.plugins().then((ps) => {
      if (cancelled) return;
      const m: Record<string, string[]> = {};
      for (const p of ps) m[p.id] = p.capabilities ?? [];
      setPluginsForCaps(m);
    }).catch(() => { /* capabilities unavailable — Browse stays hidden */ });
    return () => { cancelled = true; };
  }, []);
  const hasFilesystemCap = (pluginId: string): boolean => (pluginsForCaps[pluginId] ?? []).includes('filesystem');

  /** The dataset row whose contents the file browser is showing (null = closed). */
  const [browseTarget, setBrowseTarget] = useState<StorageFilesystemRow | null>(null);

  // --- Plan tracking → auto-refresh -------------------------------------------
  // Plans created by this page are tracked ONLY for data freshness: when one
  // settles the touched devices are force-refreshed once so capacity/status
  // update immediately. Execution status lives in the top-bar plans icon.
  const [reauth, setReauth] = useState<{ label: string; retry: () => void | Promise<void> } | null>(null);
  /** Dismissible status banner (info / error only). */
  const [notice, setNotice] = useState<{ kind: 'ok' | 'info' | 'error'; text: string } | null>(null);

  /** Plan id → the devices its steps touch. */
  const [pendingPlans, setPendingPlans] = useState<Record<string, { deviceIds: string[] }>>({});
  const pendingRef = useRef(pendingPlans);
  useEffect(() => { pendingRef.current = pendingPlans; }, [pendingPlans]);

  function trackPlan(planId: string, deviceIds: string[]) {
    setPendingPlans((prev) => ({ ...prev, [planId]: { deviceIds } }));
  }

  useEffect(() => {
    if (Object.keys(pendingPlans).length === 0) return;
    const timer = setInterval(async () => {
      for (const [planId, entry] of Object.entries(pendingRef.current)) {
        let p;
        try {
          p = await api.getPlan(planId);
        } catch { continue; } // transient API error — keep waiting
        if (!['succeeded', 'failed', 'cancelled'].includes(p.status)) continue;
        setPendingPlans((prev) => {
          const next = { ...prev };
          delete next[planId];
          return next;
        });
        try { await api.refreshDevices(entry.deviceIds); } catch { /* fall back to the 30s poll */ }
        void queryClient.invalidateQueries({ queryKey: ['storage'] });
        if (p.status !== 'succeeded') {
          setNotice({ kind: 'error', text: `A storage plan finished with errors — check the Plans page.` });
        }
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [pendingPlans, queryClient]);

  // --- Row-type predicates (drive action eligibility) ----------------------------
  // NOTE: some plugins mislabel datasets as `zfs-pool` even when the name contains
  // a slash (e.g. TrueNAS reporting `zroot/var/log`). A REAL ZFS pool name never
  // contains `/`, so we treat "pool" as type=zfs-pool AND no-slash, and anything
  // else that is ZFS (or has a slash) as dataset-like. This keeps scrub offered
  // only on genuine pools while still enabling quota/mount/snapshot on datasets.
  const isRealPool = (r: StorageFilesystemRow): boolean => r.type === 'zfs-pool' && !r.name.includes('/');
  const isDatasetLike = (r: StorageFilesystemRow): boolean =>
    r.type === 'zfs-dataset' || r.type === 'zfs-zvol' || (r.type.startsWith('zfs') && r.name.includes('/'));
  const isMounted = (r: StorageFilesystemRow): boolean => !!r.mountpoint;

  // --- Data -----------------------------------------------------------------------
  const overview = storageQuery.data;
  const allFilesystems: StorageFilesystemRow[] = overview?.filesystems ?? [];
  const disks: StorageDiskRow[] = overview?.disks ?? [];

  // Summary strip: aggregate capacity across top-level filesystems (real pools +
  // non-ZFS rows — datasets/zvols are sub-volumes of their pool, counting them
  // too would double the numbers).
  const topLevel = allFilesystems.filter((f) => !isDatasetLike(f));
  const totalSize = topLevel.reduce((sum, f) => sum + (f.sizeBytes ?? 0), 0);
  const totalUsed = topLevel.reduce((sum, f) => sum + (f.usedBytes ?? 0), 0);
  const poolCount = allFilesystems.filter(isRealPool).length;
  const datasetCount = allFilesystems.filter(isDatasetLike).length;

  // --- Hierarchical tree: pools → datasets → sub-datasets / zvols -----------------
  // ZFS datasets + zvols are nested under their IMMEDIATE parent (the plugin sets
  // `parent` to the direct parent name) instead of appearing as flat rows. A row
  // whose parent is not present in this poll's data stays top-level so nothing
  // disappears. Names are per-device, so attachment is scoped by deviceId+pluginId.
  const fsKey = (f: StorageFilesystemRow): string => `${f.deviceId}|${f.pluginId}|${f.name}`;
  const byName = new Map<string, StorageFilesystemRow[]>();
  for (const f of allFilesystems) {
    let arr = byName.get(f.name);
    if (!arr) { arr = []; byName.set(f.name, arr); }
    arr.push(f);
  }
  const hasParent = (f: StorageFilesystemRow): boolean => {
    if (!isDatasetLike(f) || !f.parent) return false;
    const parents = byName.get(f.parent);
    return !!parents?.some((p) => p.deviceId === f.deviceId && p.pluginId === f.pluginId);
  };
  // childrenOf for the DataTable: direct children of one row, sorted by name.
  const childrenByParentKey = new Map<string, StorageFilesystemRow[]>();
  for (const f of allFilesystems) {
    if (!hasParent(f)) continue;
    const parents = byName.get(f.parent!)!;
    const parent = parents.find((p) => p.deviceId === f.deviceId && p.pluginId === f.pluginId);
    if (!parent) continue;
    const pk = fsKey(parent);
    let arr = childrenByParentKey.get(pk);
    if (!arr) { arr = []; childrenByParentKey.set(pk, arr); }
    arr.push(f);
  }
  for (const arr of childrenByParentKey.values()) arr.sort((a, b) => a.name.localeCompare(b.name));
  // Top-level rows: everything that is NOT attached under an existing parent.
  const filesystems: StorageFilesystemRow[] = allFilesystems.filter((f) => !hasParent(f));

  // --- Single-filesystem row action -------------------------------------------
  async function singleFs(row: StorageFilesystemRow, actionId: string, input: Record<string, unknown>, label: string) {
    const attempt = async () => {
      const planId = await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input }]);
      trackPlan(planId, [row.deviceId]);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label, retry: attempt });
      else setNotice({ kind: 'error', text: `${label} failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  // --- Bulk filesystem action (selection bar) ---------------------------------
  function fsBulk(actionId: string, label: string, eligible: (r: StorageFilesystemRow) => boolean, noEligibleMsg: string) {
    return async (rows: StorageFilesystemRow[]) => {
      // Skip rows whose plugin does NOT advertise this action id — a selection can
      // span several plugins (e.g. TrueNAS + OPNsense), and only the ones that
      // implement the contract are actually actionable. This keeps bulk ops safe
      // across mixed-plugin selections instead of erroring on plan creation.
      const sel = rows.filter((r) => hasAction(r.pluginId, actionId) && eligible(r));
      if (sel.length === 0) {
        setNotice({ kind: 'info', text: noEligibleMsg });
        return;
      }
      const attempt = async () => {
        for (const g of Array.from(groupByDevice(sel, (r) => ({ pluginId: r.pluginId, deviceId: r.deviceId }), (r) => r.name).values())) {
          // Deleting a pool is recursive — it owns child datasets.
          const input: Record<string, unknown> = { names: g.values };
          if (actionId === 'storage.delete') input.recursive = true;
          const planId = await createAndExecutePlan(g.pluginId, actionId, [{ deviceId: g.deviceId, input }]);
          trackPlan(planId, [g.deviceId]);
        }
      };
      try {
        await attempt();
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) setReauth({ label, retry: attempt });
        else setNotice({ kind: 'error', text: `${label} failed: ${err instanceof Error ? err.message : String(err)}` });
      }
    };
  }

  // --- Dialog targets -----------------------------------------------------------
  const [snapshotTarget, setSnapshotTarget] = useState<StorageFilesystemRow | null>(null);
  const [quotaTarget, setQuotaTarget] = useState<StorageFilesystemRow | null>(null);

  // --- Per-row action buttons (shared by top-level rows AND nested children) -----
  // Availability is GENERIC — a button only renders when the row's plugin advertises
  // that action id in its catalog, so any future storage plugin gets this column free.
  function renderActions(row: StorageFilesystemRow): ReactNode {
    const pool = isRealPool(row);
    const dsLike = isDatasetLike(row);
    const mounted = isMounted(row);

    const actions: { id: string; label: string; icon: ReactNode; available: boolean; eligible: boolean; danger?: boolean }[] = [
      { id: 'storage.scrub', label: `Scrub pool ${row.name}`, icon: <Search size={14} />, available: hasAction(row.pluginId, 'storage.scrub'), eligible: pool },
      { id: 'storage.snapshot', label: `Snapshot ${row.name}`, icon: <Camera size={14} />, available: hasAction(row.pluginId, 'storage.snapshot'), eligible: pool || dsLike },
      { id: 'storage.quota-set', label: `Set quota on ${row.name}`, icon: <Gauge size={14} />, available: hasAction(row.pluginId, 'storage.quota-set'), eligible: dsLike },
      { id: 'storage.mount', label: `Mount ${row.name}`, icon: <ArrowDownToLine size={14} />, available: hasAction(row.pluginId, 'storage.mount'), eligible: dsLike && !mounted },
      { id: 'storage.unmount', label: `Unmount ${row.name}`, icon: <ArrowUpFromLine size={14} />, available: hasAction(row.pluginId, 'storage.unmount'), eligible: dsLike && mounted },
      { id: 'storage.delete', label: `Delete ${row.name}`, icon: <Trash2 size={13} />, available: hasAction(row.pluginId, 'storage.delete'), eligible: true, danger: true },
    ];

    // Browse the contents over SFTP — only when the plugin advertises the
    // 'filesystem' capability AND this row is a ZFS filesystem with a directory tree
    // (a pool or dataset; zvols are block devices). The mountpoint is resolved by the
    // PLUGIN at browse time (pool.dataset.query covers pools too), so we don't gate on
    // the row's own mountpoint field — pool rows carry null there.
    const browsable = hasFilesystemCap(row.pluginId) && (pool || dsLike);

    return (
      <div className="flex items-center gap-0.5">
        {actions.map((a) => {
          if (!a.available) return null;
          const enabled = a.eligible;
          return (
            <button
              key={a.id}
              type="button"
              aria-label={a.label}
              title={enabled ? a.label : 'Not applicable to this filesystem'}
              disabled={!enabled}
              onClick={() => {
                if (a.id === 'storage.snapshot') setSnapshotTarget(row);
                else if (a.id === 'storage.quota-set') setQuotaTarget(row);
                else if (a.id === 'storage.delete') {
                  const recursive = pool || dsLike; // pools + datasets own children — zvols don't
                  const msg = `Permanently delete "${row.name}"? This is destructive and removes all data in it.` + (recursive ? ' Child datasets will be removed too.' : '');
                  if (!window.confirm(msg)) return;
                  void singleFs(row, a.id, { names: [row.name], recursive }, `Delete ${row.name}`);
                } else {
                  void singleFs(row, a.id, { names: [row.name] }, a.label.split(' ')[0]);
                }
              }}
              className={clsx(
                'rounded-md p-1.5 hover:bg-muted',
                a.danger ? 'text-danger-fg hover:text-danger-fg' : 'text-secondary hover:text-foreground',
                !enabled && 'cursor-not-allowed opacity-30',
              )}
            >
              {a.icon}
            </button>
          );
        })}
        {browsable && (
          <button
            type="button"
            aria-label={`Browse contents of ${row.name}`}
            title={`Browse the files in ${row.name}${row.mountpoint ? ` (${row.mountpoint})` : ''}`}
            onClick={() => setBrowseTarget(row)}
            className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
          >
            <FolderOpen size={14} />
          </button>
        )}
      </div>
    );
  }

  // --- Filesystem columns -----------------------------------------------------------
  const fsColumns: DataTableColumn<StorageFilesystemRow>[] = [
    {
      header: 'Name',
      key: 'name',
      width: 280,
      render: (row) => <span className="font-medium text-foreground">{row.name}</span>,
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
      width: 240,
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
    {
      header: 'Actions',
      key: 'actions',
      width: 230,
      sortable: false,
      excludeFromExport: true,
      render: (row) => renderActions(row),
    },
  ];

  // Cell content for one column of an expanded child row — mirrors the top-level
  // column renders so children line up with the header. The name cell shows only
  // the BASENAME (the nesting conveys the parent chain; full path in tooltip) and
  // indents by depth. Actions render identically to top-level rows, so nested
  // datasets get the same per-row controls as pools.
  function childCell(key: string, child: StorageFilesystemRow, depth: number): ReactNode {
    switch (key) {
      case 'name': {
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
      case 'actions':
        // Nested datasets carry the SAME per-row actions as top-level rows.
        return renderActions(child);
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
      <tr className="bg-sky-50/40 dark:bg-muted/70">
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
        {/* Empty selection cell — the table is selectable, so parent rows carry a
         * checkbox column between chevron and data. Children are NOT selectable,
         * but without this cell every child's content shifts one column left. */}
        {ctx.selectable && <td className="px-3 py-2" />}
        {ctx.columns.map((col) => (
          <td key={col.key} className="overflow-hidden px-4 py-2 text-secondary">
            {childCell(col.key, child, ctx.depth)}
          </td>
        ))}
      </tr>
    );
  }

  // --- Disk columns (read-only — physical media has no generic actions) -----------
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
      width: 240,
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

  // --- Horizontal splitter: filesystem table (top) vs disk table (bottom) --------
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

  return (
    <Layout title="Storage">
      {/* Full-height column: filesystem / disk tables split by a horizontal
          splitter — collapsing the disks gives its space back to the table. */}
      <div className="flex h-full min-h-0 flex-col">
        {storageQuery.isLoading && <p className="shrink-0 text-sm text-muted-foreground">Loading storage inventory...</p>}
        {storageQuery.isError && (
          <p className="shrink-0 text-sm text-danger-fg">Failed to load storage data: {(storageQuery.error as Error).message}</p>
        )}

        {/* Info / error banner */}
        {notice && (
          <div
            className={clsx(
              'mb-3 flex shrink-0 items-center gap-2 rounded-lg border px-4 py-2 text-xs',
              notice.kind === 'ok' && 'border-success-border bg-success text-success-fg',
              notice.kind === 'info' && 'border-info-border bg-info text-info-fg',
              notice.kind === 'error' && 'border-danger-border bg-danger text-danger-fg',
            )}
          >
            <span className="flex-1">{notice.text}</span>
            <button type="button" aria-label="Dismiss notice" onClick={() => setNotice(null)} className="rounded p-0.5 opacity-70 hover:opacity-100">
              <X size={14} />
            </button>
          </div>
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
              {allFilesystems.length - poolCount - datasetCount} other filesystem{allFilesystems.length - poolCount - datasetCount === 1 ? '' : 's'}
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
            {storageQuery.data && (
              <DataTable<StorageFilesystemRow>
                columns={fsColumns}
                rows={filesystems}
                rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}`}
                storageKey="storage-filesystems"
                autoRefresh={{ intervalMs: 30_000, queries: [storageQuery] }}
                fillHeight
                searchPlaceholder="Search filesystems…"
                selectable
                bulkActions={[
                  { label: 'Scrub', onClick: fsBulk('storage.scrub', 'Scrub selected pools', isRealPool, 'No selected rows are ZFS pools — nothing to scrub.') },
                  { label: 'Mount', onClick: fsBulk('storage.mount', 'Mount selected datasets', (r) => isDatasetLike(r) && !isMounted(r), 'No selected datasets are unmounted — nothing to mount.') },
                  { label: 'Unmount', onClick: fsBulk('storage.unmount', 'Unmount selected datasets', (r) => isDatasetLike(r) && isMounted(r), 'No selected datasets are mounted — nothing to unmount.') },
                  {
                    label: 'Delete',
                    confirm: (c) => `Permanently delete ${c} filesystem(s)? This is destructive and removes all data in them.`,
                    onClick: fsBulk('storage.delete', 'Delete selected', () => true, ''),
                  },
                ]}
                emptyMessage="No filesystems reported yet — devices with a storage plugin (TrueNAS pools/datasets, RouterOS/SwOS root filesystem) populate this view within a poll cycle."
                expandable={{
                  // Hierarchical nesting: pools → datasets → sub-datasets/zvols.
                  childrenOf: (row) => childrenByParentKey.get(`${row.deviceId}|${row.pluginId}|${row.name}`) ?? [],
                  renderChild: (child, _parent, ctx) => <DatasetChildRow child={child} ctx={ctx} />,
                }}
              />
            )}
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

        {/* Snapshot / quota dialogs */}
        {snapshotTarget && <SnapshotDialog row={snapshotTarget} onClose={() => setSnapshotTarget(null)} />}
        {quotaTarget && <QuotaDialog row={quotaTarget} onClose={() => setQuotaTarget(null)} />}

        {/* Filesystem browser — browse a dataset's contents over SFTP (capability 'filesystem'). */}
        {browseTarget && (
          <FileBrowserDialog
            deviceId={browseTarget.deviceId}
            pluginId={browseTarget.pluginId}
            context={{ kind: 'dataset', name: browseTarget.name }}
            title={`Browse ${browseTarget.name}`}
            subtitle={`${browseTarget.deviceName ?? browseTarget.managementAddress ?? ''}${browseTarget.mountpoint ? ` · ${browseTarget.mountpoint}` : ''}`}
            onClose={() => setBrowseTarget(null)}
          />
        )}

        {/* 2FA revalidation (plan create/execute returned 401) */}
        {reauth && (
          <ReauthDialog
            contextLabel={reauth.label}
            onClose={() => setReauth(null)}
            onSuccess={async () => {
              setReauth(null);
              await reauth.retry();
            }}
          />
        )}
      </div>
    </Layout>
  );
}
