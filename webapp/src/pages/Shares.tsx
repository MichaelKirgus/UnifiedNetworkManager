import { useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { CheckCircle2, ChevronDown, ChevronUp, EyeOff, FolderTree, HardDrive, Loader2, Pencil, Plus, Trash2, Users, X } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { StatusBadge } from '../components/StatusBadge';
import { formatDuration } from '../components/formatMetric';
import { ReauthDialog } from '../components/ReauthDialog';
import { READONLY_MESSAGE, runAction, useExecutionMode, type ExecutionMode } from '../executionMode';
import { api, ApiError, ShareRow, ShareSessionRow } from '../api/client';

// ---------------------------------------------------------------------------
// Badges + helpers (same visual language as the Storage page)
// ---------------------------------------------------------------------------

/** Share protocol → badge style. */
const TYPE_STYLES: Record<string, string> = {
  smb: 'bg-accent-indigo text-accent-indigo-fg',
  nfs: 'bg-accent-teal text-accent-teal-fg',
  iscsi: 'bg-accent-purple text-accent-purple-fg',
  nvmeof: 'bg-accent-sky text-accent-sky-fg',
};

const TYPE_LABELS: Record<string, string> = {
  smb: 'SMB/CIFS',
  nfs: 'NFS',
  iscsi: 'iSCSI',
  nvmeof: 'NVMe-oF',
};

function TypeBadge({ type }: { type: string }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium ${TYPE_STYLES[type] ?? 'bg-muted text-secondary'}`}>
      {TYPE_LABELS[type] ?? type}
    </span>
  );
}

/** "—" for empty/unknown values (the API stores '' / null for unknown fields). */
function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

// ---------------------------------------------------------------------------
// Plan helpers (same contract as the Storage page)
// ---------------------------------------------------------------------------

/** Creates a plan for ONE plugin. In Execute mode it is also executed in the
 * background; in Plan mode it is saved WITHOUT executing and only its id is
 * returned — callers surface a "saved" notice instead of tracking execution.
 * Throws on failure — callers catch ApiError 401 to offer two-factor revalidation. */
async function createAndExecutePlan(
  pluginId: string,
  actionId: string,
  steps: Array<{ deviceId: string; input: Record<string, unknown> }>,
  mode: ExecutionMode,
): Promise<string> {
  const first = steps[0];
  const create = async () => {
    const plan = await api.createPlan({
      pluginId,
      intentActionId: actionId,
      inputs: first.input,
      devices: [{ deviceId: first.deviceId }],
    });
    if (steps.length > 1) {
      await api.addPlanStepsBulk(plan.id, steps.slice(1).map((s) => ({ deviceId: s.deviceId, actionId, input: s.input })));
    }
    return plan;
  };
  return runAction(create, (id) => api.executePlan(id), mode);
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
// Share CRUD → action-id mapping (GENERIC contract)
// ---------------------------------------------------------------------------

/** The per-protocol action ids the TrueNAS plugin advertises. A button only renders
 * when the row's plugin actually lists that id in its catalog, so any future storage
 * plugin implementing the same ids gets this page for free. */
const ACTION_IDS: Record<string, { create?: string; update?: string; delete: string }> = {
  smb: { create: 'shares.smb.create', update: 'shares.smb.update', delete: 'shares.smb.delete' },
  nfs: { create: 'shares.nfs.create', update: 'shares.nfs.update', delete: 'shares.nfs.delete' },
  iscsi: { create: 'shares.iscsi.create', delete: 'shares.iscsi.delete' },
  nvmeof: { create: 'shares.nvmeof.create', delete: 'shares.nvmeof.delete' },
};

/** The identifying key of a share row for its protocol (SMB/iSCSI/NVMe-oF = name, NFS = path). */
function shareKey(row: ShareRow): string {
  return row.type === 'nfs' ? (row.path ?? row.name) : row.name;
}

/** Builds the action input for a create/update of one share from the form state. */
function buildShareInput(type: string, mode: 'create' | 'edit', f: ShareForm): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (type === 'nfs') {
    out['path'] = f.path.trim();
    out['hosts'] = splitHosts(f.hostsText);
    // Update always carries readOnly so it can be toggled off; create only when set.
    if (mode === 'edit' || f.readOnly) out['readOnly'] = mode === 'edit' ? f.readOnly : true;
  } else {
    out['name'] = f.name.trim();
    if (f.path.trim()) out['path'] = f.path.trim(); // iSCSI/NVMe-oF LUN/namespace dataset (optional)
    if (type === 'smb') {
      if (mode === 'edit' || f.comment.trim() !== '') out['comment'] = mode === 'edit' ? f.comment : f.comment.trim();
    }
  }
  return out;
}

/** Splits a comma-separated host list into trimmed, non-empty entries. */
function splitHosts(text: string): string[] {
  return text.split(',').map((h) => h.trim()).filter((h) => h.length > 0);
}

// ---------------------------------------------------------------------------
// Share form state + create/edit dialog (2FA-gated via the plan workflow).
// ---------------------------------------------------------------------------

interface ShareForm {
  type: string;
  name: string;
  path: string;
  comment: string;
  hostsText: string;
  readOnly: boolean;
}

function initialForm(type: string, row?: ShareRow): ShareForm {
  const extra = row?.extra ?? {};
  return {
    type,
    name: row && row.type !== 'nfs' ? row.name : '',
    path: row ? (row.path ?? (row.type === 'nfs' ? row.name : '')) : '',
    comment: typeof extra['comment'] === 'string' ? (extra['comment'] as string) : '',
    hostsText: Array.isArray(extra['hosts']) ? (extra['hosts'] as unknown[]).filter((h): h is string => typeof h === 'string').join(', ') : '',
    readOnly: extra['readOnly'] === true,
  };
}

function ShareDialog({ mode, type, row, onClose }: { mode: 'create' | 'edit'; type?: string; row?: ShareRow; onClose: () => void }) {
  // Global Execute/Plan mode (aliased — `mode` above is the dialog's create/edit mode).
  const { mode: execMode } = useExecutionMode();
  const isPlanMode = execMode === 'plan';
  // Read-Only: the share plan cannot be saved or executed.
  const isReadOnly = execMode === 'readonly';
  const [form, setForm] = useState<ShareForm>(() => initialForm(type ?? 'smb', row));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reauth, setReauth] = useState(false);
  // Plan mode: the share plan was saved without executing.
  const [saved, setSaved] = useState(false);

  // In create mode the protocol is chosen in-dialog; in edit mode it is fixed.
  const setType = (t: string) => setForm((f) => ({ ...f, type: t }));
  const isNfs = form.type === 'nfs';

  async function submit() {
    // Validate the required field for the chosen protocol before touching the API.
    if (!isNfs && form.name.trim() === '') { setError('A share name is required.'); return; }
    if (form.path.trim() === '') { setError(isNfs ? 'An exported path is required.' : 'A dataset/path to export is required.'); return; }
    setSaving(true);
    setError(null);

    const pluginId = row?.pluginId ?? '';
    const deviceId = row?.deviceId ?? '';
    const actionId = mode === 'edit' ? ACTION_IDS[form.type]?.update : ACTION_IDS[form.type]?.create;
    if (!actionId) { setSaving(false); setError(`No ${mode} action available for ${TYPE_LABELS[form.type] ?? form.type}.`); return; }

    if (isReadOnly) return; // Read-Only — the button is disabled; this is a safety net.

    const input = buildShareInput(form.type, mode, form);
    const attempt = async () => {
      await createAndExecutePlan(pluginId, actionId, [{ deviceId, input }], execMode);
      if (isPlanMode) {
        setSaved(true);
        return;
      }
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

  const title = mode === 'edit' ? `Edit ${TYPE_LABELS[form.type] ?? form.type} share` : 'New share';

  // Plan mode: the plan was saved without executing — offer to close.
  if (saved) {
    return (
      <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
        <div
          className="mt-8 w-full max-w-md rounded-md border border-border bg-card shadow-xl"
          onClick={(e) => e.stopPropagation()}
        >
          <header className="flex items-center justify-between border-b border-border px-4 py-3">
            <h2 className="text-base font-semibold text-foreground">{title}</h2>
            <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
              <X size={16} />
            </button>
          </header>
          <div className="space-y-3 px-4 py-4">
            <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-xs text-success-fg">
              <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
              Share change saved as a plan — it was NOT executed. Open the Plans center to run it later (or schedule it).
            </div>
          </div>
          <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
            <button type="button" onClick={onClose} className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90">
              Close
            </button>
          </footer>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      <div className="mt-8 w-full max-w-md rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">{title}</h2>
            {row && (
              <p className="mt-0.5 text-xs text-muted-foreground">Applies on {row.deviceName ?? row.deviceId}.</p>
            )}
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X size={16} />
          </button>
        </header>

        <div className="space-y-4 px-4 py-4">
          {isReadOnly && (
            <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
              <EyeOff size={14} className="mt-0.5 shrink-0" />
              Read-only mode is active — this change cannot be saved or executed. Switch to Plan or Execute in the top bar.
            </div>
          )}
          {error && !reauth && (
            <div className="rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
          )}

          {/* Protocol — only selectable when creating. */}
          {mode === 'create' && (
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Protocol</label>
              <select
                value={form.type}
                onChange={(e) => setType(e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
              >
                <option value="smb">SMB / CIFS</option>
                <option value="nfs">NFS</option>
                <option value="iscsi">iSCSI target</option>
                <option value="nvmeof">NVMe-oF subsystem</option>
              </select>
            </div>
          )}

          {/* Name (SMB / iSCSI / NVMe-oF) — NFS is identified by its path. */}
          {!isNfs && (
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">
                {form.type === 'smb' ? 'Share name' : form.type === 'iscsi' ? 'Target name' : 'Subsystem NQN'}
              </label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder={form.type === 'smb' ? 'public' : form.type === 'iscsi' ? 'iqn.2024-01.org.unm:tank' : 'nqn.2024-01.org.unm:tank'}
                className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint"
              />
            </div>
          )}

          {/* Path / exported dataset. */}
          <div>
            <label className="mb-1 block text-xs font-medium text-secondary">
              {isNfs ? 'Exported path' : form.type === 'smb' ? 'Dataset to export' : 'Backing dataset (LUN/namespace)'}
            </label>
            <input
              type="text"
              value={form.path}
              onChange={(e) => setForm((f) => ({ ...f, path: e.target.value }))}
              placeholder="/mnt/tank/public"
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint"
            />
            {!isNfs && form.type !== 'smb' && (
              <p className="mt-1 text-[11px] text-faint">Optional — leave empty to create the target/subsystem without a LUN.</p>
            )}
          </div>

          {/* SMB comment. */}
          {form.type === 'smb' && (
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Comment</label>
              <input
                type="text"
                value={form.comment}
                onChange={(e) => setForm((f) => ({ ...f, comment: e.target.value }))}
                placeholder="Optional description"
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-faint"
              />
            </div>
          )}

          {/* NFS host access + read-only. */}
          {isNfs && (
            <>
              <div>
                <label className="mb-1 block text-xs font-medium text-secondary">Allowed hosts</label>
                <input
                  type="text"
                  value={form.hostsText}
                  onChange={(e) => setForm((f) => ({ ...f, hostsText: e.target.value }))}
                  placeholder="Leave empty for all hosts, or list IPs/CIDRs (comma-separated)"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint"
                />
              </div>
              <label className="flex items-center gap-2 text-xs text-secondary">
                <input type="checkbox" checked={form.readOnly} onChange={(e) => setForm((f) => ({ ...f, readOnly: e.target.checked }))} />
                Export read-only
              </label>
            </>
          )}
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={saving || (mode === 'edit' && !row) || isReadOnly}
            title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : undefined}
            onClick={() => void submit()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving && <Loader2 size={12} className="animate-spin" />}
            {isPlanMode ? 'Save as plan' : mode === 'edit' ? 'Save changes' : 'Create share'}
          </button>
        </footer>

        {reauth && (
          <ReauthDialog
            contextLabel={`${title}`}
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

export default function Shares() {
  // Global Execute/Plan mode — decides whether page actions run immediately or
  // are saved as (unexecuted) plans for later execution/scheduling.
  const { mode } = useExecutionMode();

  // The API polls plugins every ~30s and upserts the share inventory + replaces
  // live sessions — refresh at the same cadence so both track live state.
  const sharesQuery = useQuery({
    queryKey: ['shares'],
    queryFn: () => api.shares(),
    refetchInterval: 30_000,
  });
  const queryClient = useQueryClient();

  // --- Action catalogs (drive per-row action availability GENERICALLY) -------
  const catalogPluginIds = useMemo(
    () => Array.from(new Set((sharesQuery.data?.shares ?? []).map((r) => r.pluginId))),
    [sharesQuery.data],
  );
  const catalogsQuery = useQuery({
    queryKey: ['plugin-actions-catalogs', 'shares', catalogPluginIds.join('|')],
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

  // --- Plan tracking → auto-refresh -------------------------------------------
  const [reauth, setReauth] = useState<{ label: string; retry: () => void | Promise<void> } | null>(null);
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
        void queryClient.invalidateQueries({ queryKey: ['shares'] });
        if (p.status !== 'succeeded') {
          setNotice({ kind: 'error', text: `A share plan finished with errors — check the Plans page.` });
        }
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [pendingPlans, queryClient]);

  // --- Single-share delete (per-row trash button) -----------------------------
  async function singleDelete(row: ShareRow) {
    const actionId = ACTION_IDS[row.type]?.delete;
    if (!actionId || !hasAction(row.pluginId, actionId)) return;
    const key = shareKey(row);
    const msg = `Permanently delete the ${TYPE_LABELS[row.type] ?? row.type} share "${key}"? This removes only the export — the underlying dataset and its data are untouched.`;
    if (!window.confirm(msg)) return;
    // NFS deletes by path, the others by name.
    const input: Record<string, unknown> = row.type === 'nfs' ? { paths: [key] } : { names: [key] };
    const attempt = async () => {
      if (mode === 'readonly') { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input }], mode);
      if (mode === 'plan') {
        setNotice({ kind: 'ok', text: `Delete ${key}: saved as a plan — not executed. Open the Plans center to run it later.` });
        return;
      }
      trackPlan(planId, [row.deviceId]);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `Delete ${key}`, retry: attempt });
      else setNotice({ kind: 'error', text: `Delete failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  // --- Bulk delete (selection bar) --------------------------------------------
  async function bulkDelete(rows: ShareRow[]) {
    {
      const sel = rows.filter((r) => hasAction(r.pluginId, ACTION_IDS[r.type]?.delete ?? ''));
      if (sel.length === 0) { setNotice({ kind: 'info', text: 'No selected shares are deletable on their plugin.' }); return; }
      const attempt = async () => {
        if (mode === 'readonly') { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
        let savedCount = 0;
        for (const g of Array.from(groupByDevice(sel, (r) => ({ pluginId: r.pluginId, deviceId: r.deviceId }), (r) => shareKey(r)).values())) {
          // All rows in one group share a device+plugin but may span protocols —
          // delete each protocol's keys with its own action id.
          const byType = new Map<string, string[]>();
          for (const r of sel.filter((x) => x.pluginId === g.pluginId && x.deviceId === g.deviceId)) {
            const list = byType.get(r.type) ?? [];
            list.push(shareKey(r));
            byType.set(r.type, list);
          }
          for (const [type, keys] of byType) {
            const actionId = ACTION_IDS[type]?.delete;
            if (!actionId) continue;
            const input: Record<string, unknown> = type === 'nfs' ? { paths: keys } : { names: keys };
            const planId = await createAndExecutePlan(g.pluginId, actionId, [{ deviceId: g.deviceId, input }], mode);
            if (mode === 'plan') {
              savedCount += 1;
              continue;
            }
            trackPlan(planId, [g.deviceId]);
          }
        }
        if (mode === 'plan' && savedCount > 0) {
          setNotice({ kind: 'ok', text: `Delete selected shares: ${savedCount} plan${savedCount === 1 ? '' : 's'} saved without executing — open the Plans center to run them later.` });
        }
      };
      try {
        await attempt();
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) setReauth({ label: 'Delete selected shares', retry: attempt });
        else setNotice({ kind: 'error', text: `Delete failed: ${err instanceof Error ? err.message : String(err)}` });
      }
    }
  }

  // --- Dialog targets -----------------------------------------------------------
  const [dialog, setDialog] = useState<{ mode: 'create' | 'edit'; type?: string; row?: ShareRow } | null>(null);

  // --- Data -----------------------------------------------------------------------
  const overview = sharesQuery.data;
  const allShares: ShareRow[] = overview?.shares ?? [];
  const sessions: ShareSessionRow[] = overview?.sessions ?? [];

  // Summary strip: counts per protocol + total live sessions.
  const countByType = (t: string) => allShares.filter((s) => s.type === t).length;
  const activeSessions = sessions.length;

  // --- Per-row action buttons -----------------------------------------------------
  function renderActions(row: ShareRow): ReactNode {
    // Read-Only mode disables every share write action.
    if (mode === 'readonly') return null;
    const ids = ACTION_IDS[row.type] ?? {};
    const canEdit = !!ids.update && hasAction(row.pluginId, ids.update);
    const canDelete = !!ids.delete && hasAction(row.pluginId, ids.delete);

    return (
      <div className="flex items-center gap-0.5">
        {canEdit && (
          <button
            type="button"
            aria-label={`Edit ${row.name}`}
            title={`Edit this ${TYPE_LABELS[row.type] ?? row.type} share`}
            onClick={() => setDialog({ mode: 'edit', type: row.type, row })}
            className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
          >
            <Pencil size={14} />
          </button>
        )}
        {canDelete && (
          <button
            type="button"
            aria-label={`Delete ${row.name}`}
            title={`Delete this ${TYPE_LABELS[row.type] ?? row.type} share`}
            onClick={() => void singleDelete(row)}
            className="rounded-md p-1.5 text-danger-fg hover:bg-muted hover:text-danger-fg"
          >
            <Trash2 size={13} />
          </button>
        )}
      </div>
    );
  }

  // --- Share columns --------------------------------------------------------------
  const shareColumns: DataTableColumn<ShareRow>[] = [
    {
      header: 'Name',
      key: 'name',
      width: 260,
      render: (row) => <span className="font-medium text-foreground">{row.name}</span>,
    },
    {
      header: 'Protocol',
      key: 'type',
      width: 110,
      render: (row) => <TypeBadge type={row.type} />,
    },
    {
      header: 'Path / Dataset',
      key: 'path',
      width: 240,
      exportValue: (row) => row.path ?? '',
      render: (row) => <span className="font-mono text-xs">{orDash(row.path)}</span>,
    },
    {
      header: 'Status',
      key: 'status',
      width: 110,
      render: (row) => <StatusBadge status={row.status} />,
    },
    {
      header: 'Sessions',
      key: 'sessionCount',
      width: 90,
      sortAccessor: (row) => row.sessionCount ?? -1,
      exportValue: (row) => String(row.sessionCount ?? ''),
      render: (row) => (
        <span className="font-mono text-xs">
          {typeof row.sessionCount === 'number' ? row.sessionCount : '—'}
        </span>
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
    {
      header: 'Actions',
      key: 'actions',
      width: 100,
      sortable: false,
      excludeFromExport: true,
      render: (row) => renderActions(row),
    },
  ];

  // --- Session columns (bottom panel — live client connections) -------------------
  const sessionColumns: DataTableColumn<ShareSessionRow>[] = [
    {
      header: 'Protocol',
      key: 'type',
      width: 100,
      render: (row) => <TypeBadge type={row.type} />,
    },
    {
      header: 'Share',
      key: 'shareName',
      width: 220,
      exportValue: (row) => row.shareName,
      render: (row) => <span className="font-medium text-foreground">{orDash(row.shareName)}</span>,
    },
    {
      header: 'Client address',
      key: 'clientAddress',
      width: 200,
      exportValue: (row) => row.clientAddress,
      render: (row) => <span className="font-mono text-xs">{orDash(row.clientAddress)}</span>,
    },
    {
      header: 'User',
      key: 'user',
      width: 160,
      exportValue: (row) => row.user ?? '',
      render: (row) => <span className="font-mono text-xs">{orDash(row.user)}</span>,
    },
    {
      header: 'Uptime',
      key: 'uptimeSeconds',
      width: 120,
      sortAccessor: (row) => row.uptimeSeconds ?? -1,
      exportValue: (row) => (typeof row.uptimeSeconds === 'number' ? formatDuration(row.uptimeSeconds) : ''),
      render: (row) => <span className="font-mono text-xs">{typeof row.uptimeSeconds === 'number' ? formatDuration(row.uptimeSeconds) : '—'}</span>,
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

  // --- Horizontal splitter: shares table (top) vs sessions panel (bottom) --------
  const [sessionsOpen, setSessionsOpen] = useState(true);
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
    <Layout title="Shares">
      {/* Full-height column: shares table / sessions panel split by a horizontal
          splitter — collapsing the sessions gives its space back to the table. */}
      <div className="flex h-full min-h-0 flex-col">
        {sharesQuery.isLoading && <p className="shrink-0 text-sm text-muted-foreground">Loading share inventory...</p>}
        {sharesQuery.isError && (
          <p className="shrink-0 text-sm text-danger-fg">Failed to load shares: {(sharesQuery.error as Error).message}</p>
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

        {/* Summary strip — per-protocol counts + live session total. */}
        {!sharesQuery.isLoading && !sharesQuery.isError && (
          <div className="mb-3 flex shrink-0 flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-border bg-card px-4 py-2 text-xs">
            <span className="flex items-center gap-2 text-secondary">
              <FolderTree size={13} className="text-accent-solid" />
              {allShares.length} share{allShares.length === 1 ? '' : 's'}
              {' · '}
              {countByType('smb')} SMB · {countByType('nfs')} NFS · {countByType('iscsi')} iSCSI · {countByType('nvmeof')} NVMe-oF
            </span>
            <span className="flex items-center gap-2 text-secondary">
              <Users size={13} className="text-accent-teal-fg" />
              {activeSessions} active client session{activeSessions === 1 ? '' : 's'}
            </span>
          </div>
        )}

        {/* Toolbar — New share (create dialog with protocol picker). Hidden in Read-Only mode. */}
        {!sharesQuery.isLoading && !sharesQuery.isError && mode !== 'readonly' && (
          <div className="mb-2 flex shrink-0 items-center justify-between">
            <button
              type="button"
              onClick={() => setDialog({ mode: 'create', type: 'smb' })}
              className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90"
            >
              <Plus size={14} /> New share
            </button>
          </div>
        )}

        <div ref={vSplitRef} className="flex min-h-0 flex-1 flex-col">
          {/* Shares table (top) — fixed share of the page height while the
              sessions panel is open; when collapsed it takes everything left. */}
          <div
            className={clsx('min-h-0 pr-1', !sessionsOpen && 'flex-1')}
            style={{ height: sessionsOpen ? `${tablePct}%` : undefined }}
          >
            {sharesQuery.data && (
              <DataTable<ShareRow>
                columns={shareColumns}
                rows={allShares}
                rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}|${row.type}`}
                storageKey="shares"
                autoRefresh={{ intervalMs: 30_000, queries: [sharesQuery] }}
                fillHeight
                searchPlaceholder="Search shares…"
                selectable
                bulkActions={[
                  {
                    label: 'Delete',
                    confirm: (c) => `Permanently delete ${c} share(s)? This removes only the exports — underlying datasets and data are untouched.`,
                    onClick: bulkDelete,
                  },
                ]}
                emptyMessage="No shares reported yet — devices with a file-sharing plugin (TrueNAS SMB/NFS/iSCSI/NVMe-oF) populate this view within an inventory poll."
              />
            )}
          </div>

          {/* Horizontal splitter between the two panels. */}
          {sessionsOpen && (
            <div
              role="separator"
              aria-orientation="horizontal"
              onMouseDown={startVDrag}
              className="group relative -my-1 h-3 shrink-0 cursor-row-resize"
              title="Drag to resize — or collapse the sessions panel for full shares height"
            >
              <div className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-muted transition-colors group-hover:bg-accent-hover" />
              <div className="absolute left-1/2 top-1/2 flex h-3 w-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center">
                <span className="h-1 w-6 rounded-full bg-status-neutral transition-colors group-hover:bg-accent-hover" />
              </div>
            </div>
          )}

          {/* Sessions panel (bottom) — live CIFS/SMB + NFS client connections. */}
          <div className={clsx('shrink-0 min-h-0 pl-1', sessionsOpen && 'flex-1')}>
            <div className="flex h-full min-h-0 flex-col rounded-lg border border-border bg-card">
              <button
                type="button"
                onClick={() => setSessionsOpen((o) => !o)}
                className="flex w-full shrink-0 items-center justify-between px-4 py-3 text-left"
                aria-expanded={sessionsOpen}
              >
                <span className="flex items-center gap-2 text-sm font-semibold text-secondary">
                  <Users size={16} className="text-muted-foreground" />
                  Active client sessions
                  {activeSessions > 0 && (
                    <span className="rounded-full bg-accent-teal px-1.5 py-0.5 text-xs font-medium text-accent-teal-fg">{activeSessions}</span>
                  )}
                </span>
                {sessionsOpen ? <ChevronDown size={18} className="text-faint" /> : <ChevronUp size={18} className="text-faint" />}
              </button>
              {sessionsOpen && (
                <div className="min-h-0 flex-1 border-t border-border p-3">
                  <DataTable<ShareSessionRow>
                    columns={sessionColumns}
                    rows={sessions}
                    rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.type}|${row.shareName}|${row.clientAddress}`}
                    storageKey="share-sessions"
                    autoRefresh={{ intervalMs: 30_000, queries: [sharesQuery] }}
                    fillHeight
                    searchPlaceholder="Search sessions…"
                    emptyMessage="No active client sessions right now — CIFS/SMB and NFS connections appear here within a poll cycle (requires an SSH slot bound to the device)."
                  />
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Create / edit share dialog */}
        {dialog && <ShareDialog mode={dialog.mode} type={dialog.type} row={dialog.row} onClose={() => setDialog(null)} />}

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
