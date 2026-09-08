import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { Loader2, Monitor, Pause, Play, Plug, RotateCw, Square, Trash2, Unplug, X, Zap } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { formatBytes, formatDuration } from '../components/formatMetric';
import { ReauthDialog } from '../components/ReauthDialog';
import { api, ApiError, VmDevice, VmNic, VmRow } from '../api/client';

// ---------------------------------------------------------------------------
// State badge (case-tolerant — live probe states are lowercase libvirt strings)
// ---------------------------------------------------------------------------

const STATE_STYLES: Record<string, string> = {
  RUNNING: 'bg-success text-success-fg border-success-border',
  STOPPED: 'bg-muted text-secondary border-border',
  SUSPENDED: 'bg-warning text-warning-fg border-warning-border',
  PAUSED: 'bg-sky-100 text-sky-800 border-sky-300',
  ERROR: 'bg-danger text-danger-fg border-danger-border',
};

function StateBadge({ state }: { state: string }) {
  const style = STATE_STYLES[state] ?? STATE_STYLES[state.toUpperCase()] ?? 'bg-warning text-warning-fg border-warning-border';
  return (
    <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium', style)}>
      {state.toLowerCase()}
    </span>
  );
}

/** Normalizes a raw libvirt/virsh state string to the canonical uppercase form. */
function normalizeVmState(s: string): string {
  const u = s.toUpperCase();
  if (u === 'SHUT OFF' || u === 'INACTIVE') return 'STOPPED';
  if (u === 'RUNNING' || u === 'ACTIVE') return 'RUNNING';
  return u;
}

// ---------------------------------------------------------------------------
// Uptime cell
// ---------------------------------------------------------------------------

function UptimeCell({ row }: { row: VmRow }) {
  if (row.state !== 'RUNNING' || !row.startedAt) return <span className="text-faint">—</span>;
  const since = new Date(row.startedAt).getTime();
  if (Number.isNaN(since)) return <span className="text-faint">—</span>;
  const secs = Math.max(0, (Date.now() - since) / 1000);
  return (
    <span className="font-mono text-xs text-secondary" title={`Running since ${new Date(row.startedAt).toLocaleString()}`}>
      {formatDuration(secs)}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Extra / devices helpers
// ---------------------------------------------------------------------------

function extraOf(row: VmRow): Record<string, unknown> {
  const e = row.extra;
  return e && typeof e === 'object' ? (e as Record<string, unknown>) : {};
}

function devicesOf(row: VmRow): VmDevice[] {
  const e = extraOf(row);
  const d = e['devices'];
  if (Array.isArray(d)) return d.filter((x): x is VmDevice => !!x && typeof x === 'object' && typeof (x as VmDevice).dtype === 'string');
  const n = e['nics'];
  if (!Array.isArray(n)) return [];
  return n
    .filter((x): x is VmNic => !!x && typeof x === 'object')
    .map((nic) => ({ dtype: 'NIC', label: nic.mac || undefined, detail: [nic.type, nic.nicAttach ? `→ ${nic.nicAttach}` : null].filter(Boolean).join(' ') || undefined }));
}

// ---------------------------------------------------------------------------
// Display tree (VM → devices)
// ---------------------------------------------------------------------------

interface VmNode {
  key: string;
  kind: 'vm' | 'device';
  /** Source VM row — set on BOTH vm and device nodes (parent context for actions). */
  row?: VmRow;
  dtype?: string;
  label?: string;
  detail?: string;
}

function buildVm(row: VmRow): { vm: VmNode; devices: VmNode[] } {
  const base = `${row.deviceId}|${row.pluginId}|${row.name}`;
  const devices = devicesOf(row).map((d, i) => ({
    key: `${base}#dev${i}`,
    kind: 'device' as const,
    row, // parent VM — needed for NIC detach actions on child rows
    dtype: d.dtype,
    label: typeof d.label === 'string' && d.label !== '' ? d.label : undefined,
    detail: typeof d.detail === 'string' && d.detail !== '' ? d.detail : undefined,
  }));
  return { vm: { key: base, kind: 'vm', row }, devices };
}

function DevicesCell({ row }: { row: VmRow }) {
  const devices = devicesOf(row);
  if (devices.length === 0) return <span className="text-faint">—</span>;
  const counts = new Map<string, number>();
  for (const d of devices) counts.set(d.dtype.toUpperCase(), (counts.get(d.dtype.toUpperCase()) ?? 0) + 1);
  return (
    <div className="flex flex-wrap items-center gap-1" title={`${devices.length} device(s) — expand for detail`}>
      {[...counts.entries()].map(([t, n]) => (
        <span key={t} className="rounded border border-border bg-background px-1.5 py-0.5 text-[11px] leading-4 text-secondary">
          {n > 1 ? `${n}× ` : ''}{t}
        </span>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Child-row actions context (NIC detach)
// ---------------------------------------------------------------------------

interface DeviceActionContext {
  hasAction: (pluginId: string, actionId: string) => boolean;
  detachNic: (node: VmNode) => void;
}

function nodeCell(key: string, node: VmNode, depth: number, actions?: DeviceActionContext): ReactNode {
  switch (key) {
    case 'name':
      return (
        <span className="block truncate font-mono text-xs text-secondary" style={{ paddingLeft: 18 + depth * 14 }} title={node.label ?? node.dtype}>
          {node.label ?? '—'}
        </span>
      );
    case 'devices': {
      if (!node.detail) return <span className="text-faint">—</span>;
      return <span className="font-mono text-[11px] text-muted-foreground">{node.detail}</span>;
    }
    case 'actions': {
      // NIC detach button — only on NIC device rows when the plugin advertises it.
      if (node.dtype !== 'NIC' || !node.label || !actions) return null;
      const pid = node.row?.pluginId ?? '';
      if (!actions.hasAction(pid, 'vms.nic-detach')) return null;
      return (
        <button
          type="button"
          aria-label={`Detach NIC ${node.label}`}
          title={`Detach NIC ${node.label}`}
          onClick={() => actions.detachNic(node)}
          className="rounded-md p-1 text-danger-fg hover:bg-muted hover:text-danger-fg"
        >
          <Unplug size={13} />
        </button>
      );
    }
    default:
      return null;
  }
}

function ChildRow({ node, ctx, actions }: { node: VmNode; ctx: ExpandChildContext; actions?: DeviceActionContext }) {
  return (
    <tr className="bg-indigo-50/40 dark:bg-muted/70">
      <td className="px-1 py-2 align-middle">
        <span className="inline-block h-6 w-6" />
      </td>
      {ctx.selectable && <td className="px-3 py-2" />}
      {ctx.columns.map((col) => (
        <td key={col.key} className="overflow-hidden px-4 py-2 text-secondary">
          {nodeCell(col.key, node, ctx.depth, actions)}
        </td>
      ))}
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Plan helpers (same contract as the Containers page)
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
// NIC attach dialog — reads vms.nic-choices (read-only), submits vms.nic-attach
// through the plan workflow (2FA-gated).
// ---------------------------------------------------------------------------

interface NicAttachTarget {
  row: VmRow;
}

function NicAttachDialog({ target, onClose }: { target: NicAttachTarget; onClose: () => void }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [bridges, setBridges] = useState<string[]>([]);
  const [macvlans, setMacvlans] = useState<string[]>([]);
  const [selected, setSelected] = useState('');
  const [nicType, setNicType] = useState<'BRIDGE' | 'MACVLAN'>('BRIDGE');
  const [mac, setMac] = useState('');
  const [saving, setSaving] = useState(false);
  const [reauth, setReauth] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await api.executePluginAction(target.row.pluginId, { deviceId: target.row.deviceId, actionId: 'vms.nic-choices', input: {} });
        if (!cancelled) {
          setBridges(Array.isArray(res.details.bridges) ? (res.details.bridges as string[]) : []);
          setMacvlans(Array.isArray(res.details.macvlans) ? (res.details.macvlans as string[]) : []);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [target.row.pluginId, target.row.deviceId]);

  function pickInterface(value: string) {
    setSelected(value);
    setNicType(macvlans.includes(value) ? 'MACVLAN' : 'BRIDGE');
  }

  async function submit() {
    if (!selected) return;
    setSaving(true);
    setError(null);
    const input: Record<string, unknown> = { name: target.row.name, nicAttach: selected, type: nicType };
    if (mac.trim()) input['mac'] = mac.trim().toUpperCase();
    const attempt = async () => {
      await createAndExecutePlan(target.row.pluginId, 'vms.nic-attach', [{ deviceId: target.row.deviceId, input }]);
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
            <h2 className="text-base font-semibold text-foreground">Attach NIC — {target.row.name}</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">Applies via the plan workflow on {target.row.deviceName ?? target.row.deviceId}.</p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X size={16} />
          </button>
        </header>

        <div className="space-y-4 px-4 py-4">
          {loading && (
            <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 size={14} className="animate-spin" /> Loading available interfaces…</p>
          )}
          {error && !reauth && (
            <div className="rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
          )}

          {!loading && !error && (
            <>
              <div>
                <label className="mb-1 block text-xs font-medium text-secondary">Interface</label>
                <select
                  value={selected}
                  onChange={(e) => pickInterface(e.target.value)}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
                >
                  <option value="">Select a bridge or MACVLAN…</option>
                  {bridges.length > 0 && (
                    <optgroup label="Bridges">
                      {bridges.map((b) => <option key={b} value={b}>{b}</option>)}
                    </optgroup>
                  )}
                  {macvlans.length > 0 && (
                    <optgroup label="MACVLANs">
                      {macvlans.map((m) => <option key={m} value={m}>{m}</option>)}
                    </optgroup>
                  )}
                </select>
              </div>

              <div>
                <label className="mb-1 block text-xs font-medium text-secondary">MAC address (optional)</label>
                <input
                  type="text"
                  value={mac}
                  onChange={(e) => setMac(e.target.value)}
                  placeholder="Auto-assigned when empty"
                  pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint"
                />
              </div>
            </>
          )}
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={!selected || saving}
            onClick={() => void submit()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving && <Loader2 size={12} className="animate-spin" />}
            Attach NIC
          </button>
        </footer>

        {reauth && (
          <ReauthDialog
            contextLabel={`Attach NIC to ${target.row.name}`}
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

export default function Vms() {
  // The API polls plugins every ~30s and upserts these rows — refresh at the
  // same cadence so the view tracks live inventory.
  const vmsQuery = useQuery({
    queryKey: ['vms'],
    queryFn: () => api.vms(),
    refetchInterval: 30_000,
  });
  const queryClient = useQueryClient();

  // --- Action catalogs (drive per-row action availability GENERICALLY) -------
  // A button only renders when the row's plugin advertises that action id — so
  // any future hypervisor plugin (libvirt, Proxmox…) implementing the same ids
  // gets the full Actions column + bulk bar for free.
  const catalogPluginIds = useMemo(
    () => Array.from(new Set((vmsQuery.data?.vms ?? []).map((r) => r.pluginId))),
    [vmsQuery.data],
  );
  const catalogsQuery = useQuery({
    queryKey: ['plugin-actions-catalogs', catalogPluginIds.join('|')],
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

  // --- Live VM states probe (3s cadence, 'vmStates' key via virsh list) ------
  // Fresh plugins report real libvirt states; the State badge flips in ~3 s
  // after a start/stop instead of waiting for the next inventory poll.
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const probePluginIds = useMemo(
    () => new Set((pluginsQuery.data ?? []).filter((p) => (p.capabilities ?? []).includes('probe')).map((p) => p.id)),
    [pluginsQuery.data],
  );

  const probeTargets = useMemo(() => {
    const seen = new Set<string>();
    const out: { deviceId: string; pluginId: string }[] = [];
    for (const r of vmsQuery.data?.vms ?? []) {
      if (!probePluginIds.has(r.pluginId)) continue;
      const k = `${r.deviceId}|${r.pluginId}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({ deviceId: r.deviceId, pluginId: r.pluginId });
    }
    return out;
  }, [vmsQuery.data, probePluginIds]);

  const probeResults = useQueries({
    queries: probeTargets.map((t) => ({
      queryKey: ['device-probe', t.deviceId, 'vmStates'],
      queryFn: () => api.deviceProbe(t.deviceId, ['vmStates'], t.pluginId),
      refetchInterval: 3_000,
      staleTime: 0,
      gcTime: 30_000,
    })),
  });

  // deviceId|pluginId → { at, states: guest name → normalized state }. A failed
  // poll keeps serving the last good snapshot (react-query retains data).
  const liveVmStatesByDevice = useMemo(() => {
    const m = new Map<string, { at: number; states: Record<string, string> }>();
    probeTargets.forEach((t, i) => {
      const res = probeResults[i];
      if (!res?.data) return;
      const raw = res.data.probe.metrics['vmStates'];
      if (!raw || typeof raw !== 'object') return;
      const states: Record<string, string> = {};
      for (const [name, entry] of Object.entries(raw as Record<string, unknown>)) {
        const s = typeof entry === 'string' ? entry : (entry && typeof entry === 'object' && typeof (entry as Record<string, unknown>).status === 'string') ? String((entry as Record<string, unknown>).status) : '';
        if (s) states[name] = normalizeVmState(s);
      }
      m.set(`${t.deviceId}|${t.pluginId}`, { at: Date.parse(res.data.probe.collectedAt) || Date.now(), states });
    });
    return m;
  }, [probeTargets, probeResults]);

  /** Fresh (≤30 s) live state for one VM — null when the probe has no recent data. */
  function freshLiveState(deviceId: string, pluginId: string, name: string): string | null {
    const e = liveVmStatesByDevice.get(`${deviceId}|${pluginId}`);
    if (!e || Date.now() - e.at > 30_000) return null;
    return e.states[name] ?? null;
  }

  /** Effective state: fresh live probe wins over the cached inventory state. */
  function effectiveState(row: VmRow): string {
    const live = freshLiveState(row.deviceId, row.pluginId, row.name);
    return live ?? row.state;
  }

  // --- State sets for action eligibility --------------------------------------
  const RUNNING_STATES = useMemo(() => new Set(['RUNNING']), []);
  const STOPPED_STATES = useMemo(() => new Set(['STOPPED']), []);
  const SUSPENDED_STATES = useMemo(() => new Set(['SUSPENDED', 'PAUSED']), []);

  // --- Plan tracking → auto-refresh -------------------------------------------
  // Plans created by this page are tracked ONLY for data freshness: when one
  // settles the touched devices are force-refreshed once (vm.query re-runs) so
  // states update immediately. Execution status lives in the top-bar plans icon.
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
        void queryClient.invalidateQueries({ queryKey: ['vms'] });
        if (p.status !== 'succeeded') {
          setNotice({ kind: 'error', text: `A VM plan finished with errors — check the Plans page.` });
        }
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [pendingPlans, queryClient]);

  // --- Single-VM row action ----------------------------------------------------
  async function singleVm(row: VmRow, actionId: string, label: string) {
    const attempt = async () => {
      const planId = await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input: { names: [row.name] } }]);
      trackPlan(planId, [row.deviceId]);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `${label} — ${row.name}`, retry: attempt });
      else setNotice({ kind: 'error', text: `${label} failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  // --- Bulk VM action (selection bar) -------------------------------------------
  function vmBulk(actionId: string, label: string, eligible: (r: VmRow) => boolean, noEligibleMsg: string) {
    return async (rows: VmNode[]) => {
      const vms = rows.filter((n) => n.row && eligible(n.row));
      if (vms.length === 0) {
        setNotice({ kind: 'info', text: noEligibleMsg });
        return;
      }
      const attempt = async () => {
        for (const g of Array.from(groupByDevice(vms.map((n) => n.row!), (r) => ({ pluginId: r.pluginId, deviceId: r.deviceId }), (r) => r.name).values())) {
          const planId = await createAndExecutePlan(g.pluginId, actionId, [{ deviceId: g.deviceId, input: { names: g.values } }]);
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

  // --- NIC attach / detach --------------------------------------------------------
  const [nicTarget, setNicTarget] = useState<NicAttachTarget | null>(null);

  function detachNic(node: VmNode) {
    const row = node.row;
    const mac = node.label;
    if (!row || !mac) return;
    if (!window.confirm(`Detach NIC ${mac} from "${row.name}"?`)) return;
    const attempt = async () => {
      const planId = await createAndExecutePlan(row.pluginId, 'vms.nic-detach', [{ deviceId: row.deviceId, input: { name: row.name, mac } }]);
      trackPlan(planId, [row.deviceId]);
    };
    (async () => {
      try {
        await attempt();
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) setReauth({ label: `Detach NIC ${mac} — ${row.name}`, retry: attempt });
        else setNotice({ kind: 'error', text: `Detach NIC failed: ${err instanceof Error ? err.message : String(err)}` });
      }
    })();
  }

  // --- Display tree -----------------------------------------------------------------
  const tree = useMemo(() => {
    const childMap = new Map<string, VmNode[]>();
    const roots: VmNode[] = [];
    for (const row of vmsQuery.data?.vms ?? []) {
      const built = buildVm(row);
      roots.push(built.vm);
      if (built.devices.length > 0) childMap.set(built.vm.key, built.devices);
    }
    return { roots, childMap };
  }, [vmsQuery.data]);

  // --- Columns ------------------------------------------------------------------------
  const columns: DataTableColumn<VmNode>[] = [
    {
      header: 'VM',
      key: 'name',
      width: 220,
      exportValue: (node) => node.row?.name ?? '',
      render: (node) => {
        if (!node.row) return null;
        const desc = extraOf(node.row)['description'];
        return (
          <div className="flex flex-col gap-0.5">
            <span className="font-medium text-foreground">{node.row.name}</span>
            {typeof desc === 'string' && desc !== '' && (
              <span className="truncate text-[11px] text-faint" title={desc}>{desc}</span>
            )}
          </div>
        );
      },
    },
    {
      header: 'Hypervisor',
      key: 'deviceName',
      width: 230,
      exportValue: (node) => `${node.row?.deviceName ?? '?'} (${node.row?.managementAddress ?? '?'})`,
      render: (node) => {
        const r = node.row;
        if (!r) return null;
        return <DeviceChip deviceName={r.deviceName} managementAddress={r.managementAddress} pluginName={r.pluginName} siteName={r.siteName} interfaces={[]} />;
      },
    },
    {
      header: 'State',
      key: 'state',
      width: 120,
      exportValue: (node) => node.row?.state ?? '',
      render: (node) => (node.row ? <StateBadge state={effectiveState(node.row)} /> : null),
    },
    {
      header: 'vCPUs',
      key: 'vcpus',
      width: 80,
      sortAccessor: (node) => node.row?.vcpus ?? -1,
      exportValue: (node) => node.row?.vcpus ?? '',
      render: (node) =>
        node.row && node.row.vcpus !== null && node.row.vcpus !== undefined ? (
          <span className="font-mono text-xs">{node.row.vcpus}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Memory',
      key: 'memoryMiB',
      width: 110,
      sortAccessor: (node) => node.row?.memoryMiB ?? -1,
      exportValue: (node) => (node.row?.memoryMiB != null ? formatBytes(node.row.memoryMiB * 1048576) : ''),
      render: (node) =>
        node.row && node.row.memoryMiB !== null && node.row.memoryMiB !== undefined ? (
          <span className="font-mono text-xs">{formatBytes((node.row.memoryMiB as number) * 1048576)}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Uptime',
      key: 'startedAt',
      width: 120,
      exportValue: (node) => node.row?.startedAt ?? '',
      sortAccessor: (node) => (node.row?.startedAt ? new Date(node.row.startedAt).getTime() : null),
      render: (node) => (node.row ? <UptimeCell row={node.row} /> : null),
    },
    {
      header: 'Devices',
      key: 'devices',
      width: 240,
      exportValue: (node) => (node.row ? devicesOf(node.row).map((d) => `${d.dtype}: ${d.label ?? ''} ${d.detail ?? ''}`.trim()).join('; ') : ''),
      render: (node) => (node.row ? <DevicesCell row={node.row} /> : null),
    },
    {
      header: 'Collected',
      key: 'collectedAt',
      width: 170,
      sortAccessor: (node) => new Date(node.row?.collectedAt ?? '').getTime(),
      render: (node) => (node.row ? <span className="text-xs text-secondary">{new Date(node.row.collectedAt).toLocaleString()}</span> : null),
    },
    {
      // One-click per-row actions. Availability is GENERIC — a button only
      // renders when the row's plugin advertises that action id in its catalog,
      // so any future hypervisor plugin (libvirt, Proxmox…) gets this column free.
      header: 'Actions',
      key: 'actions',
      width: 170,
      sortable: false,
      excludeFromExport: true,
      render: (node) => {
        const r = node.row;
        if (!r || node.kind !== 'vm') return null;
        const state = effectiveState(r);
        const isRunning = RUNNING_STATES.has(state);
        const isStopped = STOPPED_STATES.has(state);
        const isSuspended = SUSPENDED_STATES.has(state);

        // Power-on button adapts: Start when stopped, Resume when suspended.
        const powerActionId = isSuspended ? 'vms.resume' : 'vms.start';
        const powerLabel = isSuspended ? 'Resume' : 'Start';
        const powerAvailable = hasAction(r.pluginId, powerActionId);
        const powerEligible = isStopped || isSuspended;

        const actions: { id: string; label: string; icon: ReactNode; available: boolean; eligible: boolean; danger?: boolean }[] = [
          { id: powerActionId, label: `${powerLabel} ${r.name}`, icon: <Play size={14} />, available: powerAvailable, eligible: powerEligible },
          { id: 'vms.stop', label: `Stop ${r.name}`, icon: <Square size={13} />, available: hasAction(r.pluginId, 'vms.stop'), eligible: isRunning, danger: true },
          { id: 'vms.kill', label: `Kill ${r.name}`, icon: <Zap size={14} />, available: hasAction(r.pluginId, 'vms.kill'), eligible: isRunning || isSuspended, danger: true },
          { id: 'vms.restart', label: `Restart ${r.name}`, icon: <RotateCw size={14} />, available: hasAction(r.pluginId, 'vms.restart'), eligible: !isStopped },
          { id: 'vms.suspend', label: `Suspend ${r.name}`, icon: <Pause size={13} />, available: hasAction(r.pluginId, 'vms.suspend'), eligible: isRunning },
          { id: 'vms.delete', label: `Delete ${r.name}`, icon: <Trash2 size={13} />, available: hasAction(r.pluginId, 'vms.delete'), eligible: true, danger: true },
          { id: 'vms.nic-attach', label: `Attach NIC to ${r.name}`, icon: <Plug size={14} />, available: hasAction(r.pluginId, 'vms.nic-attach'), eligible: true },
        ];

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
                  title={enabled ? a.label : `Not applicable in state ${state.toLowerCase()}`}
                  disabled={!enabled}
                  onClick={() => {
                    if (a.id === 'vms.nic-attach') setNicTarget({ row: r });
                    else if (a.id === 'vms.delete') {
                      if (!window.confirm(`Permanently delete VM "${r.name}"? This is destructive.`)) return;
                      void singleVm(r, a.id, `Delete ${r.name}`);
                    } else {
                      void singleVm(r, a.id, a.label.split(' ')[0]);
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
          </div>
        );
      },
    },
  ];

  // --- Summary numbers ------------------------------------------------------------------
  const running = tree.roots.filter((n) => n.row && RUNNING_STATES.has(effectiveState(n.row))).length;
  const totalVcpus = tree.roots.reduce((sum, n) => sum + (n.row?.vcpus ?? 0), 0);
  const totalMemMiB = tree.roots.reduce((sum, n) => sum + (n.row?.memoryMiB ?? 0), 0);

  return (
    <Layout title="VMs">
      <div className="flex h-full min-h-0 flex-col">
        {vmsQuery.isLoading && <p className="shrink-0 text-sm text-muted-foreground">Loading VMs...</p>}
        {vmsQuery.isError && (
          <p className="shrink-0 text-sm text-danger-fg">Failed to load VMs: {(vmsQuery.error as Error).message}</p>
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

        {/* Summary strip — VM counts + allocated resources. */}
        {!vmsQuery.isLoading && !vmsQuery.isError && (
          <div className="mb-3 flex shrink-0 flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-border bg-card px-4 py-2 text-xs">
            <span className="flex items-center gap-2 text-secondary">
              <Monitor size={13} className="text-indigo-500" />
              {tree.roots.length} VM{tree.roots.length === 1 ? '' : 's'} · {running} running
            </span>
            {totalVcpus > 0 && (
              <span className="flex items-center gap-2 text-secondary">
                <Monitor size={13} className="text-muted-foreground" />
                {totalVcpus} vCPU{totalVcpus === 1 ? '' : 's'} allocated
              </span>
            )}
            {totalMemMiB > 0 && (
              <span className="flex items-center gap-2 text-secondary">
                <Monitor size={13} className="text-muted-foreground" />
                <span className="font-mono text-secondary">{formatBytes(totalMemMiB * 1048576)} memory allocated</span>
              </span>
            )}
          </div>
        )}

        {vmsQuery.data && (
          <DataTable<VmNode>
            columns={columns}
            rows={tree.roots}
            rowKey={(node) => node.key}
            storageKey="vms"
            autoRefresh={{ intervalMs: 30_000, queries: [vmsQuery] }}
            fillHeight
            searchPlaceholder="Search VMs…"
            selectable
            bulkActions={[
              { label: 'Stop', onClick: vmBulk('vms.stop', 'Stop selected', (r) => RUNNING_STATES.has(effectiveState(r)), 'No selected VMs are running — nothing to stop.') },
              { label: 'Kill', confirm: (c) => `Hard-kill ${c} VM(s)? Unsaved guest state will be lost.`, onClick: vmBulk('vms.kill', 'Kill selected', (r) => RUNNING_STATES.has(effectiveState(r)) || SUSPENDED_STATES.has(effectiveState(r)), 'No selected VMs are running or suspended — nothing to kill.') },
              { label: 'Start', onClick: vmBulk('vms.start', 'Start selected', (r) => STOPPED_STATES.has(effectiveState(r)), 'No selected VMs are stopped — nothing to start.') },
              { label: 'Restart', onClick: vmBulk('vms.restart', 'Restart selected', () => true, '') },
              { label: 'Suspend', onClick: vmBulk('vms.suspend', 'Suspend selected', (r) => RUNNING_STATES.has(effectiveState(r)), 'No selected VMs are running — nothing to suspend.') },
              { label: 'Resume', onClick: vmBulk('vms.resume', 'Resume selected', (r) => SUSPENDED_STATES.has(effectiveState(r)), 'No selected VMs are suspended — nothing to resume.') },
              {
                label: 'Delete',
                confirm: (c) => `Permanently delete ${c} VM(s)? This is destructive.`,
                onClick: vmBulk('vms.delete', 'Delete selected', () => true, ''),
              },
            ]}
            expandable={{
              childrenOf: (node) => tree.childMap.get(node.key) ?? [],
              renderChild: (child, _parent, ctx) => <ChildRow node={child} ctx={ctx} actions={{ hasAction, detachNic }} />,
            }}
            emptyMessage="No VMs collected yet — assign a TrueNAS plugin to a hypervisor device and wait for the next poll. NIC MAC addresses appear on the Hosts page with source “VM”."
          />
        )}

        {/* NIC attach dialog */}
        {nicTarget && <NicAttachDialog target={nicTarget} onClose={() => setNicTarget(null)} />}

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
