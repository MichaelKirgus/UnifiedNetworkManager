import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { CheckCircle2, EyeOff, Loader2, Monitor, Pencil, Pause, Play, Plus, RefreshCw, RotateCw, Square, Trash2, Unplug, X, Zap } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { formatBytes, formatDuration } from '../components/formatMetric';
import { ReauthDialog } from '../components/ReauthDialog';
import { defaultValues, SchemaForm, validateSchema } from '../components/SchemaForm';
import { READONLY_MESSAGE, runAction, useExecutionMode, type ExecutionMode } from '../executionMode';
import { api, ApiError, CatalogEntry, Device, FileRepoEntry, InputSchema, VmDevice, VmNic, VmRow } from '../api/client';
import { useTimeFormat } from '../utils/time';

// ---------------------------------------------------------------------------
// State badge (case-tolerant — live probe states are lowercase libvirt strings)
// ---------------------------------------------------------------------------

const STATE_STYLES: Record<string, string> = {
  RUNNING: 'bg-success text-success-fg border-success-border',
  STOPPED: 'bg-muted text-secondary border-border',
  SUSPENDED: 'bg-warning text-warning-fg border-warning-border',
  PAUSED: 'bg-accent-sky text-accent-sky-fg border-accent-sky-border',
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
  const { formatDateTime } = useTimeFormat();
  if (row.state !== 'RUNNING' || !row.startedAt) return <span className="text-faint">—</span>;
  const since = new Date(row.startedAt).getTime();
  if (Number.isNaN(since)) return <span className="text-faint">—</span>;
  const secs = Math.max(0, (Date.now() - since) / 1000);
  return (
    <span className="font-mono text-xs text-secondary" title={`Running since ${formatDateTime(row.startedAt)}`}>
      {formatDuration(secs)}
    </span>
  );
}

/** Live CPU% cell — percent of ALLOCATED vCPUs with amber/red tint at high
 * utilization (same thresholds as the Containers page). "—" until the first
 * successful probe cycle after a plugin restart has established its baseline. */
function CpuCell({ pct }: { pct?: number | null }) {
  if (pct === undefined || pct === null) return <span className="text-faint">—</span>;
  return (
    <span className={clsx('font-mono text-xs', pct >= 90 ? 'text-danger-fg' : pct >= 60 ? 'text-warning-fg' : 'text-foreground')}>
      {pct.toFixed(1)}%
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
  /** The appliance's integer device id (vms.device-detach/edit target) when known. */
  devId?: number;
}

function buildVm(row: VmRow): { vm: VmNode; devices: VmNode[] } {
  const base = `${row.deviceId}|${row.pluginId}|${row.name}`;
  const devices = devicesOf(row).map((d, i) => ({
    key: `${base}#dev${i}`,
    kind: 'device' as const,
    row, // parent VM — needed for device actions on child rows
    dtype: d.dtype,
    label: typeof d.label === 'string' && d.label !== '' ? d.label : undefined,
    detail: typeof d.detail === 'string' && d.detail !== '' ? d.detail : undefined,
    devId: typeof d.id === 'number' ? d.id : undefined,
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
  /** Generic device detach by integer id — any dtype (NIC, disk, display, CD-ROM…). */
  detachDevice: (node: VmNode) => void;
  /** Opens the generic Edit-device dialog for this attached device. */
  editDevice: (node: VmNode) => void;
  /** True when the parent VM is stopped — vms.device-detach requires it. */
  vmStopped: (row: VmRow) => boolean;
  /** Read-Only mode — disables the device write actions. */
  readOnly?: boolean;
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
      if (!node.row || !actions) return null;
      const pid = node.row.pluginId;
      // Generic device actions — any dtype that carries an integer id, when the
      // plugin advertises them. Edit (vms.device-update) works on running VMs for
      // hot-pluggable types; detach requires a STOPPED VM (the appliance enforces
      // it too) and is disabled otherwise with an explanatory title.
      if (node.devId !== undefined && (actions.hasAction(pid, 'vms.device-detach') || actions.hasAction(pid, 'vms.device-update'))) {
        const stopped = actions.vmStopped(node.row);
        const blockedByReadOnly = !!actions.readOnly;
        return (
          <span className="inline-flex items-center gap-0.5">
            {actions.hasAction(pid, 'vms.device-update') && (
              <button
                type="button"
                aria-label={`Edit ${node.dtype ?? 'device'} ${node.label ?? ''}`}
                title={blockedByReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : `Edit ${node.dtype?.toLowerCase() ?? 'device'} ${node.label ?? ''}`}
                disabled={blockedByReadOnly}
                onClick={() => actions.editDevice(node)}
                className="rounded-md p-1 text-secondary hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-30"
              >
                <Pencil size={13} />
              </button>
            )}
            {actions.hasAction(pid, 'vms.device-detach') && (
              <button
                type="button"
                aria-label={`Detach ${node.dtype ?? 'device'} ${node.label ?? ''}`}
                title={blockedByReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : !stopped ? `Stop the VM first — devices can only be detached while it is stopped` : `Detach ${node.dtype?.toLowerCase() ?? 'device'} ${node.label ?? ''}`}
                disabled={blockedByReadOnly || !stopped}
                onClick={() => actions.detachDevice(node)}
                className="rounded-md p-1 text-danger-fg hover:bg-muted hover:text-danger-fg disabled:cursor-not-allowed disabled:opacity-30"
              >
                <Unplug size={13} />
              </button>
            )}
          </span>
        );
      }
      // Legacy fallback — NIC detach by MAC (plugins that don't carry device ids).
      if (node.dtype !== 'NIC' || !node.label) return null;
      if (!actions.hasAction(pid, 'vms.nic-detach')) return null;
      const blockedByReadOnly = !!actions.readOnly;
      return (
        <button
          type="button"
          aria-label={`Detach NIC ${node.label}`}
          title={blockedByReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : `Detach NIC ${node.label}`}
          disabled={blockedByReadOnly}
          onClick={() => actions.detachNic(node)}
          className="rounded-md p-1 text-danger-fg hover:bg-muted hover:text-danger-fg disabled:cursor-not-allowed disabled:opacity-30"
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
    <tr className="bg-accent-indigo/40 dark:bg-muted/70">
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
// Add-device dialog — the NIC attach (vms.nic-choices → vms.nic-attach) and
// CD-ROM/ISO attach (repo / dataset / manual path → vms.cdrom-attach) flows are
// folded into it below, driven by the plugin's vms.device-types descriptor.
// ---------------------------------------------------------------------------

interface NicAttachTarget {
  row: VmRow;
}

// ---------------------------------------------------------------------------
// Create-VM dialog — hypervisor-generic: the form is driven by the plugin's
// `vms.create` inputSchema (rendered via SchemaForm), so any future hypervisor
// plugin implementing that id gets this dialog for free. Custom controls on top:
// an appliance picker (multi-TrueNAS fleets), a disk-dataset picker and a NIC
// section — all fed by read-only catalog actions (vms.create-choices /
// vms.nic-choices) on the SELECTED device, so choices always match the target.
// ---------------------------------------------------------------------------

interface CreateVmTarget {
  /** The appliance device (UNM device row) the VM will be created on. */
  device: Device;
  pluginId: string;
}

/** Generates a random locally-administered unicast MAC (02:xx:…). */
function generateMac(): string {
  const b = [0x02, ...Array.from({ length: 5 }, () => Math.floor(Math.random() * 256))];
  return b.map((x) => x.toString(16).padStart(2, '0')).join(':').toUpperCase();
}

/** Human-readable size for a MiB value (memory fields). */
function humanMiB(mib: number): string {
  if (mib >= 1024) return `${(mib / 1024).toLocaleString()} GiB`;
  return `${mib} MiB`;
}

/** Human-readable size for a byte value (disk fields). */
function humanBytes(b: number): string {
  const gb = b / 1073741824;
  if (gb >= 1024) return `${(gb / 1024).toLocaleString()} TiB`;
  return `${gb.toLocaleString()} GiB`;
}

/** Common memory presets in MiB, labelled with friendly GB values. */
const MEMORY_PRESETS: { value: number; label: string }[] = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536].map((v) => ({ value: v, label: humanMiB(v) }));

/** Common disk presets in bytes, labelled with friendly GB/TB values. */
const DISK_PRESETS: { value: number; label: string }[] = [
  ...[10, 20, 50, 100, 200, 500].map((g) => ({ value: g * 1073741824, label: `${g} GB` })),
  ...[1, 2, 4, 8].map((t) => ({ value: t * 1099511627776, label: `${t} TB` })),
];

/** A size combobox: friendly preset options (GB/TB labels) that resolve to the
 * integer MiB/bytes value; a non-preset current value is kept as an extra option
 * so custom sizes are never lost. */
function SizeSelect({ value, presets, format, onChange }: { value: number | undefined; presets: { value: number; label: string }[]; format: (n: number) => string; onChange: (v: number | undefined) => void }) {
  const opts = value !== undefined && !presets.some((p) => p.value === value) ? [{ value, label: format(value) }, ...presets] : presets;
  return (
    <select value={value ?? ''} onChange={(e) => onChange(e.target.value === '' ? undefined : Number(e.target.value))}
      className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
      <option value="">Select a size…</option>
      {opts.map((o) => (<option key={o.value} value={o.value}>{o.label}</option>))}
    </select>
  );
}

function CreateVmDialog({ targets, onClose }: { targets: CreateVmTarget[]; onClose: () => void }) {
  const { mode } = useExecutionMode();
  const isPlanMode = mode === 'plan';
  const isReadOnly = mode === 'readonly';
  // Which appliance to create on — the dialog owns this selection so multi-
  // appliance fleets work (the top-bar button just opens the dialog).
  const [targetIdx, setTargetIdx] = useState(0);
  const target = targets[Math.min(targetIdx, Math.max(targets.length - 1, 0))] ?? null;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [schema, setSchema] = useState<InputSchema | null>(null);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  // Per-appliance choices (re-fetched when the appliance changes).
  const [datasets, setDatasets] = useState<{ name: string; mountpoint: string }[]>([]);
  const [bridges, setBridges] = useState<string[]>([]);
  const [macvlans, setMacvlans] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [reauth, setReauth] = useState(false);
  // Plan mode: the create plan was saved without executing.
  const [saved, setSaved] = useState(false);
  // Form defaults are applied ONCE — switching appliance must not wipe user input.
  const initializedRef = useRef(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!target) return;
      try {
        setLoading(true);
        setError(null);
        // The action's inputSchema IS the form — read it from the catalog.
        const cat = await api.pluginActions(target.pluginId);
        const entry: CatalogEntry | undefined = cat.actions.find((a) => a.id === 'vms.create');
        if (!entry) {
          setSchema(null); // can't happen in practice — the button is gated on hasAction('vms.create')
          return;
        }
        setSchema(entry.inputSchema ?? {});
        if (!initializedRef.current) {
          // Pre-fill defaults from the schema itself (first load only).
          const init: Record<string, unknown> = {};
          for (const [k, p] of Object.entries(entry.inputSchema ?? {})) {
            if (p?.default !== undefined) init[k] = p.default;
          }
          setValues(init);
          initializedRef.current = true;
        }
        // Dataset + NIC pickers — read-only catalog actions on the SELECTED device.
        const [choicesRes, nicRes] = await Promise.all([
          api.executePluginAction(target.pluginId, { deviceId: target.device.id, actionId: 'vms.create-choices', input: {} }),
          api.executePluginAction(target.pluginId, { deviceId: target.device.id, actionId: 'vms.nic-choices', input: {} }).catch(() => null),
        ]);
        if (cancelled) return;
        const dsList = Array.isArray(choicesRes.details.datasets) ? (choicesRes.details.datasets as { name: string; mountpoint: string }[]) : [];
        setDatasets(dsList);
        const b = nicRes?.details.bridges;
        const m = nicRes?.details.macvlans;
        const brList = Array.isArray(b) ? (b as string[]) : [];
        const mvList = Array.isArray(m) ? (m as string[]) : [];
        setBridges(brList);
        setMacvlans(mvList);
        // Dataset + NIC selections are appliance-specific — drop them when they
        // don't exist on the newly selected appliance.
        setValues((v) => {
          const ds = typeof v['dataset'] === 'string' ? (v['dataset'] as string) : '';
          const na = typeof v['nicAttach'] === 'string' ? (v['nicAttach'] as string) : '';
          if ((ds && !dsList.some((d) => d.name === ds)) || (na && !brList.includes(na) && !mvList.includes(na))) {
            const next = { ...v };
            if (ds && !dsList.some((d) => d.name === ds)) delete next['dataset'];
            if (na && !brList.includes(na) && !mvList.includes(na)) delete next['nicAttach'];
            return next;
          }
          return v;
        });
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [target?.pluginId, target?.device.id]); // eslint-disable-line react-hooks/exhaustive-deps

  function setField(key: string, value: unknown) {
    const next = { ...values, [key]: value };
    if (key === 'nicAttach' && typeof value === 'string' && value !== '') {
      // Auto-generate a MAC when empty. The bridge/MACVLAN kind is inferred by
      // the appliance from the chosen interface (TrueNAS v26) — no selector needed.
      if (!next['mac']) next['mac'] = generateMac();
    } else if (key === 'nicAttach') {
      // No NIC selected — drop the now-irrelevant MAC.
      delete next['mac'];
    } else if (key === 'diskMode') {
      // Switching disk mode clears the fields of the other mode.
      if (value === 'path') { delete next['dataset']; delete next['sizeBytes']; delete next['zvolName']; }
      else { delete next['diskPath']; }
    }
    setValues(next);
  }

  async function submit() {
    if (isReadOnly || !schema || !target) return; // Read-Only / no target — safety nets.
    const errs = validateSchema(schema, values);
    // The custom controls aren't covered by the schema validator — check them here.
    const dm = typeof values['diskMode'] === 'string' ? (values['diskMode'] as string) : 'zvol';
    if (dm === 'zvol') {
      if (!datasetValue) errs['dataset'] = 'Select a dataset for the new ZVOL';
      if (!(typeof values['sizeBytes'] === 'number')) errs['sizeBytes'] = 'Select a disk size';
    } else {
      const dp = typeof values['diskPath'] === 'string' ? (values['diskPath'] as string) : '';
      if (!dp.startsWith('/dev/zvol/')) errs['diskPath'] = 'Must be an existing /dev/zvol/… path';
    }
    setFieldErrors(errs);
    if (Object.keys(errs).length > 0) return;
    setSaving(true);
    setError(null);
    const attempt = async () => {
      await createAndExecutePlan(target.pluginId, 'vms.create', [{ deviceId: target.device.id, input: values }], mode);
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

  // The schema-driven part of the form — everything EXCEPT the custom controls
  // rendered explicitly below (appliance/disk/memory/NIC pickers with live
  // choices + friendly size comboboxes). Keeps name/vcpus/etc. generic.
  // NOTE: must stay ABOVE any early return — hooks may not be conditional.
  const CUSTOM_KEYS = ['dataset', 'nicAttach', 'mac', 'nicType', 'memoryMiB', 'minMemoryMiB', 'sizeBytes', 'diskPath', 'diskMode', 'zvolName', 'diskType'];
  const formSchema = useMemo(() => {
    if (!schema) return null;
    const out: InputSchema = {};
    for (const [k, p] of Object.entries(schema)) {
      if (CUSTOM_KEYS.includes(k)) continue;
      out[k] = p;
    }
    return out;
  }, [schema]);

  // Plan mode: the plan was saved without executing — offer to close.
  if (saved) {
    return (
      <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
        <div className="mt-8 w-full max-w-md rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
          <header className="flex items-center justify-between border-b border-border px-4 py-3">
            <h2 className="text-base font-semibold text-foreground">Create VM — saved</h2>
            <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted"><X size={16} /></button>
          </header>
          <div className="space-y-3 px-4 py-4">
            <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-xs text-success-fg">
              <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
              VM creation saved as a plan — it was NOT executed. Open the Plans center to run it later (or schedule it).
            </div>
          </div>
          <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
            <button type="button" onClick={onClose} className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90">Close</button>
          </footer>
        </div>
      </div>
    );
  }

  const nicAttach = typeof values['nicAttach'] === 'string' ? (values['nicAttach'] as string) : '';
  const macValue = typeof values['mac'] === 'string' ? (values['mac'] as string) : '';
  const datasetValue = typeof values['dataset'] === 'string' ? (values['dataset'] as string) : '';
  const vmName = typeof values['name'] === 'string' ? (values['name'] as string) : '';
  const diskMode = typeof values['diskMode'] === 'string' ? (values['diskMode'] as string) : 'zvol';
  const sizeBytesVal = typeof values['sizeBytes'] === 'number' ? (values['sizeBytes'] as number) : undefined;
  const memVal = typeof values['memoryMiB'] === 'number' ? (values['memoryMiB'] as number) : undefined;
  const minMemVal = typeof values['minMemoryMiB'] === 'number' ? (values['minMemoryMiB'] as number) : undefined;
  const zvolNameVal = typeof values['zvolName'] === 'string' ? (values['zvolName'] as string) : '';
  const diskTypeVal = typeof values['diskType'] === 'string' ? (values['diskType'] as string) : 'VIRTIO';
  // The ZVOL leaf that will be created — override if given, else derived from the VM name.
  // Case is preserved (ZFS dataset names are case-sensitive); only invalid chars stripped.
  const zvolLeaf = (zvolNameVal || vmName).replace(/[^a-zA-Z0-9_]/g, '');

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      {/* Compact: the panel is capped to the viewport and only its BODY scrolls —
          the page behind never has to scroll for this dialog. */}
      <div className="mt-6 flex max-h-[calc(100vh-96px)] w-full max-w-lg flex-col rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex shrink-0 items-center justify-between border-b border-border px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">Create VM</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {targets.length === 1 && target ? `Applies via the plan workflow on ${target.device.name}.` : 'Applies via the plan workflow — pick an appliance below.'}
            </p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted"><X size={16} /></button>
        </header>

        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto px-4 py-3">
          {isReadOnly && (
            <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
              <EyeOff size={14} className="mt-0.5 shrink-0" />
              Read-only mode is active — this change cannot be saved or applied. Switch to Plan or Execute in the top bar.
            </div>
          )}
          {loading && (
            <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 size={14} className="animate-spin" /> Loading VM creation form…</p>
          )}
          {error && !reauth && (
            <div className="rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
          )}

          {!loading && !error && schema && target && (
            <>
              {/* Appliance picker — multi-appliance fleets. */}
              {targets.length > 1 && (
                <div>
                  <label className="mb-1 block text-xs font-medium text-secondary">Appliance</label>
                  <select value={targetIdx} onChange={(e) => setTargetIdx(Number(e.target.value))}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                    {targets.map((t, i) => (
                      <option key={`${t.device.id}|${t.pluginId}`} value={i}>{t.device.name}</option>
                    ))}
                  </select>
                </div>
              )}

              {/* VM basics — schema-driven (name, description, vCPUs, firmware…). */}
              {formSchema && Object.keys(formSchema).length > 0 && (
                <SchemaForm schema={formSchema} values={values} onChange={(v) => setValues(v)} fieldErrors={fieldErrors} />
              )}

              {/* Memory — friendly GB comboboxes. */}
              <div className="space-y-2 rounded-md border border-border bg-background/60 p-3">
                <label className="block text-xs font-medium text-secondary">Memory</label>
                <SizeSelect value={memVal} presets={MEMORY_PRESETS} format={humanMiB} onChange={(v) => setField('memoryMiB', v)} />
                {fieldErrors['memoryMiB'] && <p className="text-xs text-danger-fg">{fieldErrors['memoryMiB']}</p>}
                <div>
                  <label className="mb-1 block text-xs font-medium text-secondary">Minimum memory (optional)</label>
                  <SizeSelect value={minMemVal} presets={MEMORY_PRESETS} format={humanMiB} onChange={(v) => setField('minMemoryMiB', v)} />
                </div>
              </div>

              {/* Disk — mode + zvol/path specifics. */}
              <div className="space-y-2 rounded-md border border-border bg-background/60 p-3">
                <label className="block text-xs font-medium text-secondary">Disk</label>
                <select value={diskMode} onChange={(e) => setField('diskMode', e.target.value)}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                  <option value="zvol">New ZVOL (recommended)</option>
                  <option value="path">Existing disk path</option>
                </select>

                {diskMode === 'zvol' ? (
                  <>
                    {datasets.length > 0 && (
                      <div>
                        <label className="mb-1 block text-xs font-medium text-secondary">Disk dataset</label>
                        <select value={datasetValue} onChange={(e) => setField('dataset', e.target.value || undefined)}
                          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                          <option value="">Select a dataset…</option>
                          {datasets.map((d) => (<option key={d.name} value={d.name}>{d.name}</option>))}
                        </select>
                        {fieldErrors['dataset'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['dataset']}</p>}
                      </div>
                    )}
                    <div>
                      <label className="mb-1 block text-xs font-medium text-secondary">Disk size</label>
                      <SizeSelect value={sizeBytesVal} presets={DISK_PRESETS} format={humanBytes} onChange={(v) => setField('sizeBytes', v)} />
                      {fieldErrors['sizeBytes'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['sizeBytes']}</p>}
                    </div>
                    <div>
                      <label className="mb-1 block text-xs font-medium text-secondary">ZVOL name (optional)</label>
                      <input type="text" value={zvolNameVal} onChange={(e) => setField('zvolName', e.target.value || undefined)}
                        placeholder={vmName ? vmName.replace(/[^a-zA-Z0-9_]/g, '') : 'derived from VM name'}
                        className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint" />
                      {datasetValue && zvolLeaf && (
                        <p className="mt-1 text-xs text-faint">Will create ZVOL <span className="font-mono">{datasetValue}/{zvolLeaf}</span></p>
                      )}
                    </div>
                  </>
                ) : (
                  <div>
                    <label className="mb-1 block text-xs font-medium text-secondary">Disk path</label>
                    <input type="text" value={typeof values['diskPath'] === 'string' ? (values['diskPath'] as string) : ''} onChange={(e) => setField('diskPath', e.target.value || undefined)}
                      placeholder="/dev/zvol/POOL/disk" pattern="^/dev/zvol/.+"
                      className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint" />
                    {fieldErrors['diskPath'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['diskPath']}</p>}
                  </div>
                )}

                <div>
                  <label className="mb-1 block text-xs font-medium text-secondary">Controller</label>
                  <select value={diskTypeVal} onChange={(e) => setField('diskType', e.target.value)}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                    <option value="VIRTIO">VIRTIO (performance)</option>
                    <option value="AHCI">AHCI (compatibility)</option>
                  </select>
                </div>
              </div>

              {/* NIC — interface selection (bridges + MACVLANs in optgroups); the
                  attachment kind is inferred by the appliance from the interface,
                  and a MAC is auto-generated. */}
              <div className="space-y-2 rounded-md border border-border bg-background/60 p-3">
                <label className="block text-xs font-medium text-secondary">Network (optional)</label>
                <div>
                  <label className="mb-1 block text-xs font-medium text-secondary">Interface</label>
                  <select value={nicAttach} onChange={(e) => setField('nicAttach', e.target.value || undefined)}
                    disabled={bridges.length === 0 && macvlans.length === 0}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground disabled:opacity-50">
                    <option value="">No NIC — attach later</option>
                    {bridges.length > 0 && (<optgroup label="Bridges">{bridges.map((b) => (<option key={b} value={b}>{b}</option>))}</optgroup>)}
                    {macvlans.length > 0 && (<optgroup label="MACVLANs">{macvlans.map((m) => (<option key={m} value={m}>{m}</option>))}</optgroup>)}
                  </select>
                </div>
                {nicAttach !== '' && (
                  <div className="flex items-center gap-2">
                    <input type="text" value={macValue} onChange={(e) => setField('mac', e.target.value || undefined)}
                      pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$" placeholder="MAC address (auto-generated)"
                      className="flex-1 rounded-md border border-border bg-background px-3 py-1.5 font-mono text-sm text-foreground placeholder:text-faint" />
                    <button type="button" onClick={() => setField('mac', generateMac())} title="Generate a new MAC address" aria-label="Generate a new MAC address"
                      className="rounded-md border border-border bg-background p-1.5 text-secondary hover:bg-muted">
                      <RefreshCw size={13} />
                    </button>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        <footer className="flex shrink-0 items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={!schema || saving || isReadOnly}
            title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : undefined}
            onClick={() => void submit()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving && <Loader2 size={12} className="animate-spin" />}
            {isPlanMode ? 'Save as plan' : 'Create VM'}
          </button>
        </footer>

        {reauth && (
          <ReauthDialog
            contextLabel={`Create VM on ${target?.device.name ?? ''}`}
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
// CD-ROM / ISO attach dialog — three sources, all hypervisor-generic:
//   1. UNM file repo (Files page) → the plugin streams it onto the appliance
//      when missing (vms.cdrom-attach with repoFileId + dataset).
//   2. An existing ISO in a dataset on the appliance (vms.iso-choices).
//   3. A manual /mnt/ path.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Add-device dialog — hypervisor-generic. The plugin's `vms.device-types`
// read action advertises every attachable device type with its form fields
// (inputSchema), whether the VM must be stopped, and which read-only action
// feeds a picker. This dialog renders that contract generically — it has NO
// knowledge of TrueNAS dtypes, so a future Proxmox plugin with other types /
// fields / actions gets this same dialog for free. Submit goes through the
// plan workflow as `vms.<dtype-lowercase>-attach` (2FA-gated).
// ---------------------------------------------------------------------------

/** One attachable device type as advertised in vms.device-types details.types[]. */
interface VmDeviceTypeDescriptor {
  dtype: string;
  label: string;
  description?: string;
  /** True when the appliance requires a STOPPED VM for this type. */
  requiresStopped: boolean;
  /** Read-only catalog action whose details feed the dialog's picker (optional). */
  choicesActionId?: string;
  inputSchema: InputSchema;
  /** The subset of fields editable on an ALREADY-ATTACHED device (vms.device-update). Absent = not editable in place. */
  editInputSchema?: InputSchema;
}

/** Target of the Edit-device dialog — one attached device row under a VM. */
interface DeviceEditTarget {
  row: VmRow;
  /** The appliance's integer device id (vms.device-get / vms.device-update target). */
  devId: number;
  dtype: string;
}

/** One normalized picker entry from a type's choices action. */
interface VmDeviceChoice { id: string; label: string; available?: boolean; hint?: string; }

/** Normalizes the details of a type's choices action into picker entries. */
function normalizeChoices(dtype: string, details: Record<string, unknown>): { list: VmDeviceChoice[]; iommu?: boolean } {
  // NIC choices are two flat string lists (bridges + macvlans), not object rows.
  if (dtype.toUpperCase() === 'NIC') {
    const bridges = Array.isArray(details['bridges']) ? (details['bridges'] as string[]) : [];
    const macvlans = Array.isArray(details['macvlans']) ? (details['macvlans'] as string[]) : [];
    return { list: [
      ...bridges.map((b) => ({ id: b, label: b })),
      ...macvlans.map((m) => ({ id: m, label: m, hint: 'MACVLAN' })),
    ] };
  }
  const raw = (details['devices'] ?? details['disks']) as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(raw)) return { list: [] };
  let list: VmDeviceChoice[];
  switch (dtype.toUpperCase()) {
    case 'PCI':
      // Usable devices first — the picker should lead with what works.
      list = raw
        .map((x) => ({ id: String(x['id'] ?? ''), label: String(x['description'] ?? x['id']), available: x['available'] === true, hint: x['available'] === true ? undefined : (typeof x['error'] === 'string' && x['error'] !== '' ? x['error'] : 'unavailable') }))
        .sort((a, b) => Number(b.available ?? false) - Number(a.available ?? false));
      break;
    case 'USB':
      list = raw.map((x) => ({ id: String(x['id'] ?? ''), label: String(x['description'] ?? x['id']), available: x['available'] === true, hint: x['available'] === true ? undefined : 'unavailable' }));
      break;
    case 'DISK':
      list = raw.map((x) => ({ id: String(x['path'] ?? ''), label: String(x['name'] ?? x['path']) }));
      break;
    default:
      list = raw.map((x) => ({ id: String(x['id'] ?? ''), label: String(x['description'] ?? x['id']) }));
  }
  return { list, ...(typeof details['iommuEnabled'] === 'boolean' ? { iommu: details['iommuEnabled'] as boolean } : {}) };
}

function AttachDeviceDialog({ target, stopped, onClose }: { target: NicAttachTarget; stopped: boolean; onClose: () => void }) {
  const { mode } = useExecutionMode();
  const isPlanMode = mode === 'plan';
  const isReadOnly = mode === 'readonly';
  const row = target.row;

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [types, setTypes] = useState<VmDeviceTypeDescriptor[]>([]);
  const [dtype, setDtype] = useState('');
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [choiceData, setChoiceData] = useState<{ list: VmDeviceChoice[]; iommu?: boolean } | null>(null);
  // CD-ROM/ISO source data — loaded when the CDROM type is selected (repo files,
  // appliance datasets and per-dataset ISO lists). The `source` field in values
  // picks which of these sections renders.
  const [cdromRepoFiles, setCdromRepoFiles] = useState<FileRepoEntry[]>([]);
  const [cdromDatasets, setCdromDatasets] = useState<{ name: string; mountpoint: string }[]>([]);
  const [cdromIsoFiles, setCdromIsoFiles] = useState<{ path: string; name: string; sizeBytes: number | null }[]>([]);
  const [cdromIsoPath, setCdromIsoPath] = useState('');
  const [cdromManualPath, setCdromManualPath] = useState('');
  const [saving, setSaving] = useState(false);
  const [reauth, setReauth] = useState(false);
  // Plan mode: the attach plan was saved without executing.
  const [saved, setSaved] = useState(false);

  // Load the descriptor catalog that drives this whole dialog.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await api.executePluginAction(row.pluginId, { deviceId: row.deviceId, actionId: 'vms.device-types', input: {} });
        if (!cancelled) {
          const raw = Array.isArray(res.details.types) ? (res.details.types as VmDeviceTypeDescriptor[]) : [];
          // A VM may have at most ONE display (appliance rule) — hide the type once it exists.
          const visible = raw.filter((t) => !(t.dtype === 'DISPLAY' && devicesOf(row).some((d) => d.dtype === 'DISPLAY')));
          setTypes(visible);
          if (visible.length > 0) {
            setDtype(visible[0].dtype);
            setValues(defaultValues(visible[0].inputSchema));
          }
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [row.pluginId, row.deviceId]);

  const selectedType = types.find((t) => t.dtype === dtype) ?? null;

  // Load the picker for the selected type (disk / pci / usb / nic choices).
  useEffect(() => {
    const actionId = selectedType?.choicesActionId;
    if (!actionId || !selectedType) { setChoiceData(null); return; }
    const dtype = selectedType.dtype;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.executePluginAction(row.pluginId, { deviceId: row.deviceId, actionId, input: {} });
        if (!cancelled) setChoiceData(normalizeChoices(dtype, res.details));
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      }
    })();
    return () => { cancelled = true; };
  }, [row.pluginId, row.deviceId, selectedType?.choicesActionId]);

  // CD-ROM source data — repo files + appliance datasets (both cheap reads).
  useEffect(() => {
    if (!selectedType || selectedType.dtype.toUpperCase() !== 'CDROM') return;
    let cancelled = false;
    (async () => {
      try {
        const [filesRes, choicesRes] = await Promise.all([
          api.repoFiles('iso').catch(() => ({ files: [] as FileRepoEntry[] })),
          api.executePluginAction(row.pluginId, { deviceId: row.deviceId, actionId: 'vms.create-choices', input: {} }).catch(() => null),
        ]);
        if (cancelled) return;
        setCdromRepoFiles(Array.isArray(filesRes.files) ? filesRes.files : []);
        const ds = choicesRes?.details.datasets;
        setCdromDatasets(Array.isArray(ds) ? (ds as { name: string; mountpoint: string }[]) : []);
      } catch { /* best-effort — the manual path source still works */ }
    })();
    return () => { cancelled = true; };
  }, [row.pluginId, row.deviceId, selectedType?.dtype]);

  // ISOs of the chosen dataset (vms.iso-choices — read-only).
  const cdromDataset = String(values['dataset'] ?? '');
  useEffect(() => {
    if (!selectedType || selectedType.dtype.toUpperCase() !== 'CDROM' || !cdromDataset) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.executePluginAction(row.pluginId, { deviceId: row.deviceId, actionId: 'vms.iso-choices', input: { dataset: cdromDataset } });
        if (!cancelled) setCdromIsoFiles(Array.isArray(res.details.files) ? (res.details.files as { path: string; name: string; sizeBytes: number | null }[]) : []);
      } catch {
        if (!cancelled) setCdromIsoFiles([]);
      }
    })();
    return () => { cancelled = true; };
  }, [row.pluginId, row.deviceId, selectedType?.dtype, cdromDataset]);

  function pickType(t: VmDeviceTypeDescriptor) {
    setDtype(t.dtype);
    setValues(defaultValues(t.inputSchema));
    setFieldErrors({});
  }

  // Which schema fields are covered by a picker (or don't apply to the current
  // disk/ISO mode) — they are hidden from SchemaForm and excluded from the submit.
  const skippedKeys = useMemo(() => {
    const skip = new Set<string>();
    if (!selectedType) return skip;
    switch (selectedType.dtype.toUpperCase()) {
      case 'PCI': skip.add('pptdev'); break;
      case 'USB': skip.add('usbDevice'); break;
      case 'NIC': skip.add('nicAttach'); break; // covered by the interface picker
      case 'DISK': {
        const m = String(values['mode'] ?? 'existing');
        if (m === 'existing') { skip.add('dataset'); skip.add('sizeBytes'); skip.add('zvolName'); }
        else { skip.add('path'); }
        break;
      }
      case 'CDROM':
        // Every field is driven by the custom source section below (the source
        // select + repo file / dataset / ISO pickers or a manual path).
        skip.add('source'); skip.add('repoFileId'); skip.add('dataset'); skip.add('path');
        break;
    }
    return skip;
  }, [selectedType, values]);

  const formSchema = useMemo(() => {
    if (!selectedType) return {} as InputSchema;
    const out: InputSchema = {};
    for (const [k, p] of Object.entries(selectedType.inputSchema)) if (!skippedKeys.has(k)) out[k] = p;
    return out;
  }, [selectedType, skippedKeys]);

  // The picker's target field key (null = no picker for this type/mode).
  const choiceField = useMemo(() => {
    if (!selectedType || !choiceData) return null;
    switch (selectedType.dtype.toUpperCase()) {
      case 'PCI': return 'pptdev';
      case 'USB': return 'usbDevice';
      case 'NIC': return 'nicAttach';
      case 'DISK': return values['mode'] === 'existing' ? 'path' : null;
      default: return null;
    }
  }, [selectedType, choiceData, values]);

  const needsStopped = selectedType?.requiresStopped === true && !stopped;

  // CD-ROM source completeness — mirrors the old standalone dialog's canSubmit.
  const cdromCanSubmit = useMemo(() => {
    if (!selectedType || selectedType.dtype.toUpperCase() !== 'CDROM') return true;
    const s = String(values['source'] ?? 'repo');
    if (s === 'repo') return !!values['repoFileId'] && !!values['dataset'];
    if (s === 'dataset') return !!cdromIsoPath;
    return cdromManualPath.trim().startsWith('/mnt/');
  }, [selectedType, values, cdromIsoPath, cdromManualPath]);

  async function submit() {
    if (isReadOnly || !selectedType) return; // safety net — the button is disabled
    const errors: Record<string, string> = validateSchema(selectedType.inputSchema, values);
    // Conditional requirements SchemaForm can't express on its own.
    if (choiceField && choiceData && !(values[choiceField] !== undefined && values[choiceField] !== '')) {
      errors[choiceField] = 'Required';
    }
    if (selectedType.dtype === 'DISK' && String(values['mode'] ?? 'existing') === 'new-zvol') {
      if (!values['dataset']) errors['dataset'] = 'Required';
      if (typeof values['sizeBytes'] !== 'number') errors['sizeBytes'] = 'Required';
    }
    // CD-ROM — the source section's pickers are outside SchemaForm, so their
    // requirements are checked here.
    if (selectedType.dtype === 'CDROM' && !cdromCanSubmit) {
      const s = String(values['source'] ?? 'repo');
      if (s === 'repo') {
        if (!values['repoFileId']) errors['repoFileId'] = 'Required';
        if (!values['dataset']) errors['dataset'] = 'Required';
      } else if (s === 'dataset') {
        if (!cdromIsoPath) errors['path'] = 'Select an ISO';
      } else if (!cdromManualPath.trim().startsWith('/mnt/')) {
        errors['path'] = 'Must start with /mnt/';
      }
    }
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return;

    // Only the ACTIVE fields ride along — stale mode-irrelevant values are dropped.
    const input: Record<string, unknown> = { name: row.name };
    for (const k of Object.keys(selectedType.inputSchema)) {
      if (skippedKeys.has(k)) continue;
      const v = values[k];
      if (v !== undefined && v !== '') input[k] = v;
    }
    // CD-ROM — the source section owns its fields, so build them explicitly.
    if (selectedType.dtype === 'CDROM') {
      const s = String(values['source'] ?? 'repo');
      if (s === 'repo') {
        input['repoFileId'] = values['repoFileId'];
        input['dataset'] = values['dataset'];
      } else if (s === 'dataset') {
        input['path'] = cdromIsoPath;
      } else {
        input['path'] = cdromManualPath.trim();
      }
    }

    setSaving(true);
    setError(null);
    const actionId = `vms.${selectedType.dtype.toLowerCase()}-attach`;
    const attempt = async () => {
      await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input }], mode);
      if (isPlanMode) { setSaved(true); return; }
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

  // Plan mode: the plan was saved without executing — offer to close.
  if (saved) {
    return (
      <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
        <div className="mt-8 w-full max-w-md rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
          <header className="flex items-center justify-between border-b border-border px-4 py-3">
            <h2 className="text-base font-semibold text-foreground">Add device — {row.name}</h2>
            <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted"><X size={16} /></button>
          </header>
          <div className="space-y-3 px-4 py-4">
            <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-xs text-success-fg">
              <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
              Device attach saved as a plan — it was NOT executed. Open the Plans center to run it later (or schedule it).
            </div>
          </div>
          <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
            <button type="button" onClick={onClose} className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90">Close</button>
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
            <h2 className="text-base font-semibold text-foreground">Add device — {row.name}</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">Applies via the plan workflow on {row.deviceName ?? row.deviceId}.</p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted"><X size={16} /></button>
        </header>

        <div className="space-y-4 px-4 py-4">
          {isReadOnly && (
            <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
              <EyeOff size={14} className="mt-0.5 shrink-0" />
              Read-only mode is active — this change cannot be saved or applied. Switch to Plan or Execute in the top bar.
            </div>
          )}
          {loading && (
            <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 size={14} className="animate-spin" /> Loading attachable device types…</p>
          )}
          {error && !reauth && (
            <div className="rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
          )}

          {!loading && !error && types.length === 0 && (
            <p className="text-sm text-muted-foreground">This hypervisor does not advertise any attachable device types.</p>
          )}

          {!loading && !error && types.length > 0 && selectedType && (
            <>
              {/* Type picker — one button per advertised dtype. */}
              <div className="flex flex-wrap gap-1.5">
                {types.map((t) => {
                  const blocked = t.requiresStopped && !stopped;
                  return (
                    <button
                      key={t.dtype}
                      type="button"
                      disabled={blocked || isReadOnly}
                      title={blocked ? `Stop the VM first — ${t.label.toLowerCase()} requires a stopped VM` : t.description ?? t.label}
                      onClick={() => pickType(t)}
                      className={clsx(
                        'rounded-md border px-2.5 py-1 text-xs font-medium',
                        t.dtype === dtype ? 'border-primary bg-primary text-primary-fg' : 'border-border bg-background text-secondary hover:bg-muted',
                        (blocked || isReadOnly) && 'cursor-not-allowed opacity-40',
                      )}
                    >
                      {t.label}
                    </button>
                  );
                })}
              </div>

              {/* State / capability warnings for the selected type. */}
              {needsStopped && (
                <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
                  <EyeOff size={14} className="mt-0.5 shrink-0" />
                  {selectedType.label} requires a STOPPED VM — stop “{row.name}” first, then reopen this dialog.
                </div>
              )}
              {selectedType.dtype.toUpperCase() === 'PCI' && choiceData?.iommu === false && (
                <div className="flex items-start gap-2 rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">
                  <EyeOff size={14} className="mt-0.5 shrink-0" />
                  IOMMU is not enabled on this host — PCIe passthrough will not work until it is turned on in the BIOS.
                </div>
              )}

              {/* Picker fed by the type's choices action (disk / pci / usb). */}
              {choiceField && choiceData && (
                <div>
                  <label className="mb-1 block text-xs font-medium text-secondary">
                    {(selectedType.inputSchema[choiceField]?.label) ?? 'Device'}
                  </label>
                  <select
                    value={typeof values[choiceField] === 'string' ? (values[choiceField] as string) : ''}
                    onChange={(e) => {
                      const next: Record<string, unknown> = { ...values, [choiceField]: e.target.value || undefined };
                      // NIC — the attachment kind follows the picked interface (MACVLAN hint).
                      if (selectedType.dtype.toUpperCase() === 'NIC' && e.target.value) {
                        const entry = choiceData.list.find((c) => c.id === e.target.value);
                        next['type'] = entry?.hint === 'MACVLAN' ? 'MACVLAN' : 'BRIDGE';
                      }
                      setValues(next); setFieldErrors({});
                    }}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
                  >
                    <option value="">Select a device…</option>
                    {choiceData.list.map((c) => (
                      <option key={c.id} value={c.id} disabled={c.available === false}>
                        {c.label}{c.hint ? ` — ${c.hint}` : ''}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* CD-ROM source section — repo file / existing ISO / manual path. */}
              {selectedType.dtype.toUpperCase() === 'CDROM' && (
                <div className="space-y-3">
                  <div>
                    <label className="mb-1 block text-xs font-medium text-secondary">ISO source</label>
                    <select value={String(values['source'] ?? 'repo')} onChange={(e) => { setValues({ ...values, source: e.target.value }); setCdromIsoPath(''); setCdromManualPath(''); setFieldErrors({}); }}
                      className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                      <option value="repo">From UNM file repo (Files page)</option>
                      <option value="dataset">Existing ISO on the appliance</option>
                      <option value="path">Manual path (/mnt/…)</option>
                    </select>
                  </div>

                  {String(values['source'] ?? 'repo') === 'repo' && (
                    <>
                      <div>
                        <label className="mb-1 block text-xs font-medium text-secondary">File from repo</label>
                        <select value={typeof values['repoFileId'] === 'string' ? (values['repoFileId'] as string) : ''} onChange={(e) => { setValues({ ...values, repoFileId: e.target.value || undefined }); setFieldErrors({}); }}
                          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                          <option value="">Select a file…</option>
                          {cdromRepoFiles.map((f) => (
                            <option key={f.id} value={f.id}>{f.name} ({formatBytes(f.sizeBytes)})</option>
                          ))}
                        </select>
                        {fieldErrors['repoFileId'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['repoFileId']}</p>}
                        {cdromRepoFiles.length === 0 && (
                          <p className="mt-1 text-xs text-faint">No files in the repo yet — upload an ISO on the Files page first.</p>
                        )}
                      </div>
                      <div>
                        <label className="mb-1 block text-xs font-medium text-secondary">Target dataset</label>
                        <select value={typeof values['dataset'] === 'string' ? (values['dataset'] as string) : ''} onChange={(e) => { setValues({ ...values, dataset: e.target.value || undefined }); setCdromIsoPath(''); setFieldErrors({}); }}
                          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                          <option value="">Select a dataset…</option>
                          {cdromDatasets.map((d) => (
                            <option key={d.name} value={d.name}>{d.name}</option>
                          ))}
                        </select>
                        {fieldErrors['dataset'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['dataset']}</p>}
                        <p className="mt-1 text-xs text-faint">The ISO is streamed onto the appliance when missing, then attached.</p>
                      </div>
                    </>
                  )}

                  {String(values['source'] ?? 'repo') === 'dataset' && (
                    <>
                      <div>
                        <label className="mb-1 block text-xs font-medium text-secondary">Dataset</label>
                        <select value={cdromDataset} onChange={(e) => { setValues({ ...values, dataset: e.target.value || undefined }); setCdromIsoPath(''); setFieldErrors({}); }}
                          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                          <option value="">Select a dataset…</option>
                          {cdromDatasets.map((d) => (
                            <option key={d.name} value={d.name}>{d.name}</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="mb-1 block text-xs font-medium text-secondary">ISO</label>
                        <select value={cdromIsoPath} onChange={(e) => { setCdromIsoPath(e.target.value); setFieldErrors({}); }} disabled={!cdromDataset}
                          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground disabled:opacity-50">
                          <option value="">Select an ISO…</option>
                          {cdromIsoFiles.map((f) => (
                            <option key={f.path} value={f.path}>{f.name}{f.sizeBytes != null ? ` (${formatBytes(f.sizeBytes)})` : ''}</option>
                          ))}
                        </select>
                        {fieldErrors['path'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['path']}</p>}
                      </div>
                    </>
                  )}

                  {String(values['source'] ?? 'repo') === 'path' && (
                    <div>
                      <label className="mb-1 block text-xs font-medium text-secondary">ISO path</label>
                      <input type="text" value={cdromManualPath} onChange={(e) => { setCdromManualPath(e.target.value); setFieldErrors({}); }} placeholder="/mnt/POOL/VM/debian.iso"
                        className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint" />
                      {fieldErrors['path'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['path']}</p>}
                    </div>
                  )}
                </div>
              )}

              {/* The type's form fields, rendered generically from its inputSchema. */}
              {selectedType.dtype.toUpperCase() !== 'CDROM' && (
                <SchemaForm schema={formSchema} values={values} onChange={(v) => { setValues(v); setFieldErrors({}); }} fieldErrors={fieldErrors} />
              )}
            </>
          )}
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={!selectedType || saving || isReadOnly || needsStopped}
            title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : needsStopped ? 'Stop the VM first' : undefined}
            onClick={() => void submit()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving && <Loader2 size={12} className="animate-spin" />}
            {isPlanMode ? 'Save as plan' : selectedType ? `Attach ${selectedType.label}` : 'Attach'}
          </button>
        </footer>

        {reauth && (
          <ReauthDialog
            contextLabel={`Add device to ${row.name}`}
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
// Edit-device dialog — generic over the plugin's vms.device-types descriptors:
// the form is rendered from the type's `editInputSchema` (the subset of fields
// changeable in place), prefilled via vms.device-get, and submitted as a
// partial-merge vms.device-update through the plan workflow. A future hypervisor
// plugin implementing those ids + descriptor fields gets this dialog for free.
// ---------------------------------------------------------------------------

function EditDeviceDialog({ target, stopped, onClose }: { target: DeviceEditTarget; stopped: boolean; onClose: () => void }) {
  const { mode } = useExecutionMode();
  const isPlanMode = mode === 'plan';
  const isReadOnly = mode === 'readonly';
  const row = target.row;

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [descriptor, setDescriptor] = useState<VmDeviceTypeDescriptor | null>(null);
  const [values, setValues] = useState<Record<string, unknown>>({});
  /** The values vms.device-get reported — the diff baseline for submit. */
  const [originals, setOriginals] = useState<Record<string, unknown>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [choiceData, setChoiceData] = useState<{ list: VmDeviceChoice[]; iommu?: boolean } | null>(null);
  // CD-ROM ISO source data (same sources as the attach dialog). The manual path
  // itself lives in values['path'] — prefilled with the device's current ISO.
  const [cdromRepoFiles, setCdromRepoFiles] = useState<FileRepoEntry[]>([]);
  const [cdromDatasets, setCdromDatasets] = useState<{ name: string; mountpoint: string }[]>([]);
  const [cdromIsoFiles, setCdromIsoFiles] = useState<{ path: string; name: string; sizeBytes: number | null }[]>([]);
  const [cdromIsoPath, setCdromIsoPath] = useState('');
  const [saving, setSaving] = useState(false);
  const [reauth, setReauth] = useState(false);
  // Plan mode: the edit plan was saved without executing.
  const [saved, setSaved] = useState(false);

  // Load the descriptor for this dtype + the device's current values (prefill).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await api.executePluginAction(row.pluginId, { deviceId: row.deviceId, actionId: 'vms.device-types', input: {} });
        if (cancelled) return;
        const raw = Array.isArray(res.details.types) ? (res.details.types as VmDeviceTypeDescriptor[]) : [];
        const t = raw.find((x) => x.dtype.toUpperCase() === target.dtype.toUpperCase()) ?? null;
        setDescriptor(t);
        if (!t?.editInputSchema) return; // nothing editable — the message below explains why
        const getRes = await api.executePluginAction(row.pluginId, { deviceId: row.deviceId, actionId: 'vms.device-get', input: { name: row.name, deviceId: target.devId } });
        if (cancelled) return;
        const vals = (getRes.details.values && typeof getRes.details.values === 'object' ? getRes.details.values : {}) as Record<string, unknown>;
        setOriginals(vals);
        // Prefill — schema defaults first, then the appliance's current values.
        const merged: Record<string, unknown> = defaultValues(t.editInputSchema);
        for (const [k, v] of Object.entries(vals)) if (v !== undefined && v !== '') merged[k] = v;
        setValues(merged);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [row.pluginId, row.deviceId, row.name, target.devId, target.dtype]);

  const isCdrom = descriptor?.dtype.toUpperCase() === 'CDROM';
  const cdromDataset = String(values['dataset'] ?? '');

  // NIC picker (same choices action as the attach dialog).
  useEffect(() => {
    if (!descriptor || !descriptor.choicesActionId) return;
    const choicesActionId = descriptor.choicesActionId;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.executePluginAction(row.pluginId, { deviceId: row.deviceId, actionId: choicesActionId, input: {} });
        if (!cancelled) setChoiceData(normalizeChoices(descriptor.dtype, res.details));
      } catch { /* picker is optional — manual entry still works */ }
    })();
    return () => { cancelled = true; };
  }, [row.pluginId, row.deviceId, descriptor?.choicesActionId, descriptor?.dtype]);

  // CD-ROM source data (repo files + appliance datasets).
  useEffect(() => {
    if (!isCdrom) return;
    let cancelled = false;
    (async () => {
      try {
        const [filesRes, choicesRes] = await Promise.all([
          api.repoFiles('iso').catch(() => ({ files: [] as FileRepoEntry[] })),
          api.executePluginAction(row.pluginId, { deviceId: row.deviceId, actionId: 'vms.create-choices', input: {} }).catch(() => null),
        ]);
        if (cancelled) return;
        setCdromRepoFiles(Array.isArray(filesRes.files) ? filesRes.files : []);
        const ds = choicesRes?.details.datasets;
        setCdromDatasets(Array.isArray(ds) ? (ds as { name: string; mountpoint: string }[]) : []);
      } catch { /* best-effort — the manual path source still works */ }
    })();
    return () => { cancelled = true; };
  }, [row.pluginId, row.deviceId, isCdrom]);

  // ISOs of the chosen dataset.
  useEffect(() => {
    if (!isCdrom || !cdromDataset) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.executePluginAction(row.pluginId, { deviceId: row.deviceId, actionId: 'vms.iso-choices', input: { dataset: cdromDataset } });
        if (!cancelled) setCdromIsoFiles(Array.isArray(res.details.files) ? (res.details.files as { path: string; name: string; sizeBytes: number | null }[]) : []);
      } catch {
        if (!cancelled) setCdromIsoFiles([]);
      }
    })();
    return () => { cancelled = true; };
  }, [row.pluginId, row.deviceId, isCdrom, cdromDataset]);

  const editSchema = descriptor?.editInputSchema ?? ({} as InputSchema);

  // Fields covered by the NIC picker or the CDROM source section — hidden from SchemaForm.
  const skippedKeys = useMemo(() => {
    const skip = new Set<string>();
    if (!descriptor) return skip;
    if (descriptor.dtype.toUpperCase() === 'NIC') skip.add('nicAttach'); // covered by the interface picker
    if (isCdrom) { skip.add('source'); skip.add('repoFileId'); skip.add('dataset'); skip.add('path'); }
    return skip;
  }, [descriptor, isCdrom]);

  const formSchema = useMemo(() => {
    const out: InputSchema = {};
    for (const [k, p] of Object.entries(editSchema)) if (!skippedKeys.has(k)) out[k] = p;
    return out;
  }, [editSchema, skippedKeys]);

  // The CDROM source section's completeness — mirrors the attach dialog.
  const cdromCanSubmit = useMemo(() => {
    if (!isCdrom) return true;
    const s = String(values['source'] ?? 'path');
    if (s === 'repo') return !!values['repoFileId'] && !!values['dataset'];
    if (s === 'dataset') return !!cdromIsoPath;
    // source 'path' — the manual input is bound to values['path'] (prefilled with the current ISO).
    return String(values['path'] ?? '').trim().startsWith('/mnt/');
  }, [isCdrom, values, cdromIsoPath]);

  // Only CHANGED fields ride along — the appliance merges, so unchanged keys are omitted.
  const changedKeys = useMemo(() => {
    if (!descriptor) return [];
    const out: string[] = [];
    for (const k of Object.keys(editSchema)) {
      const v = values[k];
      const o = originals[k];
      if (v === undefined || v === '') continue; // empty = "keep current"
      if (String(v) !== String(o ?? '')) out.push(k);
    }
    return out;
  }, [descriptor, editSchema, values, originals]);

  const needsStopped = descriptor?.requiresStopped === true && !stopped;

  async function submit() {
    if (isReadOnly || !descriptor) return; // safety net — the button is disabled
    const errors: Record<string, string> = validateSchema(editSchema, values);
    if (isCdrom && !cdromCanSubmit) {
      const s = String(values['source'] ?? 'path');
      if (s === 'repo') {
        if (!values['repoFileId']) errors['repoFileId'] = 'Required';
        if (!values['dataset']) errors['dataset'] = 'Required';
      } else if (s === 'dataset') {
        if (!cdromIsoPath) errors['path'] = 'Select an ISO';
      } else if (!String(values['path'] ?? '').trim().startsWith('/mnt/')) {
        errors['path'] = 'Must start with /mnt/';
      }
    }
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return;

    // Build the fields payload — only what actually changed.
    const fields: Record<string, unknown> = {};
    for (const k of changedKeys) {
      if (skippedKeys.has(k)) continue; // picker/section-owned — handled below
      fields[k] = values[k];
    }
    if (isCdrom) {
      const s = String(values['source'] ?? 'path');
      if (s === 'repo') { fields['repoFileId'] = values['repoFileId']; fields['dataset'] = values['dataset']; }
      else if (s === 'dataset') { fields['path'] = cdromIsoPath; }
      else { fields['path'] = String(values['path'] ?? '').trim(); }
    } else if (descriptor.choicesActionId === 'vms.nic-choices') {
      // The NIC picker owns nicAttach — include it only when it actually changed.
      const v = values['nicAttach'];
      if (typeof v === 'string' && v !== '' && String(v) !== String(originals['nicAttach'] ?? '')) fields['nicAttach'] = v;
    }

    setSaving(true);
    setError(null);
    const attempt = async () => {
      await createAndExecutePlan(row.pluginId, 'vms.device-update', [{ deviceId: row.deviceId, input: { name: row.name, deviceId: target.devId, fields } }], mode);
      if (isPlanMode) { setSaved(true); return; }
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

  // Plan mode: the plan was saved without executing — offer to close.
  if (saved) {
    return (
      <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
        <div className="mt-8 w-full max-w-md rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
          <header className="flex items-center justify-between border-b border-border px-4 py-3">
            <h2 className="text-base font-semibold text-foreground">Edit device — {row.name}</h2>
            <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted"><X size={16} /></button>
          </header>
          <div className="space-y-3 px-4 py-4">
            <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-xs text-success-fg">
              <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
              Device edit saved as a plan — it was NOT executed. Open the Plans center to run it later (or schedule it).
            </div>
          </div>
          <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
            <button type="button" onClick={onClose} className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90">Close</button>
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
            <h2 className="text-base font-semibold text-foreground">Edit {descriptor?.label ?? target.dtype.toLowerCase()} — {row.name}</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">Unchanged fields keep their current value; applies via the plan workflow on {row.deviceName ?? row.deviceId}.</p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted"><X size={16} /></button>
        </header>

        <div className="space-y-4 px-4 py-4">
          {isReadOnly && (
            <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
              <EyeOff size={14} className="mt-0.5 shrink-0" />
              Read-only mode is active — this change cannot be saved or applied. Switch to Plan or Execute in the top bar.
            </div>
          )}
          {loading && (
            <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 size={14} className="animate-spin" /> Loading current device values…</p>
          )}
          {error && !reauth && (
            <div className="rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
          )}

          {!loading && !error && descriptor && !descriptor.editInputSchema && (
            <p className="text-sm text-muted-foreground">
              {descriptor.label ?? target.dtype.toLowerCase()} devices cannot be edited in place on this hypervisor — detach the device and attach a new one instead.
            </p>
          )}

          {!loading && !error && descriptor?.editInputSchema && (
            <>
              {needsStopped && (
                <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
                  <EyeOff size={14} className="mt-0.5 shrink-0" />
                  Editing this device requires a STOPPED VM — stop “{row.name}” first, then reopen this dialog.
                </div>
              )}

              {/* NIC picker (bridge / MACVLAN) when the type advertises one. */}
              {descriptor.choicesActionId === 'vms.nic-choices' && choiceData && (
                <div>
                  <label className="mb-1 block text-xs font-medium text-secondary">Interface (bridge / MACVLAN)</label>
                  <select
                    value={typeof values['nicAttach'] === 'string' ? (values['nicAttach'] as string) : ''}
                    onChange={(e) => { setValues({ ...values, nicAttach: e.target.value || undefined }); setFieldErrors({}); }}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
                  >
                    <option value="">Select an interface…</option>
                    {choiceData.list.map((c) => (
                      <option key={c.id} value={c.id}>{c.label}{c.hint ? ` — ${c.hint}` : ''}</option>
                    ))}
                  </select>
                </div>
              )}

              {/* CD-ROM ISO source section — same sources as the attach dialog. */}
              {isCdrom && (
                <div className="space-y-3">
                  <div>
                    <label className="mb-1 block text-xs font-medium text-secondary">ISO source</label>
                    <select value={String(values['source'] ?? 'path')} onChange={(e) => { setValues({ ...values, source: e.target.value }); setCdromIsoPath(''); setFieldErrors({}); }}
                      className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                      <option value="path">Existing ISO on the appliance</option>
                      <option value="repo">From UNM file repo (Files page)</option>
                      <option value="dataset">Pick from a dataset</option>
                    </select>
                  </div>

                  {String(values['source'] ?? 'path') === 'path' && (
                    <div>
                      <label className="mb-1 block text-xs font-medium text-secondary">ISO path</label>
                      <input type="text" value={typeof values['path'] === 'string' ? (values['path'] as string) : ''} onChange={(e) => { setValues({ ...values, path: e.target.value }); setFieldErrors({}); }} placeholder="/mnt/POOL/VM/debian.iso"
                        className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint" />
                      {fieldErrors['path'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['path']}</p>}
                    </div>
                  )}

                  {String(values['source'] ?? 'path') === 'repo' && (
                    <>
                      <div>
                        <label className="mb-1 block text-xs font-medium text-secondary">File from repo</label>
                        <select value={typeof values['repoFileId'] === 'string' ? (values['repoFileId'] as string) : ''} onChange={(e) => { setValues({ ...values, repoFileId: e.target.value || undefined }); setFieldErrors({}); }}
                          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                          <option value="">Select a file…</option>
                          {cdromRepoFiles.map((f) => (
                            <option key={f.id} value={f.id}>{f.name} ({formatBytes(f.sizeBytes)})</option>
                          ))}
                        </select>
                        {fieldErrors['repoFileId'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['repoFileId']}</p>}
                      </div>
                      <div>
                        <label className="mb-1 block text-xs font-medium text-secondary">Target dataset</label>
                        <select value={typeof values['dataset'] === 'string' ? (values['dataset'] as string) : ''} onChange={(e) => { setValues({ ...values, dataset: e.target.value || undefined }); setCdromIsoPath(''); setFieldErrors({}); }}
                          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                          <option value="">Select a dataset…</option>
                          {cdromDatasets.map((d) => (
                            <option key={d.name} value={d.name}>{d.name}</option>
                          ))}
                        </select>
                        {fieldErrors['dataset'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['dataset']}</p>}
                      </div>
                    </>
                  )}

                  {String(values['source'] ?? 'path') === 'dataset' && (
                    <>
                      <div>
                        <label className="mb-1 block text-xs font-medium text-secondary">Dataset</label>
                        <select value={cdromDataset} onChange={(e) => { setValues({ ...values, dataset: e.target.value || undefined }); setCdromIsoPath(''); setFieldErrors({}); }}
                          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                          <option value="">Select a dataset…</option>
                          {cdromDatasets.map((d) => (
                            <option key={d.name} value={d.name}>{d.name}</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="mb-1 block text-xs font-medium text-secondary">ISO</label>
                        <select value={cdromIsoPath} onChange={(e) => { setCdromIsoPath(e.target.value); setFieldErrors({}); }} disabled={!cdromDataset}
                          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground disabled:opacity-50">
                          <option value="">Select an ISO…</option>
                          {cdromIsoFiles.map((f) => (
                            <option key={f.path} value={f.path}>{f.name}{f.sizeBytes != null ? ` (${formatBytes(f.sizeBytes)})` : ''}</option>
                          ))}
                        </select>
                        {fieldErrors['path'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['path']}</p>}
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* The type's editable fields, rendered generically from editInputSchema. */}
              {!isCdrom && (
                <SchemaForm schema={formSchema} values={values} onChange={(v) => { setValues(v); setFieldErrors({}); }} fieldErrors={fieldErrors} />
              )}

              {changedKeys.length === 0 && !isReadOnly && (
                <p className="text-xs text-faint">No changes yet — adjust a field above to enable saving.</p>
              )}
            </>
          )}
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={!descriptor?.editInputSchema || saving || isReadOnly || needsStopped || changedKeys.length === 0 || (isCdrom && !cdromCanSubmit)}
            title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : needsStopped ? 'Stop the VM first' : undefined}
            onClick={() => void submit()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving && <Loader2 size={12} className="animate-spin" />}
            {isPlanMode ? 'Save as plan' : `Edit ${descriptor?.label ?? 'device'}`}
          </button>
        </footer>

        {reauth && (
          <ReauthDialog
            contextLabel={`Edit device on ${row.name}`}
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
// Edit-VM dialog — generic over the plugin's vms.vm-edit-schema field catalog:
// the form is rendered from that catalog (name/description/autostart/boot
// method/system clock/NUMA/CPU pinning/topology/memory), prefilled via
// vms.vm-get, and submitted as a partial-merge vms.vm-update through the plan
// workflow. A future hypervisor plugin implementing those ids gets this dialog
// for free — same contract as EditDeviceDialog, one level up (the VM itself).
// ---------------------------------------------------------------------------

/** One editable VM-level field as advertised in vms.vm-edit-schema details.fields[]. */
interface VmEditField {
  key: string;
  label: string;
  description?: string;
  type: 'string' | 'number' | 'boolean';
  required?: boolean;
  default?: unknown;
  enum?: (string | number)[];
  min?: number;
  max?: number;
  pattern?: string;
  /** True when the appliance only accepts this change while the VM is inactive. */
  requiresStopped: boolean;
  /** Optional strings where '' is a real value (clears the setting), not "keep current". */
  clearable?: boolean;
}

function EditVmDialog({ row, stopped, onClose }: { row: VmRow; stopped: boolean; onClose: () => void }) {
  const { mode } = useExecutionMode();
  const isPlanMode = mode === 'plan';
  const isReadOnly = mode === 'readonly';

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [fields, setFields] = useState<VmEditField[]>([]);
  const [values, setValues] = useState<Record<string, unknown>>({});
  /** The values vms.vm-get reported — the diff baseline for submit. */
  const [originals, setOriginals] = useState<Record<string, unknown>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [reauth, setReauth] = useState(false);
  // Plan mode: the edit plan was saved without executing.
  const [saved, setSaved] = useState(false);

  // Load the field catalog + the VM's current values (prefill).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await api.executePluginAction(row.pluginId, { deviceId: row.deviceId, actionId: 'vms.vm-edit-schema', input: {} });
        if (cancelled) return;
        const raw = Array.isArray(res.details.fields) ? (res.details.fields as VmEditField[]) : [];
        setFields(raw);
        const getRes = await api.executePluginAction(row.pluginId, { deviceId: row.deviceId, actionId: 'vms.vm-get', input: { name: row.name } });
        if (cancelled) return;
        const vals = (getRes.details.values && typeof getRes.details.values === 'object' ? getRes.details.values : {}) as Record<string, unknown>;
        setOriginals(vals);
        // Prefill — schema defaults first, then the appliance's current values.
        const merged: Record<string, unknown> = {};
        for (const f of raw) if (f.default !== undefined) merged[f.key] = f.default;
        for (const [k, v] of Object.entries(vals)) {
          // '' is a REAL value for clearable fields (cleared setting) — keep it.
          const field = raw.find((x) => x.key === k);
          if (v !== undefined && (field?.clearable || v !== '')) merged[k] = v;
        }
        setValues(merged);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [row.pluginId, row.deviceId, row.name]);

  // Only CHANGED fields ride along — the appliance merges, so unchanged keys are omitted.
  const changedKeys = useMemo(() => {
    const out: string[] = [];
    for (const f of fields) {
      const v = values[f.key];
      const o = originals[f.key];
      if (f.clearable) {
        // '' is a real value here — clearing the setting counts as a change.
        // Numbers compare via String() so 0 vs '0' and '' vs null don't false-positive.
        if (String(v ?? '') !== String(o ?? '')) out.push(f.key);
        continue;
      }
      if (v === undefined || v === null || v === '') continue; // empty = "keep current"
      if (String(v) !== String(o ?? '')) out.push(f.key);
    }
    return out;
  }, [fields, values, originals]);

  const fieldByKey = useMemo(() => new Map(fields.map((f) => [f.key, f])), [fields]);
  // A changed requiresStopped field (the name) on a non-stopped VM blocks saving.
  const needsStopped = !stopped && changedKeys.some((k) => fieldByKey.get(k)?.requiresStopped === true);
  // Appliance rule — strict vCPU pinning needs a cpuset covering every vCPU.
  const pinVcpusBroken = values['pinVcpus'] === true && String(values['cpuset'] ?? '') === '';

  async function submit() {
    if (isReadOnly || needsStopped) return; // safety net — the button is disabled
    const errors: Record<string, string> = {};
    for (const f of fields) {
      const v = values[f.key];
      if (f.clearable) {
        // '' clears the setting — a real value, nothing to validate. Non-empty
        // values still get their type validation.
        if (v === '') continue;
        if (f.type === 'number') {
          const n = typeof v === 'string' ? Number(v) : v;
          if (typeof n !== 'number' || !Number.isFinite(n)) errors[f.key] = 'Must be a number';
          else if (f.min !== undefined && n < f.min) errors[f.key] = `Must be >= ${f.min}`;
        } else if (typeof v === 'string' && f.pattern) {
          try { if (!new RegExp(f.pattern).test(v)) errors[f.key] = `Invalid format — e.g. "0", "1" or "0-3"`; } catch { /* ignore */ }
        }
        continue;
      }
      if (v === undefined || v === null || v === '') {
        if (f.required) errors[f.key] = 'Required';
        continue;
      }
      if (f.type === 'number') {
        // Clearable numbers: '' is a real value (clears the setting), not "empty".
        if (f.clearable && v === '') continue;
        const n = typeof v === 'string' ? Number(v) : v;
        if (typeof n !== 'number' || !Number.isFinite(n)) errors[f.key] = 'Must be a number';
        else if (f.min !== undefined && n < f.min) errors[f.key] = `Must be >= ${f.min}`;
        else if (f.max !== undefined && n > f.max) errors[f.key] = `Must be <= ${f.max}`;
      } else if (typeof v === 'string' && f.pattern) {
        try { if (!new RegExp(f.pattern).test(v)) errors[f.key] = `Does not match pattern ${f.pattern}`; } catch { /* ignore */ }
      }
    }
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return;

    const fieldsPayload: Record<string, unknown> = {};
    for (const k of changedKeys) fieldsPayload[k] = values[k];

    setSaving(true);
    setError(null);
    const attempt = async () => {
      await createAndExecutePlan(row.pluginId, 'vms.vm-update', [{ deviceId: row.deviceId, input: { name: row.name, fields: fieldsPayload } }], mode);
      if (isPlanMode) { setSaved(true); return; }
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

  // Plan mode: the plan was saved without executing — offer to close.
  if (saved) {
    return (
      <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
        <div className="mt-8 w-full max-w-md rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
          <header className="flex items-center justify-between border-b border-border px-4 py-3">
            <h2 className="text-base font-semibold text-foreground">Edit VM — {row.name}</h2>
            <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted"><X size={16} /></button>
          </header>
          <div className="space-y-3 px-4 py-4">
            <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-xs text-success-fg">
              <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
              VM edit saved as a plan — it was NOT executed. Open the Plans center to run it later (or schedule it).
            </div>
          </div>
          <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
            <button type="button" onClick={onClose} className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90">Close</button>
          </footer>
        </div>
      </div>
    );
  }

  /** Renders ONE catalog field (same styling as SchemaForm) — clearable strings keep '' as a real value. */
  function renderField(f: VmEditField) {
    const v = values[f.key];
    const set = (val: unknown) => { setValues({ ...values, [f.key]: val }); setFieldErrors({}); };
    return (
      <div key={f.key}>
        <label className="mb-1 flex items-center gap-2 text-sm font-medium text-secondary">
          {f.label}
          {f.required && !f.clearable && <span className="text-danger-fg">*</span>}
        </label>
        {f.description && <p className="mb-1 text-xs text-faint">{f.description}</p>}
        {f.enum && f.enum.length > 0 ? (
          <select value={v === undefined || v === null ? '' : String(v)} onChange={(e) => set(e.target.value === '' ? undefined : e.target.value)}
            className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm focus:border-focus-ring focus:ring-1 focus:ring-focus-ring">
            <option value="" disabled>— select —</option>
            {f.enum.map((opt) => (<option key={String(opt)} value={String(opt)}>{String(opt)}</option>))}
          </select>
        ) : f.type === 'boolean' ? (
          <div className="flex items-center gap-2">
            <input type="checkbox" checked={v === true} onChange={(e) => set(e.target.checked)}
              className="h-4 w-4 rounded border-border text-foreground focus:ring-focus-ring" />
            <span className="text-sm text-muted-foreground">{v === true ? 'Enabled' : 'Disabled'}</span>
          </div>
        ) : f.type === 'number' ? (
          <input type="number" step="any" inputMode="decimal" value={v === undefined || v === null ? '' : String(v)}
            onChange={(e) => set(e.target.value === '' ? (f.clearable ? '' : undefined) : Number(e.target.value))}
            className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm focus:border-focus-ring focus:ring-1 focus:ring-focus-ring" />
        ) : (
          <input type="text" value={v === undefined || v === null ? '' : String(v)}
            onChange={(e) => set(f.clearable ? e.target.value : (e.target.value === '' ? undefined : e.target.value))}
            className={`w-full rounded-md border border-border px-2.5 py-1.5 text-sm focus:border-focus-ring focus:ring-1 focus:ring-focus-ring ${f.key === 'nodeset' || f.key === 'cpuset' ? 'font-mono' : ''}`} />
        )}
        {fieldErrors[f.key] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors[f.key]}</p>}
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      <div className="mt-8 w-full max-w-md rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">Edit VM — {row.name}</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">Unchanged fields keep their current value; applies via the plan workflow on {row.deviceName ?? row.deviceId}. Most changes take effect at the guest's next boot.</p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted"><X size={16} /></button>
        </header>

        <div className="space-y-4 px-4 py-4">
          {isReadOnly && (
            <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
              <EyeOff size={14} className="mt-0.5 shrink-0" />
              Read-only mode is active — this change cannot be saved or applied. Switch to Plan or Execute in the top bar.
            </div>
          )}
          {loading && (
            <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 size={14} className="animate-spin" /> Loading current VM settings…</p>
          )}
          {error && !reauth && (
            <div className="rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
          )}

          {!loading && !error && fields.length > 0 && (
            <>
              {needsStopped && (
                <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
                  <EyeOff size={14} className="mt-0.5 shrink-0" />
                  Renaming requires a STOPPED VM — stop “{row.name}” first, then reopen this dialog. (All other fields can be changed in any state.)
                </div>
              )}

              {pinVcpusBroken && (
                <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
                  <EyeOff size={14} className="mt-0.5 shrink-0" />
                  Pin vCPUs requires a CPU pinning (cpuset) — set it to one host CPU per vCPU, or untick the option.
                </div>
              )}

              {fields.map(renderField)}

              {changedKeys.length === 0 && !isReadOnly && (
                <p className="text-xs text-faint">No changes yet — adjust a field above to enable saving.</p>
              )}
            </>
          )}
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={saving || isReadOnly || needsStopped || pinVcpusBroken || changedKeys.length === 0}
            title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : needsStopped ? 'Stop the VM first (renaming requires it)' : pinVcpusBroken ? 'Set a cpuset for Pin vCPUs, or untick it' : undefined}
            onClick={() => void submit()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving && <Loader2 size={12} className="animate-spin" />}
            {isPlanMode ? 'Save as plan' : 'Edit VM'}
          </button>
        </footer>

        {reauth && (
          <ReauthDialog
            contextLabel={`Edit VM ${row.name}`}
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
  const { formatDateTime } = useTimeFormat();
  // Global Execute/Plan mode — decides whether page actions run immediately or
  // are saved as (unexecuted) plans for later execution/scheduling.
  const { mode } = useExecutionMode();

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

  // --- Live VM probe (3s cadence, 'vmStates' + 'vmStats' keys via virsh) ------
  // Fresh plugins report real libvirt states; the State badge flips in ~3 s
  // after a start/stop instead of waiting for the next inventory poll. The same
  // poll also carries per-VM LIVE CPU utilization (virsh domstats cpu.time
  // deltas, computed plugin-side) for the CPU% column.
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  // Devices feed the Create-VM target picker (hypervisor devices with a plugin
  // that advertises vms.create).
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices, refetchInterval: 60_000 });
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
      queryKey: ['device-probe', t.deviceId, 'vmStates+vmStats'],
      queryFn: () => api.deviceProbe(t.deviceId, ['vmStates', 'vmStats'], t.pluginId),
      refetchInterval: 3_000,
      // Same rationale as the Containers page probe — no retry storm on a
      // short-cycle poll; the next tick retries and stale data is kept.
      retry: false,
      staleTime: 0,
      gcTime: 30_000,
    })),
  });

  // deviceId|pluginId → { at, states: guest name → normalized state,
  // stats: guest name → live CPU stat }. A failed poll keeps serving the last
  // good snapshot (react-query retains data).
  const liveVmStatesByDevice = useMemo(() => {
    const m = new Map<string, { at: number; states: Record<string, string>; stats: Record<string, { cpuPct?: number; vcpus?: number }> }>();
    probeTargets.forEach((t, i) => {
      const res = probeResults[i];
      if (!res?.data) return;
      const rawStates = res.data.probe.metrics['vmStates'];
      if (!rawStates || typeof rawStates !== 'object') return;
      const states: Record<string, string> = {};
      for (const [name, entry] of Object.entries(rawStates as Record<string, unknown>)) {
        const s = typeof entry === 'string' ? entry : (entry && typeof entry === 'object' && typeof (entry as Record<string, unknown>).status === 'string') ? String((entry as Record<string, unknown>).status) : '';
        if (s) states[name] = normalizeVmState(s);
      }
      // vmStats is optional — older plugins don't serve it; the CPU% column
      // simply stays "—" until a fresh plugin version is deployed.
      const rawStats = res.data.probe.metrics['vmStats'];
      const stats: Record<string, { cpuPct?: number; vcpus?: number }> = {};
      if (rawStats && typeof rawStats === 'object') {
        for (const [name, entry] of Object.entries(rawStats as Record<string, unknown>)) {
          if (!entry || typeof entry !== 'object') continue;
          const o = entry as Record<string, unknown>;
          stats[name] = {
            cpuPct: typeof o['cpuPct'] === 'number' ? (o['cpuPct'] as number) : undefined,
            vcpus: typeof o['vcpus'] === 'number' ? (o['vcpus'] as number) : undefined,
          };
        }
      }
      m.set(`${t.deviceId}|${t.pluginId}`, { at: Date.parse(res.data.probe.collectedAt) || Date.now(), states, stats });
    });
    return m;
  }, [probeTargets, probeResults]);

  /** Fresh (≤30 s) live state for one VM — null when the probe has no recent data. */
  function freshLiveState(deviceId: string, pluginId: string, name: string): string | null {
    const e = liveVmStatesByDevice.get(`${deviceId}|${pluginId}`);
    if (!e || Date.now() - e.at > 30_000) return null;
    return e.states[name] ?? null;
  }

  /** Fresh (≤30 s) live CPU stat for one VM — null when the probe has no recent data. */
  function freshLiveCpu(deviceId: string, pluginId: string, name: string): { cpuPct?: number; vcpus?: number } | null {
    const e = liveVmStatesByDevice.get(`${deviceId}|${pluginId}`);
    if (!e || Date.now() - e.at > 30_000) return null;
    return e.stats[name] ?? null;
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
      if (mode === 'readonly') { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input: { names: [row.name] } }], mode);
      if (mode === 'plan') {
        setNotice({ kind: 'ok', text: `${label} ${row.name}: saved as a plan — not executed. Open the Plans center to run it later.` });
        return;
      }
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
        if (mode === 'readonly') { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
        let savedCount = 0;
        for (const g of Array.from(groupByDevice(vms.map((n) => n.row!), (r) => ({ pluginId: r.pluginId, deviceId: r.deviceId }), (r) => r.name).values())) {
          const planId = await createAndExecutePlan(g.pluginId, actionId, [{ deviceId: g.deviceId, input: { names: g.values } }], mode);
          if (mode === 'plan') {
            savedCount += 1;
            continue;
          }
          trackPlan(planId, [g.deviceId]);
        }
        if (mode === 'plan' && savedCount > 0) {
          setNotice({ kind: 'ok', text: `${label}: ${savedCount} plan${savedCount === 1 ? '' : 's'} saved without executing — open the Plans center to run them later.` });
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

  // --- Create VM dialog -----------------------------------------------------------
  const [createOpen, setCreateOpen] = useState(false);

  // Hypervisor devices that advertise vms.create — the top-bar Create button is
  // GENERIC: one entry per (device, plugin) pair. The dialog itself carries the
  // appliance picker for multi-appliance fleets.
  const createTargets = useMemo(() => {
    const out: CreateVmTarget[] = [];
    for (const d of devicesQuery.data ?? []) {
      for (const a of d.plugins ?? []) {
        if (a.pluginId && hasAction(a.pluginId, 'vms.create')) out.push({ device: d, pluginId: a.pluginId });
      }
    }
    return out;
  }, [devicesQuery.data]); // eslint-disable-line react-hooks/exhaustive-deps

  function openCreate() {
    if (createTargets.length === 0) return;
    setCreateOpen(true);
  }

  // --- Device attach / edit / detach ------------------------------------------------
  // Generic Add-device dialog (NIC + CD-ROM/ISO included) — driven by the
  // plugin's vms.device-types descriptor.
  const [attachTarget, setAttachTarget] = useState<NicAttachTarget | null>(null);
  // Generic Edit-device dialog — form rendered from the type's editInputSchema,
  // prefilled via vms.device-get, submitted as a partial-merge vms.device-update.
  const [editTarget, setEditTarget] = useState<DeviceEditTarget | null>(null);
  // Generic Edit-VM dialog — form rendered from the plugin's vms.vm-edit-schema
  // catalog, prefilled via vms.vm-get, submitted as a partial-merge vms.vm-update.
  const [editVmRow, setEditVmRow] = useState<VmRow | null>(null);

  function detachDevice(node: VmNode) {
    const row = node.row;
    if (!row || node.devId === undefined) return;
    const isDisk = node.dtype?.toUpperCase() === 'DISK';
    const msg = `Detach ${node.dtype?.toLowerCase() ?? 'device'} ${node.label ?? ''} from "${row.name}"? The VM must be stopped.`;
    if (!window.confirm(msg)) return;
    // Disks get a second, explicit confirmation for the destructive option.
    let removeStorage = false;
    if (isDisk) {
      removeStorage = window.confirm(`Also DESTROY the backing storage (${node.label ?? 'zvol'})? This is irreversible.`);
    }
    const attempt = async () => {
      if (mode === 'readonly') { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(row.pluginId, 'vms.device-detach', [{ deviceId: row.deviceId, input: { name: row.name, deviceId: node.devId, ...(removeStorage ? { removeStorage: true } : {}) } }], mode);
      if (mode === 'plan') {
        setNotice({ kind: 'ok', text: `Detach ${node.dtype?.toLowerCase() ?? 'device'} from ${row.name}: saved as a plan — not executed. Open the Plans center to run it later.` });
        return;
      }
      trackPlan(planId, [row.deviceId]);
    };
    (async () => {
      try {
        await attempt();
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) setReauth({ label: `Detach device — ${row.name}`, retry: attempt });
        else setNotice({ kind: 'error', text: `Detach device failed: ${err instanceof Error ? err.message : String(err)}` });
      }
    })();
  }

  function detachNic(node: VmNode) {
    const row = node.row;
    const mac = node.label;
    if (!row || !mac) return;
    if (!window.confirm(`Detach NIC ${mac} from "${row.name}"?`)) return;
    const attempt = async () => {
      if (mode === 'readonly') { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(row.pluginId, 'vms.nic-detach', [{ deviceId: row.deviceId, input: { name: row.name, mac } }], mode);
      if (mode === 'plan') {
        setNotice({ kind: 'ok', text: `Detach NIC ${mac} from ${row.name}: saved as a plan — not executed. Open the Plans center to run it later.` });
        return;
      }
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

  function editDevice(node: VmNode) {
    const row = node.row;
    if (!row || node.devId === undefined || !node.dtype) return;
    setEditTarget({ row, devId: node.devId, dtype: node.dtype });
  }

  /** Opens the generic Edit-VM dialog for this VM row (its own settings). */
  function editVm(row: VmRow) {
    setEditVmRow(row);
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
      // CPU topology as reported by the hypervisor (TrueNAS: vm.query cores/threads).
      header: 'Cores',
      key: 'cores',
      width: 70,
      sortAccessor: (node) => {
        const e = node.row ? extraOf(node.row) : {};
        return typeof e['cores'] === 'number' ? (e['cores'] as number) : -1;
      },
      exportValue: (node) => {
        const e = node.row ? extraOf(node.row) : {};
        return typeof e['cores'] === 'number' ? String(e['cores']) : '';
      },
      render: (node) => {
        const c = node.row ? extraOf(node.row)['cores'] : undefined;
        return typeof c === 'number' ? <span className="font-mono text-xs">{c}</span> : <span className="text-faint">—</span>;
      },
    },
    {
      header: 'Threads',
      key: 'threads',
      width: 70,
      sortAccessor: (node) => {
        const e = node.row ? extraOf(node.row) : {};
        return typeof e['threads'] === 'number' ? (e['threads'] as number) : -1;
      },
      exportValue: (node) => {
        const e = node.row ? extraOf(node.row) : {};
        return typeof e['threads'] === 'number' ? String(e['threads']) : '';
      },
      render: (node) => {
        const t = node.row ? extraOf(node.row)['threads'] : undefined;
        return typeof t === 'number' ? <span className="font-mono text-xs">{t}</span> : <span className="text-faint">—</span>;
      },
    },
    {
      // LIVE CPU utilization from the 3 s probe (virsh domstats cpu.time deltas,
      // computed plugin-side). "—" until the first successful cycle after a
      // plugin restart establishes its baseline.
      header: 'CPU',
      key: 'cpuPct',
      width: 80,
      sortAccessor: (node) => {
        if (!node.row) return -1;
        const live = freshLiveCpu(node.row.deviceId, node.row.pluginId, node.row.name);
        return live?.cpuPct ?? null;
      },
      exportValue: (node) => {
        if (!node.row) return '';
        const live = freshLiveCpu(node.row.deviceId, node.row.pluginId, node.row.name);
        return live?.cpuPct !== undefined ? `${live.cpuPct.toFixed(1)}%` : '';
      },
      render: (node) => {
        if (!node.row) return null;
        const state = effectiveState(node.row);
        if (!RUNNING_STATES.has(state)) return <span className="text-faint">—</span>;
        const live = freshLiveCpu(node.row.deviceId, node.row.pluginId, node.row.name);
        return <CpuCell pct={live?.cpuPct} />;
      },
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
      render: (node) => (node.row ? <span className="text-xs text-secondary">{formatDateTime(node.row.collectedAt)}</span> : null),
    },
    {
      // One-click per-row actions. Availability is GENERIC — a button only
      // renders when the row's plugin advertises that action id in its catalog,
      // so any future hypervisor plugin (libvirt, Proxmox…) gets this column free.
      header: 'Actions',
      key: 'actions',
      width: 200,
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

        // Read-Only mode disables every VM write action.
        const readOnly = mode === 'readonly';
        const actions: { id: string; label: string; icon: ReactNode; available: boolean; eligible: boolean; danger?: boolean }[] = [
          { id: powerActionId, label: `${powerLabel} ${r.name}`, icon: <Play size={14} />, available: powerAvailable && !readOnly, eligible: powerEligible },
          { id: 'vms.stop', label: `Stop ${r.name}`, icon: <Square size={13} />, available: hasAction(r.pluginId, 'vms.stop') && !readOnly, eligible: isRunning, danger: true },
          { id: 'vms.kill', label: `Kill ${r.name}`, icon: <Zap size={14} />, available: hasAction(r.pluginId, 'vms.kill') && !readOnly, eligible: isRunning || isSuspended, danger: true },
          { id: 'vms.restart', label: `Restart ${r.name}`, icon: <RotateCw size={14} />, available: hasAction(r.pluginId, 'vms.restart') && !readOnly, eligible: !isStopped },
          { id: 'vms.suspend', label: `Suspend ${r.name}`, icon: <Pause size={13} />, available: hasAction(r.pluginId, 'vms.suspend') && !readOnly, eligible: isRunning },
          { id: 'vms.delete', label: `Delete ${r.name}`, icon: <Trash2 size={13} />, available: hasAction(r.pluginId, 'vms.delete') && !readOnly, eligible: true, danger: true },
          // Generic Add-device — the dialog itself decides which types apply (the
          // plugin advertises them via vms.device-types; per-type stopped/one-per-
          // VM rules are enforced inside it).
          { id: 'vms.device-types', label: `Add device to ${r.name}`, icon: <Plus size={14} />, available: hasAction(r.pluginId, 'vms.device-types') && !readOnly, eligible: true },
          // Generic Edit-VM — the VM's OWN settings (name/description/autostart/
          // boot method/system clock/NUMA/CPU/memory); per-field stopped rules are
          // enforced inside the dialog.
          { id: 'vms.vm-edit-schema', label: `Edit ${r.name}`, icon: <Pencil size={13} />, available: hasAction(r.pluginId, 'vms.vm-edit-schema') && !readOnly, eligible: true },
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
                    if (a.id === 'vms.device-types') setAttachTarget({ row: r });
                    else if (a.id === 'vms.vm-edit-schema') editVm(r);
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
    <Layout
      title="VMs"
      actions={
        createTargets.length > 0 && mode !== 'readonly' ? (
          <button
            type="button"
            onClick={() => openCreate()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90"
          >
            <Monitor size={13} />
            Create VM
          </button>
        ) : null
      }
    >
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
              <Monitor size={13} className="text-accent-solid" />
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
              renderChild: (child, _parent, ctx) => (
                <ChildRow
                  node={child}
                  ctx={ctx}
                  actions={{ hasAction, detachNic, detachDevice, editDevice, vmStopped: (row) => STOPPED_STATES.has(effectiveState(row)), readOnly: mode === 'readonly' }}
                />
              ),
            }}
            emptyMessage="No VMs collected yet — assign a TrueNAS plugin to a hypervisor device and wait for the next poll. NIC MAC addresses appear on the Hosts page with source “VM”."
          />
        )}

        {/* Create-VM dialog */}
        {createOpen && <CreateVmDialog targets={createTargets} onClose={() => setCreateOpen(false)} />}

        {/* Generic Add-device dialog (plugin-driven device types — NIC + CD-ROM/ISO included) */}
        {attachTarget && (
          <AttachDeviceDialog
            target={attachTarget}
            stopped={STOPPED_STATES.has(effectiveState(attachTarget.row))}
            onClose={() => setAttachTarget(null)}
          />
        )}

        {/* Generic Edit-device dialog — form from the type's editInputSchema, prefilled via vms.device-get */}
        {editTarget && (
          <EditDeviceDialog
            target={editTarget}
            stopped={STOPPED_STATES.has(effectiveState(editTarget.row))}
            onClose={() => setEditTarget(null)}
          />
        )}

        {/* Generic Edit-VM dialog — form from the plugin's vms.vm-edit-schema, prefilled via vms.vm-get */}
        {editVmRow && (
          <EditVmDialog
            row={editVmRow}
            stopped={STOPPED_STATES.has(effectiveState(editVmRow))}
            onClose={() => setEditVmRow(null)}
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
