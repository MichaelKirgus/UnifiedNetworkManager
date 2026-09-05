import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { ChevronDown, ChevronRight, Monitor } from 'lucide-react';
import { useMemo, type ReactNode } from 'react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { formatBytes, formatDuration } from '../components/formatMetric';
import { api, VmDevice, VmNic, VmRow } from '../api/client';

/** VM runtime state → badge style (TrueNAS/libvirt states are uppercase; other
 * hypervisor plugins may emit their own native states — unknown ones fall back). */
const STATE_STYLES: Record<string, string> = {
  RUNNING: 'bg-emerald-100 text-emerald-800 border-emerald-300',
  STOPPED: 'bg-slate-200 text-slate-600 border-slate-300',
  SUSPENDED: 'bg-amber-100 text-amber-800 border-amber-300',
  PAUSED: 'bg-sky-100 text-sky-800 border-sky-300',
  ERROR: 'bg-red-100 text-red-800 border-red-300',
};

function StateBadge({ state }: { state: string }) {
  const style = STATE_STYLES[state] ?? 'bg-amber-100 text-amber-800 border-amber-300';
  return (
    <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium', style)}>
      {state.toLowerCase()}
    </span>
  );
}

/** Uptime cell — "running since". RUNNING + startedAt → duration; non-RUNNING
 * or no stamp → "—". The value is UNM-tracked from state transitions (a lower
 * bound that resets after restarts). */
function UptimeCell({ row }: { row: VmRow }) {
  if (row.state !== 'RUNNING' || !row.startedAt) return <span className="text-slate-400">—</span>;
  const since = new Date(row.startedAt).getTime();
  if (Number.isNaN(since)) return <span className="text-slate-400">—</span>;
  const secs = Math.max(0, (Date.now() - since) / 1000);
  return (
    <span
      className="font-mono text-xs text-slate-700"
      title={`Running since ${new Date(row.startedAt).toLocaleString()}`}
    >
      {formatDuration(secs)}
    </span>
  );
}

/** Reads the `extra` JSON object defensively — corrupt rows must not break the table. */
function extraOf(row: VmRow): Record<string, unknown> {
  const e = row.extra;
  return e && typeof e === 'object' ? (e as Record<string, unknown>) : {};
}

/** Attached devices from extra (defensive). Prefers the generic `devices[]`
 * list; falls back to the legacy `nics[]` shape so rows written by older plugin
 * versions still render. */
function devicesOf(row: VmRow): VmDevice[] {
  const e = extraOf(row);
  const d = e['devices'];
  if (Array.isArray(d)) return d.filter((x): x is VmDevice => !!x && typeof x === 'object' && typeof (x as VmDevice).dtype === 'string');
  // Legacy fallback: older plugins emitted only extra.nics[].
  const n = e['nics'];
  if (!Array.isArray(n)) return [];
  return n
    .filter((x): x is VmNic => !!x && typeof x === 'object')
    .map((nic) => ({ dtype: 'NIC', label: nic.mac || undefined, detail: [nic.type, nic.nicAttach ? `→ ${nic.nicAttach}` : null].filter(Boolean).join(' ') || undefined }));
}

/** One node in the VM → device display tree. Top-level (VM) nodes carry their
 * source row so the main columns keep working; child (device) nodes carry just
 * the fields their cells need. */
interface VmNode {
  key: string;
  kind: 'vm' | 'device';
  /** Source VM row — set on `kind === 'vm'` nodes only. */
  row?: VmRow;
  dtype?: string;
  label?: string;
  detail?: string;
}

/** Builds the display tree for one VM row: a VM node + ALL its attached devices
 * (NICs, disks, displays, CD-ROMs, PCIe…) as children. The parent is collapsed
 * by default (DataTable expansion state starts empty). */
function buildVm(row: VmRow): { vm: VmNode; devices: VmNode[] } {
  const base = `${row.deviceId}|${row.pluginId}|${row.name}`;
  const devices = devicesOf(row).map((d, i) => ({
    key: `${base}#dev${i}`,
    kind: 'device' as const,
    dtype: d.dtype,
    label: typeof d.label === 'string' && d.label !== '' ? d.label : undefined,
    detail: typeof d.detail === 'string' && d.detail !== '' ? d.detail : undefined,
  }));
  return { vm: { key: base, kind: 'vm', row }, devices };
}

/** Parent Devices cell — a compact per-type count summary ("2 NIC · 1 DISK ·
 * 1 DISPLAY"); the full detail lives in the expandable child rows. */
function DevicesCell({ row }: { row: VmRow }) {
  const devices = devicesOf(row);
  if (devices.length === 0) return <span className="text-slate-400">—</span>;
  // Group by dtype, preserving first-seen order.
  const counts = new Map<string, number>();
  for (const d of devices) counts.set(d.dtype.toUpperCase(), (counts.get(d.dtype.toUpperCase()) ?? 0) + 1);
  return (
    <div className="flex flex-wrap items-center gap-1" title={`${devices.length} device(s) — expand for detail`}>
      {[...counts.entries()].map(([t, n]) => (
        <span key={t} className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[11px] leading-4 text-slate-600">
          {n > 1 ? `${n}× ` : ''}{t}
        </span>
      ))}
    </div>
  );
}

/** Cell content for one column of an expanded child row — mirrors the top-level
 * column renders so children line up with the header. ONLY the name column is
 * indented (the hierarchy cue); every other cell aligns normally under its
 * header, exactly like a regular data row. */
function nodeCell(key: string, node: VmNode, depth: number): ReactNode {
  switch (key) {
    case 'name':
      // Device leaf — the label (MAC / disk path / display…) lives in the name
      // column, indented under its VM. MACs and paths read best monospaced.
      return (
        <span className="block truncate font-mono text-xs text-slate-600" style={{ paddingLeft: 18 + depth * 14 }} title={node.label ?? node.dtype}>
          {node.label ?? '—'}
        </span>
      );
    case 'devices': {
      if (!node.detail) return <span className="text-slate-400">—</span>;
      return <span className="font-mono text-[11px] text-slate-500">{node.detail}</span>;
    }
    default:
      return null;
  }
}

/** One expanded child rendered as a FULL `<tr>` — a chevron cell plus one cell
 * per visible column (ctx.columns), so it stays aligned with the header. */
function ChildRow({ node, ctx }: { node: VmNode; ctx: ExpandChildContext }) {
  return (
    <tr className="bg-indigo-50/40">
      <td className="px-1 py-2 align-middle">
        {/* NICs are leaves — no further nesting. */}
        <span className="inline-block h-6 w-6" />
      </td>
      {ctx.columns.map((col) => (
        <td key={col.key} className="overflow-hidden px-4 py-2 text-slate-700">
          {nodeCell(col.key, node, ctx.depth)}
        </td>
      ))}
    </tr>
  );
}

export default function Vms() {
  // The API polls plugins every ~30s and upserts these rows — refresh at the
  // same cadence so the view tracks live inventory.
  const vmsQuery = useQuery({
    queryKey: ['vms'],
    queryFn: () => api.vms(),
    refetchInterval: 30_000,
  });

  // Display tree for expandable rows: VM → NIC(s). `roots` are the top-level
  // (VM) nodes; `childMap` maps a node key to its direct children. Parents
  // start COLLAPSED — DataTable expansion state is session-only and empty.
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
            <span className="font-medium text-slate-800">{node.row.name}</span>
            {typeof desc === 'string' && desc !== '' && (
              <span className="truncate text-[11px] text-slate-400" title={desc}>{desc}</span>
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
      render: (node) => (node.row ? <StateBadge state={node.row.state} /> : null),
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
          <span className="text-slate-400">—</span>
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
          <span className="text-slate-400">—</span>
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
      render: (node) => (node.row ? <span className="text-xs text-slate-600">{new Date(node.row.collectedAt).toLocaleString()}</span> : null),
    },
  ];

  // Summary numbers across all VM rows.
  const running = tree.roots.filter((n) => n.row?.state === 'RUNNING').length;
  const totalVcpus = tree.roots.reduce((sum, n) => sum + (n.row?.vcpus ?? 0), 0);
  const totalMemMiB = tree.roots.reduce((sum, n) => sum + (n.row?.memoryMiB ?? 0), 0);

  return (
    <Layout title="VMs">
      <div className="flex h-full min-h-0 flex-col">
        {vmsQuery.isLoading && <p className="shrink-0 text-sm text-slate-500">Loading VMs...</p>}
        {vmsQuery.isError && (
          <p className="shrink-0 text-sm text-red-600">Failed to load VMs: {(vmsQuery.error as Error).message}</p>
        )}

        {/* Summary strip — VM counts + allocated resources. */}
        {!vmsQuery.isLoading && !vmsQuery.isError && (
          <div className="mb-3 flex shrink-0 flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs">
            <span className="flex items-center gap-2 text-slate-600">
              <Monitor size={13} className="text-indigo-500" />
              {tree.roots.length} VM{tree.roots.length === 1 ? '' : 's'} · {running} running
            </span>
            {totalVcpus > 0 && (
              <span className="flex items-center gap-2 text-slate-600">
                <Monitor size={13} className="text-slate-500" />
                {totalVcpus} vCPU{totalVcpus === 1 ? '' : 's'} allocated
              </span>
            )}
            {totalMemMiB > 0 && (
              <span className="flex items-center gap-2 text-slate-600">
                <Monitor size={13} className="text-slate-500" />
                <span className="font-mono text-slate-700">{formatBytes(totalMemMiB * 1048576)} memory allocated</span>
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
            expandable={{
              childrenOf: (node) => tree.childMap.get(node.key) ?? [],
              renderChild: (child, _parent, ctx) => <ChildRow node={child} ctx={ctx} />,
            }}
            emptyMessage="No VMs collected yet — assign a TrueNAS plugin to a hypervisor device and wait for the next poll. NIC MAC addresses appear on the Hosts page with source “VM”."
          />
        )}
      </div>
    </Layout>
  );
}
