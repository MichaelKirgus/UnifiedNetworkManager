import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { useMemo, type ReactNode } from 'react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { formatDuration } from '../components/formatMetric';
import { api, ContainerNetwork, ContainerRow, ContainerServiceDetail } from '../api/client';

/** Uptime cell — "running since". RUNNING + startedAt → duration; non-RUNNING
 * or no stamp → "—". The value is the real container start when the plugin
 * observed it via SSH (`docker inspect`), otherwise UNM-tracked from state
 * transitions (a lower bound that resets after restarts). */
function UptimeCell({ row }: { row: ContainerRow }) {
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

/** App workload state → badge style (TrueNAS SCALE states are uppercase). */
const STATE_STYLES: Record<string, string> = {
  RUNNING: 'bg-emerald-100 text-emerald-800 border-emerald-300',
  STOPPED: 'bg-slate-200 text-slate-600 border-slate-300',
  ERROR: 'bg-red-100 text-red-800 border-red-300',
  FAILED: 'bg-red-100 text-red-800 border-red-300',
};

function StateBadge({ state }: { state: string }) {
  const style = STATE_STYLES[state] ?? 'bg-amber-100 text-amber-800 border-amber-300';
  return (
    <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium', style)}>
      {state.toLowerCase()}
    </span>
  );
}

/** Reads the `extra` JSON object defensively — corrupt rows must not break the table. */
function extraOf(row: ContainerRow): Record<string, unknown> {
  const e = row.extra;
  return e && typeof e === 'object' ? (e as Record<string, unknown>) : {};
}

/** Networks[] from extra (defensive). */
function networksOf(row: ContainerRow): ContainerNetwork[] {
  const n = extraOf(row)['networks'];
  if (!Array.isArray(n)) return [];
  return n.filter((x): x is ContainerNetwork => !!x && typeof x === 'object' && typeof (x as ContainerNetwork).name === 'string');
}

/** Static container IPs from extra. */
function ipsOf(row: ContainerRow): string[] {
  const i = extraOf(row)['ips'];
  return Array.isArray(i) ? i.filter((x): x is string => typeof x === 'string') : [];
}

/** Published host ports from extra. */
function portsOf(row: ContainerRow): number[] {
  const p = extraOf(row)['ports'];
  return Array.isArray(p) ? p.filter((x): x is number => typeof x === 'number') : [];
}

/** Per-service detail for the expandable row (multi-container apps). */
function servicesOf(row: ContainerRow): ContainerServiceDetail[] {
  const c = extraOf(row)['containers'];
  if (!Array.isArray(c)) return [];
  return c.filter((x): x is ContainerServiceDetail => !!x && typeof x === 'object');
}

/** Splits a docker image reference into its repo and tag parts. Handles registry
 * hosts, ports, digests (`@sha256:`) and defaults to `latest` when no explicit
 * tag is present — so "Image" shows the name and "Tag" the version. */
function splitImage(image: string | null | undefined): { repo: string; tag: string } {
  if (!image || image.trim() === '') return { repo: '', tag: '' };
  const s = image.trim();
  // Digest reference — no tag part.
  const at = s.indexOf('@');
  if (at >= 0) return { repo: s.slice(0, at), tag: s.slice(at + 1) };
  const lastSlash = s.lastIndexOf('/');
  const lastColon = s.lastIndexOf(':');
  // A colon after the final slash is a tag separator; otherwise it's a port.
  if (lastColon > lastSlash) return { repo: s.slice(0, lastColon), tag: s.slice(lastColon + 1) };
  return { repo: s, tag: 'latest' };
}

/** One node in the App → Container(s) → Volume mounts display tree. Top-level
 * (app) nodes carry their source row so the main columns keep working; child
 * nodes (container/volume) carry just the fields their cells need. */
interface TreeNode {
  key: string;
  kind: 'app' | 'container' | 'volume';
  /** Source app row — set on `kind === 'app'` nodes only. */
  row?: ContainerRow;
  service?: string;
  image?: string | null;
  state?: string | null;
  mac?: string | null;
  ip?: string | null;
  startedAt?: string | null;
  /** Volume mount text (kind=volume): "source → target" (+ mode). */
  volumeText?: string;
}

/** Result of building one app's subtree: the app node + its containers, each
 * with its own volume nodes. Used to populate DataTable's child map. */
interface BuiltApp {
  app: TreeNode;
  containers: { node: TreeNode; volumes: TreeNode[] }[];
}

/** Builds the display tree for one app row: an app node, its container(s) as
 * children, and each container's declared volume mounts as grandchildren. A
 * single-container app still nests its container (uniform structure); an app
 * with no per-service detail yet falls back to a synthetic container from the
 * app-level image so nothing is lost. */
function buildApp(row: ContainerRow): BuiltApp {
  const base = `${row.deviceId}|${row.pluginId}|${row.name}`;
  const services = servicesOf(row);
  let list: ContainerServiceDetail[];
  if (services.length > 0) {
    list = services;
  } else if (row.image) {
    // No per-service detail yet — synthesize one container from the app image.
    list = [{ service: row.name, image: row.image, state: row.state.toLowerCase() }];
  } else {
    list = [];
  }

  const app: TreeNode = { key: base, kind: 'app', row };
  const containers: BuiltApp['containers'] = [];
  list.forEach((s, i) => {
    const ckey = `${base}#c${i}`;
    const vols: TreeNode[] = (Array.isArray(s.volumes) ? s.volumes : []).map((v, vi) => ({
      key: `${ckey}#v${vi}`,
      kind: 'volume',
      volumeText: [v.source, v.target ? `→ ${v.target}` : '', v.mode].filter(Boolean).join(' '),
    }));
    containers.push({
      node: {
        key: ckey,
        kind: 'container',
        service: s.service ?? (list.length > 1 ? undefined : row.name),
        image: s.image ?? null,
        state: s.state ?? null,
        mac: s.mac ?? null,
        ip: s.ip ?? null,
        startedAt: s.startedAt ?? null,
      },
      volumes: vols,
    });
  });
  return { app, containers };
}

/** One docker-network chip — name on top, driver + subnets in the tooltip. */
function NetworkChip({ net }: { net: ContainerNetwork }) {
  const tip = [net.name, net.driver ? `driver: ${net.driver}` : '', ...(net.subnets ?? [])].filter(Boolean).join(' · ');
  return (
    <span title={tip} className="inline-flex items-center rounded border border-sky-200 bg-sky-50 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-sky-800">
      {net.name}
    </span>
  );
}

/** One static IP chip (v4 blue / v6 violet — same convention as the Firewall page). */
function IpChip({ ip }: { ip: string }) {
  const isV6 = ip.includes(':');
  return (
    <span className={clsx('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-4', isV6 ? 'border-violet-200 bg-violet-50 text-violet-800' : 'border-blue-200 bg-blue-50 text-blue-800')}>
      {ip}
    </span>
  );
}

/** Network + IP cell: static IPs first, then network chips; "—" when neither. */
function NetworkCell({ row }: { row: ContainerRow }) {
  const ips = ipsOf(row);
  const nets = networksOf(row);
  if (ips.length === 0 && nets.length === 0) return <span className="text-slate-400">—</span>;
  return (
    <div className="flex flex-col gap-1">
      {ips.length > 0 && (
        <span className="flex flex-wrap gap-x-1 gap-y-0.5">{ips.map((ip) => <IpChip key={ip} ip={ip} />)}</span>
      )}
      {nets.length > 0 && (
        <span className="flex flex-wrap gap-x-1 gap-y-0.5">
          {nets.slice(0, 4).map((n) => <NetworkChip key={n.name} net={n} />)}
          {nets.length > 4 && <span className="text-[11px] text-slate-400" title={nets.map((n) => n.name).join(', ')}>+{nets.length - 4}</span>}
        </span>
      )}
    </div>
  );
}

/** Published host ports — first three + "+N" overflow. */
function PortsCell({ row }: { row: ContainerRow }) {
  const ports = portsOf(row);
  if (ports.length === 0) return <span className="text-slate-400">—</span>;
  const shown = ports.slice(0, 3);
  return (
    <span title={ports.join(', ')} className="font-mono text-xs text-slate-700">
      {shown.map((p) => p).join(', ')}
      {ports.length > 3 && <span className="text-slate-400"> +{ports.length - 3}</span>}
    </span>
  );
}

/** Version cell with an amber "update available" dot. */
function VersionCell({ row }: { row: ContainerRow }) {
  const v = row.version && row.version.trim() !== '' ? row.version : null;
  if (!v) return <span className="text-slate-400">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs text-slate-700" title={row.upgradeAvailable ? 'Update available' : undefined}>
      {v}
      {row.upgradeAvailable && <span className="h-2 w-2 rounded-full bg-amber-400" title="Update available" />}
    </span>
  );
}

/** Top-level App cell — name + "custom" marker. */
function AppCell({ row }: { row?: ContainerRow }) {
  if (!row) return null;
  return (
    <div className="flex flex-col gap-0.5">
      <span className="font-medium text-slate-800">{row.name}</span>
      {typeof extraOf(row)['customApp'] === 'boolean' && (extraOf(row)['customApp'] as boolean) && (
        <span className="text-[10px] uppercase tracking-wide text-slate-400">custom</span>
      )}
    </div>
  );
}

/** Cell content for one column of an expanded child row — mirrors the top-level
 * column renders so children line up with the header. ONLY the name column is
 * indented (the hierarchy cue); every other cell aligns normally under its
 * header, exactly like a regular data row. Container rows fill most columns;
 * volume leaves only use the name column (indented one step deeper). */
function nodeCell(key: string, node: TreeNode, depth: number): ReactNode {
  switch (key) {
    case 'name': {
      if (node.kind === 'container') {
        return (
          <span className="block truncate font-medium text-slate-700" style={{ paddingLeft: 18 + depth * 14 }} title={node.service ?? undefined}>
            {node.service ?? '—'}
          </span>
        );
      }
      // Volume leaf — the mount lives in the name column, indented under its container.
      return (
        <span className="block truncate font-mono text-[11px] text-slate-500" style={{ paddingLeft: 32 + depth * 14 }} title={node.volumeText}>
          {node.volumeText}
        </span>
      );
    }
    case 'state':
      if (node.kind === 'container' && node.state) return <StateBadge state={node.state.toUpperCase()} />;
      return null;
    case 'image': {
      if (node.kind !== 'container') return null;
      const repo = splitImage(node.image).repo;
      return repo ? (
        <span className="block truncate font-mono text-xs text-slate-700" title={node.image ?? undefined}>{repo}</span>
      ) : (
        <span className="text-slate-400">—</span>
      );
    }
    case 'tag': {
      if (node.kind !== 'container') return null;
      const tag = splitImage(node.image).tag;
      return tag ? (
        <span className="inline-flex items-center rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-slate-600" title={tag}>{tag}</span>
      ) : (
        <span className="text-slate-400">—</span>
      );
    }
    case 'networks': {
      if (node.kind !== 'container') return null;
      const parts: ReactNode[] = [];
      if (node.ip) {
        parts.push(
          <span key="ip" className={clsx('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-4', node.ip.includes(':') ? 'border-violet-200 bg-violet-50 text-violet-800' : 'border-blue-200 bg-blue-50 text-blue-800')} title="IP">
            {node.ip}
          </span>
        );
      }
      if (node.mac) parts.push(<span key="mac" className="font-mono text-[11px] text-slate-500" title="MAC address">MAC {node.mac}</span>);
      if (parts.length === 0) return <span className="text-slate-400">—</span>;
      return <span className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5">{parts}</span>;
    }
    case 'startedAt': {
      if (node.kind !== 'container' || !node.startedAt) return null;
      const since = new Date(node.startedAt).getTime();
      if (Number.isNaN(since)) return null;
      const secs = Math.max(0, (Date.now() - since) / 1000);
      return <span className="font-mono text-xs text-slate-700" title={`Running since ${new Date(node.startedAt).toLocaleString()}`}>{formatDuration(secs)}</span>;
    }
    default:
      return null;
  }
}

/** One expanded child rendered as a FULL `<tr>` — a chevron cell plus one cell
 * per visible column (ctx.columns), so it stays aligned with the header. A
 * container that has volume mounts gets its own chevron for recursive expand. */
function ChildRow({ node, ctx }: { node: TreeNode; ctx: ExpandChildContext }) {
  return (
    <tr className={node.kind === 'volume' ? 'bg-slate-50/60' : 'bg-sky-50/40'}>
      <td className="px-1 py-2 align-middle">
        {ctx.hasChildren ? (
          <button
            type="button"
            onClick={ctx.onToggle}
            aria-expanded={ctx.expanded}
            title={ctx.expanded ? 'Collapse volume mounts' : 'Show volume mounts'}
            className="flex h-6 w-6 items-center justify-center rounded text-slate-400 hover:bg-slate-200 hover:text-slate-600"
          >
            {ctx.expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
          </button>
        ) : (
          <span className="inline-block h-6 w-6" />
        )}
      </td>
      {ctx.columns.map((col) => (
        <td key={col.key} className="overflow-hidden px-4 py-2 text-slate-700">
          {nodeCell(col.key, node, ctx.depth)}
        </td>
      ))}
    </tr>
  );
}

export default function Containers() {
  // The API polls plugins every ~30s and upserts these rows — refresh at the
  // same cadence so the view tracks live inventory.
  const containersQuery = useQuery({
    queryKey: ['containers'],
    queryFn: () => api.containers(),
    refetchInterval: 30_000,
  });

  // Display tree for expandable rows: app → container(s) → volume mounts.
  // `roots` are the top-level (app) nodes; `childMap` maps a node key to its
  // DIRECT children so DataTable can render + recursively expand each level.
  const tree = useMemo(() => {
    const childMap = new Map<string, TreeNode[]>();
    const roots: TreeNode[] = [];
    for (const row of containersQuery.data?.containers ?? []) {
      const built = buildApp(row);
      roots.push(built.app);
      childMap.set(built.app.key, built.containers.map((c) => c.node));
      for (const c of built.containers) if (c.volumes.length > 0) childMap.set(c.node.key, c.volumes);
    }
    return { roots, childMap };
  }, [containersQuery.data]);

  const columns: DataTableColumn<TreeNode>[] = [
    {
      header: 'App',
      key: 'name',
      width: 210,
      exportValue: (node) => node.row?.name ?? '',
      render: (node) => <AppCell row={node.row} />,
    },
    {
      header: 'Device',
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
      width: 110,
      exportValue: (node) => node.row?.state ?? '',
      render: (node) => (node.row ? <StateBadge state={node.row.state} /> : null),
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
      header: 'Image',
      key: 'image',
      width: 210,
      exportValue: (node) => splitImage(node.row?.image).repo || '',
      render: (node) => {
        const repo = splitImage(node.row?.image).repo;
        return repo ? (
          <span className="block truncate font-mono text-xs text-slate-700" title={node.row?.image ?? undefined}>{repo}</span>
        ) : (
          <span className="text-slate-400">—</span>
        );
      },
    },
    {
      header: 'Tag',
      key: 'tag',
      width: 120,
      exportValue: (node) => splitImage(node.row?.image).tag || '',
      render: (node) => {
        const tag = splitImage(node.row?.image).tag;
        return tag ? (
          <span className="inline-flex items-center rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-slate-600" title={tag}>{tag}</span>
        ) : (
          <span className="text-slate-400">—</span>
        );
      },
    },
    {
      header: 'Network / IPs',
      key: 'networks',
      width: 230,
      exportValue: (node) => (node.row ? [...ipsOf(node.row), ...networksOf(node.row).map((n) => n.name)].join(', ') : ''),
      render: (node) => (node.row ? <NetworkCell row={node.row} /> : null),
    },
    {
      header: 'Ports',
      key: 'ports',
      width: 120,
      exportValue: (node) => (node.row ? portsOf(node.row).join(',') : ''),
      render: (node) => (node.row ? <PortsCell row={node.row} /> : null),
    },
    {
      header: 'Version',
      key: 'version',
      width: 130,
      exportValue: (node) => node.row?.version ?? '',
      render: (node) => (node.row ? <VersionCell row={node.row} /> : null),
    },
    {
      header: 'Collected',
      key: 'collectedAt',
      width: 170,
      sortAccessor: (node) => new Date(node.row?.collectedAt ?? '').getTime(),
      render: (node) => (node.row ? new Date(node.row.collectedAt).toLocaleString() : null),
    },
  ];

  return (
    <Layout title="Containers">
      {containersQuery.isLoading && <p className="text-sm text-slate-500">Loading containers...</p>}
      {containersQuery.isError && (
        <p className="text-sm text-red-600">Failed to load containers: {(containersQuery.error as Error).message}</p>
      )}
      {containersQuery.data && (
        <DataTable<TreeNode>
          columns={columns}
          rows={tree.roots}
          rowKey={(node) => node.key}
          storageKey="containers"
          autoRefresh={{ intervalMs: 30_000, queries: [containersQuery] }}
          searchPlaceholder="Search containers…"
          expandable={{
            childrenOf: (node) => tree.childMap.get(node.key) ?? [],
            renderChild: (child, _parent, ctx) => <ChildRow node={child} ctx={ctx} />,
          }}
          emptyMessage="No containers collected yet — assign a TrueNAS plugin to a device and wait for the next poll."
        />
      )}
    </Layout>
  );
}
